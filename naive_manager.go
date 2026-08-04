package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// naiveInstance represents one running naive process
type naiveInstance struct {
	sni        string
	appType    AppType
	configPath string
	listenAddr string
	port       int
	cmd        *exec.Cmd
	mu         sync.Mutex
	ready      bool
	lastUsed   time.Time
}

// NaiveManager manages a pool of naive proxy processes
// One process per SNI, spawned on demand, killed after idle timeout
type NaiveManager struct {
	naiveBin     string // path to naive binary
	upstreamURL  string // https://user:pass@proxy.owocloud.online
	configDir    string // temp dir for per-SNI configs
	basePort     int    // starting port for naive instances
	// token -- тот же общий секрет, что у SOCKS5Server/RelayServer. naive
	// умеет требовать RFC1929 auth на собственном --listen нативно (см.
	// naive_config.cc: GURL.username()/.password()) -- просто раньше мы
	// никогда не передавали туда учётные данные, и каждый из портов
	// 11000+ был точно такой же открытой дверью, как 1080/1081 были
	// раньше.
	token        []byte
	// signalPassword -- тот же пароль (в открытом виде, не hex), что на
	// сервере лежит как hex-строка в secrets.json диспетчера. Пробрасывается
	// в КАЖДЫЙ спавнимый naive-инстанс -- один и тот же пароль для всех SNI,
	// раз это привязано к пользователю, а не к конкретному decoy-домену.
	signalPassword []byte

	mu        sync.Mutex
	instances map[string]*naiveInstance
	portNext  int
}

// naiveConfig matches the JSON format naive expects
type naiveConfig struct {
	Listen          string `json:"listen"`
	Proxy           string `json:"proxy"`
	RealitySNI      string `json:"reality-sni"`
	RealityPublicKey string `json:"reality-public-key,omitempty"`
	// SignalPassword -- пароль для owo_signal (см. owo_signal.go/owo_tls_front.go
	// на стороне сервера, и патч 0003-client-signal-registration.patch на
	// стороне этого самого naive-бинарника). Без этого поля naive не впишет
	// сигнал в session_id ClientHello, и диспетчер на VPS всегда будет
	// считать соединение непроверенным (сплайс на настоящий сайт вместо
	// forward_proxy) -- см. чат: путь Б уже подтверждён живьём, это то,
	// что нужно для проверки пути "валидный сигнал".
	SignalPassword  string `json:"owo-signal-password,omitempty"`
	Log             string `json:"log"`
}

func NewNaiveManager(naiveBin, upstreamURL, configDir string, basePort int, token []byte, signalPassword []byte) (*NaiveManager, error) {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	return &NaiveManager{
		naiveBin:       naiveBin,
		upstreamURL:    upstreamURL,
		configDir:      configDir,
		basePort:       basePort,
		token:          token,
		signalPassword: signalPassword,
		instances:      make(map[string]*naiveInstance),
		portNext:       basePort,
	}, nil
}

// GetUpstreamForApp — app-aware версия GetUpstream.
// AppVideo получает отдельный QUIC-инстанс (quic:// вместо https://).
func (m *NaiveManager) GetUpstreamForApp(sni string, app AppType) (string, error) {
	key := sni

	m.mu.Lock()
	inst, exists := m.instances[key]
	if !exists {
		port := m.portNext
		m.portNext++
		inst = &naiveInstance{
			sni:     sni,
			appType: app,
			port:    port,
		}
		m.instances[key] = inst
	}
	m.mu.Unlock()

	inst.mu.Lock()
	defer inst.mu.Unlock()

	inst.lastUsed = time.Now()

	if inst.ready && inst.cmd != nil && inst.cmd.ProcessState == nil {
		return fmt.Sprintf("127.0.0.1:%d", inst.port), nil
	}

	if err := m.spawnWithApp(inst); err != nil {
		return "", fmt.Errorf("spawn naive[%s|%v]: %w", sni, app, err)
	}
	return fmt.Sprintf("127.0.0.1:%d", inst.port), nil
}

// GetUpstreamForAppShard — как GetUpstreamForApp, но создаёт несколько инстансов
// на один SNI (для IoT/speedtest где нужно много параллельных соединений).
func (m *NaiveManager) GetUpstreamForAppShard(sni string, app AppType, shard int) (string, error) {
    key := fmt.Sprintf("%s|shard%d", sni, shard)

    m.mu.Lock()
    inst, exists := m.instances[key]
    if !exists {
        port := m.portNext
        m.portNext++
        inst = &naiveInstance{
            sni:     sni,   // реальный SNI для naive конфига
            appType: app,
            port:    port,
        }
        m.instances[key] = inst
    }
    m.mu.Unlock()

    inst.mu.Lock()
    defer inst.mu.Unlock()

    inst.lastUsed = time.Now()

    if inst.ready && inst.cmd != nil && inst.cmd.ProcessState == nil {
        return fmt.Sprintf("127.0.0.1:%d", inst.port), nil
    }

    if err := m.spawnWithApp(inst); err != nil {
        return "", fmt.Errorf("spawn naive[%s|shard%d]: %w", sni, shard, err)
    }
    return fmt.Sprintf("127.0.0.1:%d", inst.port), nil
}

func (m *NaiveManager) spawnWithApp(inst *naiveInstance) error {
	proxyURL := m.upstreamURL
	// if inst.appType == AppVideo {
	//	log.Printf("[NaiveMgr] Spawning QUIC instance sni=%s port=%d", inst.sni, inst.port)
	//} else {
	//	log.Printf("[NaiveMgr] Spawning HTTP/2 instance sni=%s port=%d", inst.sni, inst.port)
	//}

	cfgPath := filepath.Join(m.configDir, fmt.Sprintf("naive_%s_%d.json", sanitize(inst.sni), inst.port))
	// Токен уже hex (encoding/hex.EncodeToString) -- только [0-9a-f], так что
	// в URL user-info безопасен без дополнительного экранирования.
	var listenAddr string
	if len(m.token) == 0 {
		listenAddr = fmt.Sprintf("socks://127.0.0.1:%d", inst.port)
	} else {
		listenAddr = fmt.Sprintf("socks://owo:%s@127.0.0.1:%d", string(m.token), inst.port)
	}

	cfg := naiveConfig{
		Listen:         listenAddr,
		Proxy:          proxyURL,
		RealitySNI:     inst.sni,
		SignalPassword: string(m.signalPassword),
		Log:            filepath.Join(m.configDir, fmt.Sprintf("naive_%s_%d.log", sanitize(inst.sni), inst.port)),
	}

	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
		return err
	}

	cmd := exec.Command(m.naiveBin, cfgPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	inst.cmd = cmd
	inst.configPath = cfgPath
	inst.listenAddr = listenAddr
	inst.ready = false

	if err := m.waitReady(inst.port, 5*time.Second); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("naive not ready: %w", err)
	}
	inst.ready = true

	go func() {
		cmd.Wait()
		inst.mu.Lock()
		inst.ready = false
		inst.mu.Unlock()
		log.Printf("[NaiveMgr] naive sni=%s exited", inst.sni)
	}()
	return nil
}


// waitReady polls until port is open or timeout
func (m *NaiveManager) waitReady(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for port %d", port)
}

// GCIdleInstances kills naive processes idle for longer than maxIdle
func (m *NaiveManager) GCIdleInstances(maxIdle time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for sni, inst := range m.instances {
		inst.mu.Lock()
		if inst.ready && time.Since(inst.lastUsed) > maxIdle {
			log.Printf("[NaiveMgr] GC: killing idle naive sni=%s", sni)
			inst.cmd.Process.Kill()
			os.Remove(inst.configPath)
			delete(m.instances, sni)
		}
		inst.mu.Unlock()
	}
}

// StartGC runs idle instance cleanup on a ticker
func (m *NaiveManager) StartGC(interval, maxIdle time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			m.GCIdleInstances(maxIdle)
		}
	}()
}

// StopAll kills all running naive instances
func (m *NaiveManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sni, inst := range m.instances {
		inst.mu.Lock()
		if inst.cmd != nil && inst.cmd.Process != nil {
			inst.cmd.Process.Kill()
		}
		os.Remove(inst.configPath)
		inst.mu.Unlock()
		log.Printf("[NaiveMgr] stopped naive sni=%s", sni)
	}
	m.instances = make(map[string]*naiveInstance)
}

// Status returns a summary of running instances
func (m *NaiveManager) Status() []InstanceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []InstanceStatus
	for _, inst := range m.instances {
		inst.mu.Lock()
		out = append(out, InstanceStatus{
			SNI:      inst.sni,
			Port:     inst.port,
			Ready:    inst.ready,
			LastUsed: inst.lastUsed,
		})
		inst.mu.Unlock()
	}
	return out
}

type InstanceStatus struct {
	SNI      string
	Port     int
	Ready    bool
	LastUsed time.Time
}

// sanitize replaces dots with underscores for safe filenames
func sanitize(s string) string {
	out := make([]byte, len(s))
	for i, c := range s {
		if c == '.' || c == ':' || c == '/' {
			out[i] = '_'
		} else {
			out[i] = byte(c)
		}
	}
	return string(out)
}

