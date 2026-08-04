package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	// ── Флаги Session Manager ─────────────────────────────────────────────────
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	naiveBin   := flag.String("naive", "./naive", "Path to naive binary")
	upstream   := flag.String("upstream", "", "Upstream proxy URL (https://user:pass@host)")
	configDir  := flag.String("cfgdir", "/tmp/owo-naive-cfgs", "Directory for per-SNI naive configs")
	basePort   := flag.Int("baseport", 11000, "Starting port for naive instances")
	socks5Token := flag.String("socks5-token", "", "Shared RFC1929 password for the local SOCKS5 listener. "+
	"MUST match whatever the TUN client on this device is configured with. "+
	"If empty, a random token is generated and printed once at startup — "+
	"copy it into the client config before this process is trusted.")
	signalPassword := flag.String("signal-password", "", "Per-user password for the owo_signal ClientHello "+
	"signal. Must match (in plaintext -- the dispatcher's secrets.json stores the hex-encoded form of "+
	"the SAME password) an entry known to the owo-dispatcher on the server side. Empty means naive "+
	"won't embed any signal, and the dispatcher will always treat this client as unauthenticated "+
	"(splice to the real decoy site instead of forward_proxy).")

	// ── Флаги Relay режима ────────────────────────────────────────────────────
	relay        := flag.Bool("relay", false, "Enable relay mode: accept incoming client connections")
	relayListen  := flag.String("relay-listen", "127.0.0.1:1081", "Relay SOCKS5 listen addr (Caddy forwards here)")
	relayIP      := flag.String("relay-ip", "", "Public IP of this relay node (for VK registry)")
	relayPort    := flag.Int("relay-port", 443, "Public port of this relay node (for VK registry)")
	relayPubkey  := flag.String("relay-pubkey", "", "REALITY fingerprint pubkey (base64, from Caddy cert)")
	relayKind    := flag.String("relay-kind", "client", "Node kind: core|server|client")
	vkToken      := flag.String("vk-token", "", "VK API token for relay registry")
	vkGroup      := flag.Int64("vk-group", 0, "VK Group ID for relay registry")
	vkKey        := flag.String("vk-key", "", "Shared HMAC key matching bot SHARED_KEY")

	// ── Флаги OwOSS ────────────────────────────────────────────────────────
	// Пока без классификатора выбора протокола (см. комментарий у поля
	// ssMgr в socks5_server.go) -- если --owoss-server задан, ВЕСЬ
	// не-direct трафик идёт через OwOSS вместо naive.
	owossServer := flag.String("owoss-server", "", "Публичный адрес owo-ss-front (host:port). Пусто = OwOSS отключён, работаем только через naive, как раньше.")
	owossSNI    := flag.String("owoss-sni", "", "SNI/ServerName для OwOSS -- собственный домен сервера (напр. owocloud.online)")
	owossPassword := flag.String("owoss-password", "", "Per-user пароль для OwOSS -- тот же, что в secrets.json на сервере")

	flag.Parse()

	if *upstream == "" {
		log.Fatal("[main] --upstream required: https://owo:pass@proxy.owocloud.online")
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[main] OwOCloak Session Manager starting")
	log.Printf("[main] listen=%s naive=%s relay=%v", *listenAddr, *naiveBin, *relay)

	// ── Токен локального SOCKS5-листенера ────────────────────────────────────
	// Закрывает обход split-tunneling через localhost (см. socks5_server.go).
	// [OwO fix] Раньше эта секция писала сырой токен в log.Printf -- это плохая
	// практика независимо от того, что обычные приложения на Android не могут
	// читать чужой logcat: логи часто утекают куда-то ещё (crash-репортеры,
	// удалённый сбор логов для отладки), и лишняя точка утечки не нужна.
	// Теперь: токен пишется в файл с правами 0600 (владелец — только процесс
	// session-manager), в лог попадает только короткий необратимый отпечаток
	// для подтверждения "какой именно токен сейчас активен", не сам секрет.
	token := []byte(*socks5Token)
	if len(token) == 0 {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			log.Fatalf("[main] failed to generate socks5 token: %v", err)
		}
		token = []byte(hex.EncodeToString(raw))
		tokenPath := filepath.Join(*configDir, "socks5.token")
		if err := os.MkdirAll(*configDir, 0700); err != nil {
			log.Fatalf("[main] failed to create %s: %v", *configDir, err)
		}
		if err := os.WriteFile(tokenPath, token, 0600); err != nil {
			log.Fatalf("[main] failed to write %s: %v", tokenPath, err)
		}
		fp := sha256.Sum256(token)
		log.Printf("[main] generated new SOCKS5 token, written to %s (mode 0600). fingerprint=%s (this is NOT the token itself)", tokenPath, hex.EncodeToString(fp[:4]))
	}

	// ── Инициализация компонентов ─────────────────────────────────────────────
	pool       := NewStickyPool(defaultPool)
	sessionMgr := NewSessionManager()

	naiveMgr, err := NewNaiveManager(*naiveBin, *upstream, *configDir, *basePort, token, []byte(*signalPassword))
	if err != nil {
		log.Fatalf("[main] NaiveManager init: %v", err)
	}

	// Прогрев IoT инстансов
	for _, sni := range []string{
		"ipv4-internet.yandex.net",
		"ipv6-internet.yandex.net",
		"internet.yandex.ru",
	} {
		naiveMgr.GetUpstreamForApp(sni, AppIoT)
	}

	naiveMgr.StartGC(2*time.Minute, 5*time.Minute)

	// ── Cloudflare Radar updater (по регионам, см. cloudflare_updater.go) ────
	StartCloudflareUpdater()

	// ── SOCKS5 сервер ─────────────────────────────────────────────────────────
	// ── OwOSS (опционально) ──────────────────────────────────────────────────
	var ssMgr *SSManager
	if *owossServer != "" {
		if *owossSNI == "" || *owossPassword == "" {
			log.Fatal("[main] --owoss-sni and --owoss-password are required when --owoss-server is set")
		}
		ssMgr = NewSSManager(*owossServer, *owossSNI, []byte(*owossPassword))
		log.Printf("[main] OwOSS enabled: server=%s sni=%s (ALL non-direct traffic routes through OwOSS -- no per-app classifier yet)", *owossServer, *owossSNI)
	}

	server := NewSOCKS5Server(*listenAddr, token, pool, naiveMgr, sessionMgr, ssMgr)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[main] SOCKS5: %v", err)
		}
	}()

	// ── Relay режим ───────────────────────────────────────────────────────────
	var cancelVK context.CancelFunc
	var vkc *VKClient

	if *relay {
		// Валидация флагов
		switch {
			case *relayIP == "":
				log.Fatal("[relay] --relay-ip required in relay mode")
			case *vkToken == "":
				log.Fatal("[relay] --vk-token required in relay mode")
			case *vkGroup == 0:
				log.Fatal("[relay] --vk-group required in relay mode")
			case *vkKey == "":
				log.Fatal("[relay] --vk-key required in relay mode")
		}

		vkc = NewVKClient(*vkToken, *vkGroup, *vkKey, *relayIP, *relayPort, *relayPubkey, *relayKind)

		// Зарегистрироваться в VK Bot
		if err := vkc.Register(); err != nil {
			log.Fatalf("[relay] VK register failed: %v", err)
		}

		// Фоновый пинг каждые 60с
		var ctx context.Context
		ctx, cancelVK = context.WithCancel(context.Background())
		vkc.StartPingLoop(ctx)

		// Relay SOCKS5 сервер
		relaySrv := NewRelayServer(*relayListen, *listenAddr, token, vkc)
		go func() {
			if err := relaySrv.ListenAndServe(); err != nil {
				log.Fatalf("[relay] %v", err)
			}
		}()

		// Status для relay
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for range t.C {
				log.Printf("[relay] active_relay_conns=%d", relaySrv.ActiveConns())
			}
		}()

		log.Printf("[relay] active: public=%s:%d  internal=%s  kind=%s",
			   *relayIP, *relayPort, *relayListen, *relayKind)
	}

	// ── Status ticker ─────────────────────────────────────────────────────────
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			instances := naiveMgr.Status()
			log.Printf("[status] active_conns=%d naive_instances=%d total_served=%d",
				   server.ActiveConns(), len(instances), server.totalConns)
			for _, inst := range instances {
				log.Printf("[status]   sni=%-25s port=%d ready=%v idle=%s",
					   inst.SNI, inst.Port, inst.Ready,
	       time.Since(inst.LastUsed).Round(time.Second))
			}
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[main] Shutting down...")

	if *relay && vkc != nil {
		if cancelVK != nil {
			cancelVK()
		}
		if err := vkc.Unregister(); err != nil {
			log.Printf("[relay] unregister error: %v", err)
		}
	}

	naiveMgr.StopAll()
	log.Printf("[main] Bye")
}
