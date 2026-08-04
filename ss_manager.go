package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

// ss_manager.go -- клиентская часть OwOSS. Архитектурно параллельно
// naive_manager.go, но устроено иначе изнутри: naive_manager.go спавнит
// внешний C++ процесс на каждый SNI и потом сам делает SOCKS5-CONNECT в
// него; здесь нет внешнего процесса вообще -- вся протокольная логика на
// Go, и вместо "получить локальный адрес -> дозвониться -> SOCKS5-CONNECT"
// используется один ДОЛГОЖИВУЩИЙ TLS+smux-сеанс к серверу OwOSS, а каждый
// новый прокси-запрос -- это просто OpenStream() в уже установленный
// сеанс (см. память проекта: OwOSS всегда работает в muxed-режиме для
// MVP, и держит один сеанс, а не по одному на SNI, потому что тут нет
// декой-под-разные-домены логики, которая заставляла naive плодить
// инстансы -- OwOSS ходит всегда на один и тот же собственный домен).
//
// Генерация ClientHello -- через uTLS (не настоящий Chromium-стек, как у
// naive) -- сознательное решение для MVP, см. память проекта: у OwOSS нет
// эталонной популяции "как обычно выглядят визиты сюда", в отличие от
// OwONaive, которая маскируется под чужой популярный домен -- поэтому
// планка качества фингерпринта здесь объективно ниже.

// owoSignalWindowSeconds -- см. owo_signal.go на серверной стороне
// (owo-ss-front); здесь та же константа, независимая копия, потому что
// session-manager не делит код с owo-front/owo-ss-front репозиторием.
const owoSignalWindowSeconds = 30

// owoComputeSignal -- та же функция, что и на сервере (owo_signal.go),
// нужна клиенту, чтобы вычислить, что вписать в SessionId ClientHello.
func owoComputeSignal(password []byte, clientRandom []byte, window int64) [4]byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(clientRandom)
	var windowBytes [8]byte
	binary.BigEndian.PutUint64(windowBytes[:], uint64(window))
	mac.Write(windowBytes[:])
	sum := mac.Sum(nil)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
}

// SSManager -- клиент OwOSS. Один экземпляр на процесс session-manager,
// как и остальные менеджеры (NaiveManager, SessionManager).
type SSManager struct {
	serverAddr string // публичный адрес owo-ss-front, напр. "owocloud.example:443"
	serverName string // SNI/ServerName -- СВОЙ домен OwOSS, не декой-домен из sniPool
	password   []byte // per-user пароль -- тот же, что и secrets.json на сервере

	// RootCAs -- опционально, кастомный пул доверенных CA вместо системного
	// (nil = обычная системная проверка, стандартный путь для прода с
	// настоящим Let's Encrypt-сертификатом). Нужен, например, для внутреннего
	// CA или для тестовых стендов с самоподписанным сертификатом -- НЕ для
	// отключения проверки вообще (InsecureSkipVerify сознательно не
	// используется нигде в этом файле).
	RootCAs *x509.CertPool

	// ClientHelloID -- какой uTLS-пресет фингерпринта использовать (nil --
	// HelloChrome_Auto по умолчанию). Указатель, а не значение: у
	// utls.ClientHelloID есть несравнимые через == поля, надёжный способ
	// проверить "не задано" -- именно nil. Сознательно вынесено в
	// настраиваемое поле, а не захардкожено: детектируемость конкретных
	// пресетов меняется со временем по мере устаревания относительно
	// реальных версий Chrome (см. память проекта), и это должно быть
	// обновляемо через конфиг команды/self-hoster'а, а не требовать
	// пересборки клиента. Не предполагается как настройка для рядового
	// пользователя приложения -- он не может осмысленно оценить компромисс
	// детектируемости.
	ClientHelloID *utls.ClientHelloID

	mu      sync.Mutex
	session *smux.Session
}

func NewSSManager(serverAddr, serverName string, password []byte) *SSManager {
	return &SSManager{
		serverAddr: serverAddr,
		serverName: serverName,
		password:   password,
	}
}

// ensureSession возвращает живой smux.Session, устанавливая новый при
// необходимости (первый вызов, либо предыдущий сеанс умер).
func (m *SSManager) ensureSession() (*smux.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.session != nil && !m.session.IsClosed() {
		return m.session, nil
	}

	sess, err := m.dialNewSession()
	if err != nil {
		return nil, err
	}
	m.session = sess
	log.Printf("[SSMgr] new OwOSS session established to %s (sni=%s)", m.serverAddr, m.serverName)
	return sess, nil
}

// dialNewSession -- полный цикл установления соединения: TCP -> uTLS
// ClientHello с вписанным HMAC-сигналом -> настоящий TLS-хендшейк -> байт
// режима (muxed) -> smux.Client поверх готового TLS-соединения.
// owossSmuxConfig -- общий конфиг smux для клиента И сервера (версии должны
// совпадать на обеих сторонах, иначе протокол не совпадёт). DefaultConfig()
// даёт Version:1 (без реального flow control) и MaxStreamBuffer 64KB --
// при RTT порядка 70-100мс это уже может быть тесно для высокой
// пропускной способности (bandwidth-delay product на 90+ Мбит/с при
// 75мс ≈ 850КБ, заметно больше 64КБ). Version:2 даёт настоящий per-stream
// flow control -- поднимаем и версию, и размеры буферов одновременно.
func owossSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxStreamBuffer = 4 * 1024 * 1024  // 4MB per-stream (было 64KB)
	cfg.MaxReceiveBuffer = 16 * 1024 * 1024 // 16MB на сессию (было 4MB)
	return cfg
}

func (m *SSManager) dialNewSession() (*smux.Session, error) {
	rawConn, err := net.DialTimeout("tcp", m.serverAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", m.serverAddr, err)
	}
	// TCP_NODELAY -- см. тот же комментарий в owo-ss-front/owo-ss-backend:
	// маленькие AEAD-чанки (заголовок длины перед каждым payload'ом)
	// страдают от алгоритма Нейгла сильнее обычного трафика, особенно
	// заметно на направлении, где именно ЭТА сторона активно пишет --
	// то есть на отдаче (клиент -> сервер).
	if tc, ok := rawConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	helloID := utls.HelloChrome_Auto
	if m.ClientHelloID != nil {
		helloID = *m.ClientHelloID
	}
	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName: m.serverName,
		RootCAs:    m.RootCAs, // nil = обычная системная проверка (прод); задаётся явно только для CA-пиннинга/тестовых стендов
	}, helloID)

	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}

	clientRandom := uconn.HandshakeState.Hello.Random
	window := time.Now().Unix() / owoSignalWindowSeconds
	tag := owoComputeSignal(m.password, clientRandom, window)

	sessionID, err := randomBytes(32)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("generate session id filler: %w", err)
	}
	copy(sessionID[28:], tag[:])
	uconn.HandshakeState.Hello.SessionId = sessionID
	uconn.HandshakeState.Hello.Raw = nil // заставить uTLS пересобрать ClientHello с новым SessionId

	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Байт режима: muxed (0x00) -- единственный реализованный режим в MVP.
	if _, err := uconn.Write([]byte{0x00}); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("write connection-mode byte: %w", err)
	}

	session, err := smux.Client(uconn, owossSmuxConfig())
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("smux.Client: %w", err)
	}
	return session, nil
}

// Dial -- открывает новый проксируемый поток к dstHost:dstPort через уже
// установленный (или свежеустановленный) OwOSS-сеанс. Возвращает net.Conn,
// готовый к передаче напрямую в существующий s.pipe(conn, upstream, ...)
// в socks5_server.go -- вызывающему коду не нужно знать про TLS/smux/AEAD
// внутри, только Read/Write/Close как у любого обычного соединения.
func (m *SSManager) Dial(dstHost string, dstPort uint16) (net.Conn, error) {
	sess, err := m.ensureSession()
	if err != nil {
		return nil, fmt.Errorf("ensure session: %w", err)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		// Сеанс мог умереть между ensureSession() и OpenStream() (например,
		// сервер разорвал соединение) -- одна попытка переустановить и
		// повторить, не более, чтобы не зациклиться при реально недоступном
		// сервере.
		m.mu.Lock()
		m.session = nil
		m.mu.Unlock()
		sess, err = m.ensureSession()
		if err != nil {
			return nil, fmt.Errorf("ensure session (retry after dead session): %w", err)
		}
		stream, err = sess.OpenStream()
		if err != nil {
			return nil, fmt.Errorf("open stream (after session retry): %w", err)
		}
	}

	aStream, err := newAEADClientStream(stream, m.password)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("newAEADClientStream: %w", err)
	}

	addrBytes, err := ssEncodeTargetAddr(dstHost, dstPort)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("ssEncodeTargetAddr(%s:%d): %w", dstHost, dstPort, err)
	}
	if _, err := aStream.Write(addrBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write target address: %w", err)
	}

	return aStream, nil
}

// Close закрывает текущий сеанс, если он есть (например, при остановке
// session-manager целиком).
func (m *SSManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session != nil {
		err := m.session.Close()
		m.session = nil
		return err
	}
	return nil
}
