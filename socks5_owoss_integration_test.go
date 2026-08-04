package main

import (
	"bufio"
	"crypto/x509"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// TestSOCKS5Server_RealOwOSSIntegration -- проверяет ПОЛНУЮ цепочку, как
// её увидел бы настоящий телефон/приложение: настоящий SOCKS5-клиент ->
// настоящий handleConn (в составе настоящего SOCKS5Server, с ssMgr) ->
// настоящие owo-ss-front/owo-ss-backend -> настоящая цель. Требует уже
// запущенных owo-ss-front (127.0.0.1:8443) и echo-цели (127.0.0.1:7000).
func TestSOCKS5Server_RealOwOSSIntegration(t *testing.T) {
	certPEM, err := os.ReadFile(testCertPath())
	if err != nil {
		t.Skipf("test cert not found (%v) -- skipping", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	ssMgr := NewSSManager("127.0.0.1:8443", "owoss-test.local", []byte("stage6-real-test-password-owoss"))
	ssMgr.RootCAs = pool

	naiveMgr, err := NewNaiveManager("/bin/true", "https://dummy:dummy@dummy.example", t.TempDir(), 11000, []byte("dummy-token"), nil)
	if err != nil {
		t.Fatalf("NewNaiveManager: %v", err)
	}

	token := []byte("test-socks5-token")
	server := NewSOCKS5Server("", token, NewStickyPool(defaultPool), naiveMgr, NewSessionManager(), ssMgr)

	// handleConn напрямую через net.Pipe -- не поднимаем реальный TCP-листенер
	// session-manager'а, но handleConn -- ровно та же функция, что вызвал бы
	// ListenAndServe() на настоящем accept().
	clientSide, serverSide := net.Pipe()
	go server.handleConn(serverSide)

	// ── Настоящий SOCKS5-хендшейк с клиентской стороны ──────────────────────
	clientSide.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: версия 5, 1 метод, RFC1929 (username/password)
	if _, err := clientSide.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := ioReadFull(clientSide, resp); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("unexpected auth method selection: %v", resp)
	}

	// RFC1929 username/password subnegotiation
	uname := []byte("testuser")
	auth := []byte{0x01, byte(len(uname))}
	auth = append(auth, uname...)
	auth = append(auth, byte(len(token)))
	auth = append(auth, token...)
	if _, err := clientSide.Write(auth); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := ioReadFull(clientSide, authResp); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authResp[1] != 0x00 {
		t.Fatalf("auth rejected: %v", authResp)
	}

	// CONNECT-запрос на нашу echo-цель (127.0.0.1:7000)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], 7000)
	req = append(req, portBytes[:]...)
	if _, err := clientSide.Write(req); err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := ioReadFull(clientSide, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT failed, reply code=%d", reply[1])
	}

	// ── Реальные данные через ВЕСЬ путь ──────────────────────────────────────
	clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientSide.Write([]byte("hello through the FULL real integration path\n")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	line, err := bufio.NewReader(clientSide).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	want := "ECHO:hello through the FULL real integration path\n"
	if line != want {
		t.Errorf("got %q, want %q", line, want)
	}
	t.Log("SUCCESS: real SOCKS5 client -> real handleConn -> real ssMgr -> real owo-ss-front/backend -> real target, all working together")
}

func ioReadFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
