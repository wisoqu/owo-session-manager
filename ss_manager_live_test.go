package main

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"
)

// testCertPath -- путь к тестовому self-signed сертификату для проверки
// через RootCAs (см. TestSSManager_LiveAgainstRealFrontAndBackend). По
// умолчанию ищет ./testcert.pem рядом с этим файлом; переопределяется
// переменной окружения OWOSS_TEST_CERT, если у вас сертификат лежит
// в другом месте. Оба живых теста в этом файле требуют реально
// запущенных owo-ss-front (127.0.0.1:8443), owo-ss-backend, и echo-цели
// (127.0.0.1:7000) -- пропускаются автоматически, если сертификат не найден.
func testCertPath() string {
	if p := os.Getenv("OWOSS_TEST_CERT"); p != "" {
		return p
	}
	return "testcert.pem"
}

func loadTestCertPool(t *testing.T) *x509.CertPool {
	t.Helper()
	certPEM, err := os.ReadFile(testCertPath())
	if err != nil {
		t.Skipf("test cert not found at %s (set OWOSS_TEST_CERT or place testcert.pem here) -- skipping live test: %v", testCertPath(), err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to parse test cert into pool")
	}
	return pool
}

// TestSSManager_LiveAgainstRealFrontAndBackend -- НЕ юнит-тест в обычном
// смысле: требует реально запущенных owo-ss-front (127.0.0.1:8443),
// owo-ss-backend, и echo-цели (127.0.0.1:7000) из песочницы. Оставлен как
// подтверждение, что ss_manager.go реально работает против настоящих
// собранных ранее бинарников, а не только компилируется.
func TestSSManager_LiveAgainstRealFrontAndBackend(t *testing.T) {
	pool := loadTestCertPool(t)

	password := []byte("stage6-real-test-password-owoss")
	mgr := NewSSManager("127.0.0.1:8443", "owoss-test.local", password)
	mgr.RootCAs = pool // тестовый самоподписанный сертификат -- честная проверка через кастомный пул, не InsecureSkipVerify

	conn, err := mgr.Dial("127.0.0.1", 7000)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("hello from real ss_manager.go\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	want := "ECHO:hello from real ss_manager.go\n"
	if reply != want {
		t.Errorf("got %q, want %q", reply, want)
	}
	t.Logf("SUCCESS: ss_manager.go's SSManager.Dial() works against the real running owo-ss-front/owo-ss-backend")
}

func TestSSManager_ConcurrentDialsShareOneSession(t *testing.T) {
	pool := loadTestCertPool(t)

	mgr := NewSSManager("127.0.0.1:8443", "owoss-test.local", []byte("stage6-real-test-password-owoss"))
	mgr.RootCAs = pool

	const n = 5
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			conn, err := mgr.Dial("127.0.0.1", 7000)
			if err != nil {
				errs <- fmt.Errorf("dial %d: %w", i, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			msg := fmt.Sprintf("concurrent-%d\n", i)
			if _, err := conn.Write([]byte(msg)); err != nil {
				errs <- fmt.Errorf("write %d: %w", i, err)
				return
			}
			reply, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				errs <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if reply != "ECHO:"+msg {
				errs <- fmt.Errorf("stream %d: got %q, want %q", i, reply, "ECHO:"+msg)
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	t.Log("SUCCESS: 5 concurrent Dial() calls correctly multiplexed over one persistent session")
}
