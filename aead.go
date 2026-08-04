package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Stage 4b: AEAD-шифрование поверх уже готового Stage 4a (ATYP+addr+port +
// проксирование). Сознательно устроено как io.Reader/io.Writer-обёртка
// вокруг stream -- так ssReadTargetAddr и весь остальной код Stage 4a
// остаются НЕИЗМЕННЫМИ, просто применяются уже к расшифрованному потоку,
// а не к сырым байтам. Формат в духе Shadowsocks AEAD (2022-edition идея):
//
//	[salt: keySize байт, plaintext]
//	[chunk]*
//
// chunk := [len_encrypted: 2+overhead][payload_encrypted: N+overhead]
//   - len_encrypted расшифровывается в uint16 длину payload (макс 0xFFFF)
//   - каждый chunk (и для длины, и для payload) шифруется под ОТДЕЛЬНЫМ
//     nonce, монотонно инкрементируемым за всю жизнь соединения в
//     конкретном направлении (как в оригинальном SS AEAD)
//
// masterKey получается из per-user пароля через sha256 (тот же пароль,
// что уже используется для owo_signal HMAC -- но с доменным разделением:
// см. deriveMasterKey, salt строки разные для сигнала и для этого).
// perSessionKey -- HKDF-Expand(masterKey, salt, "owoss-subkey").

const (
	aeadKeySize   = chacha20poly1305.KeySize   // 32
	aeadNonceSize = chacha20poly1305.NonceSize // 12
	aeadTagSize   = 16
	maxChunkPlain = 0xFFFF // максимальный размер payload одного чанка
	lenFieldPlain = 2      // uint16 длины payload перед шифрованием
)

// deriveMasterKey -- sha256(password) обрезанный/расширенный до 32 байт.
// Доменное разделение с owo_signal: используем сам пароль как есть (он уже
// per-user секрет, отдельный от подписи ClientHello -- см. память: разные
// поля используют один и тот же per-user пароль пользователя, но HMAC для
// сигнала и AEAD-ключ для данных выводятся по-разному и с разным контекстом,
// так что компрометация одного не даёт напрямую другой).
func deriveMasterKey(password []byte) [aeadKeySize]byte {
	return sha256.Sum256(append([]byte("owoss-master-key|"), password...))
}

// derivePerSessionKey -- HKDF-Expand(masterKey, salt, info) -> 32 байта.
func derivePerSessionKey(masterKey [aeadKeySize]byte, salt []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, masterKey[:], salt, []byte("owoss-subkey"))
	key := make([]byte, aeadKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// aeadNonceCounter -- монотонный nonce-счётчик для одного направления
// одного соединения. per-direction, per-connection -- никогда не
// переиспользуется между направлениями (у каждого своя пара ключ/counter
// был бы избыточен, поэтому один и тот же subkey используется в обе
// стороны, но с двумя РАЗНЫМИ salt'ами -- см. newAEADStream).
type aeadNonceCounter struct {
	counter uint64
}

func (c *aeadNonceCounter) next() [aeadNonceSize]byte {
	var n [aeadNonceSize]byte
	binary.LittleEndian.PutUint64(n[:8], c.counter)
	c.counter++
	return n
}

// aeadStream оборачивает io.ReadWriter (сюда пойдёт smux.Stream) и
// реализует io.Reader/io.Writer поверх расшифрованных/зашифрованных
// данных. Salt для каждого направления отдельный: клиент шлёт свой salt
// первым же, сервер -- свой первым же в обратную сторону, чтобы избежать
// nonce-коллизий между направлениями при одном общем subkey было бы риском
// -- поэтому вместо этого выводим ДВА разных subkey (по одному на
// направление) через два разных HKDF info-параметра.
type aeadStream struct {
	rw io.ReadWriter

	readAEAD   cipher.AEAD
	writeAEAD  cipher.AEAD
	readNonce  aeadNonceCounter
	writeNonce aeadNonceCounter

	readBuf []byte // остаток недочитанного расшифрованного chunk'а

	// readInit -- если не nil, вызывается ОДИН раз перед первым реальным
	// Read() и должен установить readAEAD. Нужен клиенту: клиент пишет
	// свой salt и сразу готов слать зашифрованные данные (writeAEAD уже
	// есть), но НЕ должен блокироваться на чтении salt'а сервера прямо в
	// конструкторе -- иначе выходит взаимный дедлок (сервер не пришлёт
	// свой salt, пока не получит и не расшифрует первый чанк от клиента,
	// а клиент не может отправить первый чанк, пока не вернулся из
	// конструктора). Поэтому чтение serverSalt откладывается до момента,
	// когда caller реально попытается что-то прочитать -- к этому моменту
	// сервер уже получил первый чанк и прислал свой salt в ответ.
	readInit func() error
}

// newAEADServerStream -- серверная сторона (owo-ss-backend). В отличие от
// newAEADClientStream -- клиентская сторона (используется здесь в
// session-manager). Пишет СВОЙ salt немедленно (writeAEAD готов сразу же --
// caller может начинать Write() без дальнейших блокировок), но чтение
// salt'а сервера (и, соответственно, готовность readAEAD) откладывается до
// первого реального Read() -- см. комментарий у поля readInit в структуре
// aeadStream. (Серверная сторона newAEADServerStream не нужна здесь --
// session-manager всегда клиент; см. owo-ss-backend для серверной версии.)
func newAEADClientStream(rw io.ReadWriter, password []byte) (*aeadStream, error) {
	masterKey := deriveMasterKey(password)

	clientSalt, err := randomBytes(aeadKeySize)
	if err != nil {
		return nil, err
	}
	if _, err := rw.Write(clientSalt); err != nil {
		return nil, fmt.Errorf("write client salt: %w", err)
	}
	writeKey, err := derivePerSessionKey(masterKey, clientSalt)
	if err != nil {
		return nil, err
	}
	writeAEAD, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, fmt.Errorf("new write AEAD: %w", err)
	}

	s := &aeadStream{rw: rw, writeAEAD: writeAEAD}
	s.readInit = func() error {
		serverSalt := make([]byte, aeadKeySize)
		if _, err := io.ReadFull(rw, serverSalt); err != nil {
			return fmt.Errorf("read server salt: %w", err)
		}
		readKey, err := derivePerSessionKey(masterKey, serverSalt)
		if err != nil {
			return err
		}
		readAEAD, err := chacha20poly1305.New(readKey)
		if err != nil {
			return fmt.Errorf("new read AEAD: %w", err)
		}
		s.readAEAD = readAEAD
		return nil
	}
	return s, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}

// Write шифрует plaintext в один или несколько chunk'ов (режется по
// maxChunkPlain) и пишет их в rw.
func (s *aeadStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunkPlain {
			n = maxChunkPlain
		}
		chunk := p[:n]

		var lenBuf [lenFieldPlain]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))

		lenNonce := s.writeNonce.next()
		encLen := s.writeAEAD.Seal(nil, lenNonce[:], lenBuf[:], nil)

		payloadNonce := s.writeNonce.next()
		encPayload := s.writeAEAD.Seal(nil, payloadNonce[:], chunk, nil)

		if _, err := s.rw.Write(encLen); err != nil {
			return total, fmt.Errorf("write chunk length: %w", err)
		}
		if _, err := s.rw.Write(encPayload); err != nil {
			return total, fmt.Errorf("write chunk payload: %w", err)
		}

		total += n
		p = p[n:]
	}
	return total, nil
}

// Read отдаёт расшифрованные байты, читая и расшифровывая chunk'и по мере
// необходимости, буферизуя остаток недочитанного chunk'а в readBuf.
func (s *aeadStream) Read(p []byte) (int, error) {
	if s.readInit != nil {
		if err := s.readInit(); err != nil {
			return 0, fmt.Errorf("lazy read-side init: %w", err)
		}
		s.readInit = nil
	}
	if len(s.readBuf) == 0 {
		if err := s.readNextChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

// aeadIdleTimeout -- если пир не прислал ни байта дольше этого времени,
// считаем соединение мёртвым и прерываем блокирующий Read() сами, не
// полагаясь только на то, что чей-то Close() успеет прервать уже начатый
// вызов. Актуально именно для случая, когда локальный клиент обрывается
// аварийно (SIGKILL и т.п.) без штатного закрытия -- тогда одна из двух
// горутин в pipe() может виснуть на Read() от уже неактуального стрима
// сколь угодно долго, если Close() почему-то не прерывает начатый вызов
// (зависит от того, как именно это реализовано в конкретной обёртке).
const aeadIdleTimeout = 90 * time.Second

func (s *aeadStream) readNextChunk() error {
	if c, ok := s.rw.(net.Conn); ok {
		c.SetReadDeadline(time.Now().Add(aeadIdleTimeout))
	}
	encLen := make([]byte, lenFieldPlain+aeadTagSize)
	if _, err := io.ReadFull(s.rw, encLen); err != nil {
		return fmt.Errorf("read chunk length: %w", err)
	}
	lenNonce := s.readNonce.next()
	lenBuf, err := s.readAEAD.Open(nil, lenNonce[:], encLen, nil)
	if err != nil {
		return fmt.Errorf("decrypt chunk length (auth failed -- wrong key or tampered data): %w", err)
	}
	payloadLen := binary.BigEndian.Uint16(lenBuf)
	if payloadLen == 0 || int(payloadLen) > maxChunkPlain {
		return fmt.Errorf("implausible chunk payload length: %d", payloadLen)
	}

	encPayload := make([]byte, int(payloadLen)+aeadTagSize)
	if _, err := io.ReadFull(s.rw, encPayload); err != nil {
		return fmt.Errorf("read chunk payload: %w", err)
	}
	payloadNonce := s.readNonce.next()
	plain, err := s.readAEAD.Open(nil, payloadNonce[:], encPayload, nil)
	if err != nil {
		return fmt.Errorf("decrypt chunk payload (auth failed -- wrong key or tampered data): %w", err)
	}
	s.readBuf = plain
	return nil
}

// ── net.Conn совместимость ──────────────────────────────────────────────
// aeadStream оборачивает io.ReadWriter (обычно smux.Stream, который сам
// уже полноценный net.Conn). Эти методы делегируют в него, когда это
// возможно -- так aeadStream можно передать напрямую в существующий
// s.pipe(conn net.Conn, upstream net.Conn, ...) в socks5_server.go, не
// меняя сигнатуру pipe() ради нашего протокола.
func (s *aeadStream) Close() error {
	if c, ok := s.rw.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (s *aeadStream) LocalAddr() net.Addr {
	if c, ok := s.rw.(net.Conn); ok {
		return c.LocalAddr()
	}
	return nil
}

func (s *aeadStream) RemoteAddr() net.Addr {
	if c, ok := s.rw.(net.Conn); ok {
		return c.RemoteAddr()
	}
	return nil
}

func (s *aeadStream) SetDeadline(t time.Time) error {
	if c, ok := s.rw.(net.Conn); ok {
		return c.SetDeadline(t)
	}
	return nil
}

func (s *aeadStream) SetReadDeadline(t time.Time) error {
	if c, ok := s.rw.(net.Conn); ok {
		return c.SetReadDeadline(t)
	}
	return nil
}

func (s *aeadStream) SetWriteDeadline(t time.Time) error {
	if c, ok := s.rw.(net.Conn); ok {
		return c.SetWriteDeadline(t)
	}
	return nil
}
