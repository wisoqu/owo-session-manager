package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Список проверен по https://github.com/hxehex/russia-mobile-internet-whitelist —
// берём только КОРНЕВЫЕ домены банков/госорганов оттуда (поддомены покрываются
// суффиксным матчингом в IsDirectDomain автоматически, добавлять их по одной
// штуке не нужно: sberbank.ru уже покрывает online.sberbank.ru, bfds.sberbank.ru и т.д.)

// sensitiveDirectDomains — банки, госуслуги и прочие сервисы, где проходят
// реальные деньги/документы пользователя.
//
// ПОЧЕМУ ЭТО ОБЯЗАТЕЛЬНО:
// SNIPool использует домены вроде sberbank.ru/gosuslugi.ru как маскировочный
// SNI для ЧУЖОГО трафика (это нормальная техника обхода цензуры — подмена
// поля SNI в TLS ClientHello). Но если пользователь САМ открывает настоящий
// sberbank.ru — этот трафик НЕ должен идти через proxy-цепочку
// (PC-доброволец → Frankfurt VPS), потому что тогда его реальная банковская
// TLS-сессия (логин, OTP, платёжные данные) физически проходит через узлы,
// которым нет причин её видеть. Это уже не обход цензуры — это риск MITM
// для самого пользователя, которого мы обязаны исключить.
//
// Поэтому: если хост назначения совпадает с этим списком — прямое
// соединение с устройства, минуя весь proxy-стек. SNI/маскировка вообще
// не применяется, как и не должна.
//
// ВАЖНО: этот список НЕ читается из внешнего конфига и не может быть
// изменён/отключён через additionalDirectDomains ниже — это осознанное
// решение. Если бы safety-critical список банков/госуслуг можно было
// перезаписать обычным конфиг-файлом, баг или атака на этот файл могли бы
// тихо отключить защиту от MITM для чьей-то банковской сессии.
// additionalDirectDomains — это ДОПОЛНЕНИЕ поверх, никогда не замена.
var sensitiveDirectDomains = []string{
	// Банки (подтверждено в whitelist.txt: sberbank.ru, tbank.ru, vtb.ru, alfabank.ru)
	"sberbank.ru",
	"tbank.ru", "tinkoff.ru", "cdn-tinkoff.ru",
	"vtb.ru",
	"alfabank.ru",
	"raiffeisen.ru",
	"gazprombank.ru",
	"rshb.ru",
	"psbank.ru",

	// Госуслуги и государственные сервисы (подтверждено в whitelist.txt)
	"gosuslugi.ru",
	"nalog.ru", "nalog.gov.ru",
	"cbr.ru",
	"mos.ru",
	"gibdd.ru",
	"rosreestr.ru",
	"fssp.gov.ru",
	"government.ru",  // правительство РФ
	"kremlin.ru",
	"duma.gov.ru",     // госдума
	"izbirkom.ru",     // ЦИК
	"cikrf.ru",        // ЦИК (альт. домен)
	"digital.gov.ru",  // Минцифры
	"roskachestvo.gov.ru",
	"genproc.gov.ru",  // Генпрокуратура
	"ofd.ru",          // оператор фискальных данных — налоговая чувствительность
	"rzd.ru",          // РЖД — оплата билетов, паспортные данные при покупке
}

// additionalDirectDomains — пользовательские "В обход"-правила из
// Flutter-клиента (раздельное туннелирование). В отличие от
// sensitiveDirectDomains это не safety-критично, просто предпочтение
// пользователя — поэтому можно грузить из файла и не хардкодить.
//
// Матчинг у IsDirectDomain уже суффиксный (host == d || HasSuffix(host,
// "."+d)) — значит запись "ru" уже покрывает любой поддомен .ru без
// специального wildcard-синтаксиса. Клиент может передать "*.ru" — здесь
// просто срезаем ведущее "*." перед добавлением в список, дальше работает
// та же суффиксная проверка, что и для обычных доменов.
var (
	additionalDirectDomains   []string
	additionalDirectDomainsMu sync.RWMutex
)

// LoadAdditionalDirectDomains читает список из текстового файла (один домен
// на строку, "#" — комментарий, пустые строки пропускаются). Отсутствие
// файла — не ошибка (флаг мог быть не передан вообще, работаем только с
// sensitiveDirectDomains), но ошибку чтения существующего файла возвращаем,
// не глотаем молча.
func LoadAdditionalDirectDomains(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[direct-domains] файл %s не найден, используется только встроенный safety-список", path)
			return nil
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var loaded []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "*.")
		loaded = append(loaded, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	additionalDirectDomainsMu.Lock()
	additionalDirectDomains = loaded
	additionalDirectDomainsMu.Unlock()

	log.Printf("[direct-domains] загружено %d доменов из %s (поверх %d встроенных)",
		len(loaded), path, len(sensitiveDirectDomains))
	return nil
}

// IsDirectDomain проверяет, должен ли хост идти напрямую, минуя proxy/naive/SNI-pool.
// Точное совпадение или поддомен (host == d || host оканчивается на "."+d).
// Сначала всегда проверяется safety-critical список (sensitiveDirectDomains),
// затем — пользовательские правила (additionalDirectDomains), если загружены.
func IsDirectDomain(host string) bool {
	host = strings.ToLower(host)
	for _, d := range sensitiveDirectDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}

	additionalDirectDomainsMu.RLock()
	defer additionalDirectDomainsMu.RUnlock()
	for _, d := range additionalDirectDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ResolveDirect резолвит хост через DoH к Яндексу (common.dot.dns.yandex.net),
// а не через системный DNS PC-добровольца.
//
// ПОЧЕМУ: обычный DNS (1.1.1.1/8.8.8.8) в "the shield"/IP+SNI-режиме (см. README
// repo hxehex/russia-mobile-internet-whitelist) тоже может резаться у некоторых
// операторов — та же история, что с DNS-over-HTTPS у Apple. common.dot.dns.yandex.net
// — поддомен yandex.net, он сам в белом списке, поэтому SNI в TLS-рукопожатии
// к самому резолверу выглядит как обычное обращение к Яндексу.
//
// ВАЖНО — границы этого решения: если оператор уже перешёл на комбинированную
// модель IP+SNI (см. "the shield" в README репозитория), DoH-запрос пройдёт по SNI,
// но дальнейшее TCP-соединение к РЕАЛЬНОМУ IP банка/госуслуги всё равно может
// блокироваться по IP — и от этого DoH не защищает. Это фундаментальное
// ограничение SNI-only обхода, не баг в этой функции.
func ResolveDirect(ctx context.Context, host string) ([]net.IP, error) {
	// A-запрос в wire-формате (RFC 1035), без внешних зависимостей.
	q := buildDNSQuery(host)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://common.dot.dns.yandex.net/dns-query", bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Fallback: системный резолвер PC (работает, если PC не на мобильной сети).
		return net.DefaultResolver.LookupIP(ctx, "ip4", host)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return net.DefaultResolver.LookupIP(ctx, "ip4", host)
	}
	ips := parseDNSAnswerIPs(body)
	if len(ips) == 0 {
		return net.DefaultResolver.LookupIP(ctx, "ip4", host)
	}
	return ips, nil
}

// buildDNSQuery собирает минимальный DNS A-запрос в wire-формате.
func buildDNSQuery(host string) []byte {
	buf := new(bytes.Buffer)
	// Header: ID, flags (recursion desired), 1 question
	buf.Write([]byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range strings.Split(host, ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)             // конец имени
	buf.Write([]byte{0x00, 0x01})   // QTYPE = A
	buf.Write([]byte{0x00, 0x01})   // QCLASS = IN
	return buf.Bytes()
}

// parseDNSAnswerIPs вытаскивает A-записи из ответа (минимальный парсер, без
// поддержки сжатия имён в RDATA — для простого A-ответа от Яндекса достаточно).
func parseDNSAnswerIPs(msg []byte) []net.IP {
	if len(msg) < 12 {
		return nil
	}
	ancount := int(msg[6])<<8 | int(msg[7])
	if ancount == 0 {
		return nil
	}
	pos := 12
	// Пропускаем секцию Question
	for pos < len(msg) && msg[pos] != 0 {
		pos += int(msg[pos]) + 1
	}
	pos += 5 // null byte + QTYPE(2) + QCLASS(2)

	var ips []net.IP
	for i := 0; i < ancount && pos < len(msg); i++ {
		// NAME (учитываем возможное сжатие — 2 байта с битами 0xC0)
		if pos < len(msg) && msg[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(msg) && msg[pos] != 0 {
				pos += int(msg[pos]) + 1
			}
			pos++
		}
		if pos+10 > len(msg) {
			break
		}
		rtype := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10
		if pos+rdlen > len(msg) {
			break
		}
		if rtype == 1 && rdlen == 4 { // A record
			ips = append(ips, net.IP(msg[pos:pos+4]))
		}
		pos += rdlen
	}
	return ips
}
