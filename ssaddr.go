package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SS-style addressing (Shadowsocks/SOCKS5 family): каждый проксируемый
// stream начинается с адреса назначения в формате:
//
//	ATYP(1) + address + port(2, big-endian)
//
// ATYP: 0x01 = IPv4 (address = 4 байта), 0x03 = domain name
// (address = 1-байтная длина + сама строка), 0x04 = IPv6 (address = 16 байт).
//
// Это Stage 4a -- парсинг адреса и реальное проксирование БЕЗ шифрования.
// AEAD-слой (Stage 4b) добавляется поверх этого же формата отдельным шагом
// сознательно: так проще ловить баги в каждой половине по отдельности,
// не мешая парсинг протокола с криптографией в одном PR.

// ATYP-константы (atypIPv4/atypDomain/atypIPv6) уже объявлены в
// socks5_server.go с теми же значениями (SOCKS5 и Shadowsocks используют
// одну и ту же конвенцию ATYP) -- переиспользуем их напрямую, не
// дублируем в этом файле.

// ssReadTargetAddr читает ATYP+address+port из r и возвращает готовую
// строку "host:port", с которой можно сразу идти в net.Dial.
func ssReadTargetAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", fmt.Errorf("read ATYP: %w", err)
	}

	var host string
	switch atyp[0] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("read IPv4 address: %w", err)
		}
		host = net.IP(b[:]).String()

	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("read IPv6 address: %w", err)
		}
		host = net.IP(b[:]).String()

	case atypDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(lenByte[0])
		if domainLen == 0 {
			return "", fmt.Errorf("zero-length domain name")
		}
		nameBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			return "", fmt.Errorf("read domain name (%d bytes): %w", domainLen, err)
		}
		host = string(nameBuf)

	default:
		return "", fmt.Errorf("unknown ATYP 0x%02x", atyp[0])
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes[:])

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// ssEncodeTargetAddr -- обратная операция, нужна клиентской стороне
// (ss_manager.go в session-manager) для формирования того же самого
// префикса перед отправкой. Включена уже сейчас, а не отложена до
// клиентского Stage, потому что тривиальна и тестируется round-trip'ом
// прямо здесь.
func ssEncodeTargetAddr(host string, port uint16) ([]byte, error) {
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, atypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, atypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long: %d bytes (max 255)", len(host))
		}
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, []byte(host)...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	out = append(out, portBytes[:]...)
	return out, nil
}
