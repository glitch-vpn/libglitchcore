package linkrelay

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
)

const (
	socksVersion       = 0x05
	socksAuthVersion   = 0x01
	methodUserPassword = 0x02
	methodNoneAccepted = 0xFF
	authSucceeded      = 0x00
	authFailed         = 0x01
	commandConnect     = 0x01

	addressIPv4   = 0x01
	addressDomain = 0x03
	addressIPv6   = 0x04

	replySucceeded           = 0x00
	replyGeneralFailure      = 0x01
	replyHostUnreachable     = 0x04
	replyCommandNotSupported = 0x07
	replyAddressNotSupported = 0x08
)

var errRefused = errors.New("SOCKS5 client refused")

// negotiate authenticates the client and reads its CONNECT target. Every
// refusal is answered here, so the caller only closes the connection.
func (r *relay) negotiate(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socksVersion {
		return "", errRefused
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if !slices.Contains(methods, methodUserPassword) {
		_, _ = conn.Write([]byte{socksVersion, methodNoneAccepted})
		return "", errRefused
	}
	if _, err := conn.Write([]byte{socksVersion, methodUserPassword}); err != nil {
		return "", err
	}

	if err := r.authenticate(conn); err != nil {
		return "", err
	}
	return readConnectTarget(conn)
}

func (r *relay) authenticate(conn net.Conn) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	user, err := readLengthPrefixed(conn)
	if err != nil {
		return err
	}
	password, err := readLengthPrefixed(conn)
	if err != nil {
		return err
	}
	matched := subtle.ConstantTimeCompare(user, []byte(r.user)) & subtle.ConstantTimeCompare(password, []byte(r.password))
	if version[0] != socksAuthVersion || matched != 1 {
		_, _ = conn.Write([]byte{socksAuthVersion, authFailed})
		return errRefused
	}
	_, err = conn.Write([]byte{socksAuthVersion, authSucceeded})
	return err
}

func readLengthPrefixed(conn net.Conn) ([]byte, error) {
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	value := make([]byte, length[0])
	_, err := io.ReadFull(conn, value)
	return value, err
}

func readConnectTarget(conn net.Conn) (string, error) {
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return "", err
	}
	if request[0] != socksVersion {
		return "", errRefused
	}
	if request[1] != commandConnect {
		reply(conn, replyCommandNotSupported)
		return "", errRefused
	}

	var host string
	switch request[3] {
	case addressIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", err
		}
		host = net.IP(raw).String()
	case addressIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", err
		}
		host = net.IP(raw).String()
	case addressDomain:
		name, err := readLengthPrefixed(conn)
		if err != nil {
			return "", err
		}
		if !isHostName(name) {
			reply(conn, replyGeneralFailure)
			return "", errRefused
		}
		host = string(name)
	default:
		reply(conn, replyAddressNotSupported)
		return "", errRefused
	}

	rawPort := make([]byte, 2)
	if _, err := io.ReadFull(conn, rawPort); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(rawPort)
	if port == 0 {
		reply(conn, replyGeneralFailure)
		return "", errRefused
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// isHostName admits what a name may hold on the wire and nothing a dial
// would read as something else: no empty name, no control or space byte.
func isHostName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, b := range name {
		if b <= 0x20 || b == 0x7F {
			return false
		}
	}
	return true
}

// reply answers a request with the unspecified bound address, which a CONNECT
// client does not read.
func reply(conn net.Conn, code byte) {
	_, _ = conn.Write([]byte{socksVersion, code, 0x00, addressIPv4, 0, 0, 0, 0, 0, 0})
}
