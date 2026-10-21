package mihomoconfig

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/vmesslink"
)

// The ciphers mihomo's VMess client (sing-vmess) accepts.
var vmessCiphers = []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero", "aes-128-cfb"}

// vmessProxy takes both link forms vmesslink reads. The transports are the
// ones mihomo's own converter maps: tcp (with or without the HTTP header),
// HTTP/2, WebSocket, HTTPUpgrade and gRPC.
func vmessProxy(link, name string) (map[string]any, error) {
	l, err := vmesslink.Parse(link)
	if err != nil {
		return nil, err
	}
	if l.ID == "" || l.Host == "" {
		return nil, fmt.Errorf("vmess: missing uuid or server host")
	}
	cipher := strings.ToLower(l.Cipher)
	if !slices.Contains(vmessCiphers, cipher) {
		return nil, fmt.Errorf("vmess: cipher %q is not supported", l.Cipher)
	}
	q := l.Params
	p := map[string]any{
		"name":    name,
		"type":    "vmess",
		"server":  l.Host,
		"port":    l.Port,
		"uuid":    l.ID,
		"alterId": l.AlterID,
		"cipher":  cipher,
		"udp":     true,
	}
	// As mihomo's converter: XUDP unless the link asks for packetaddr or none.
	switch q.Get("packetEncoding") {
	case "none":
	case "packet", "packetaddr":
		p["packet-addr"] = true
	default:
		p["xudp"] = true
	}

	if err := applyVmessTransport(p, q); err != nil {
		return nil, err
	}

	switch security := q.Get("security"); security {
	case "", "none":
	case "tls":
		p["tls"] = true
		if sni := q.Get("sni"); sni != "" {
			p["servername"] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			p["client-fingerprint"] = fp
		}
		if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
			p["alpn"] = alpn
		}
		if err := applyCertChecks(p, q, "vmess"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("vmess: security %q is not supported", security)
	}
	return p, nil
}

func applyVmessTransport(p map[string]any, q url.Values) error {
	network := q.Get("type")
	host, path := q.Get("host"), q.Get("path")
	switch network {
	case "tcp":
		switch header := q.Get("headerType"); header {
		case "", "none":
			p["network"] = "tcp"
		case "http":
			p["network"] = "http"
			opts := map[string]any{"path": []string{orSlash(path)}}
			if host != "" {
				opts["headers"] = map[string]any{"Host": splitCSV(host)}
			}
			p["http-opts"] = opts
		default:
			return fmt.Errorf("vmess: tcp header %q is not supported", header)
		}
	case "h2":
		p["network"] = "h2"
		opts := map[string]any{"path": orSlash(path)}
		if host != "" {
			opts["host"] = splitCSV(host)
		}
		p["h2-opts"] = opts
	case "ws", "httpupgrade":
		p["network"] = "ws"
		opts := map[string]any{}
		if host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		if network == "httpupgrade" {
			opts["v2ray-http-upgrade"] = true
		}
		path, earlyData, err := splitEarlyData(orSlash(path))
		if err != nil {
			return err
		}
		opts["path"] = path
		if earlyData > 0 {
			if network == "httpupgrade" {
				opts["v2ray-http-upgrade-fast-open"] = true
			} else {
				opts["max-early-data"] = earlyData
				opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
			}
		}
		if header := q.Get("eh"); header != "" && network == "ws" {
			opts["early-data-header-name"] = header
		}
		p["ws-opts"] = opts
	case "grpc":
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]any{"grpc-service-name": q.Get("serviceName")}
	default:
		return fmt.Errorf("vmess: transport %q is not supported", network)
	}
	return nil
}

func orSlash(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

// splitEarlyData takes xray's "?ed=2048" off a WebSocket path into mihomo's
// own options. mihomo would strip it from the path itself, but then set
// Sec-WebSocket-Protocol over the link's eh header name, and read it as
// WebSocket early data on an HTTPUpgrade path too.
func splitEarlyData(path string) (string, int, error) {
	u, err := url.Parse(path)
	if err != nil {
		return path, 0, nil
	}
	q := u.Query()
	ed := q.Get("ed")
	if ed == "" {
		return path, 0, nil
	}
	n, err := strconv.Atoi(ed)
	if err != nil || n < 0 {
		return "", 0, fmt.Errorf("vmess: invalid early-data size %q", ed)
	}
	q.Del("ed")
	u.RawQuery = q.Encode()
	return u.String(), n, nil
}
