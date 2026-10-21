package xrayconfig

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	xrayNet "github.com/xtls/xray-core/common/net"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/vmesslink"
)

// The ciphers xray's VMess account knows; it reads any other name as auto.
var vmessCiphers = []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}

// outboundFromVMess takes both link forms vmesslink reads, over the
// transports buildStreamSettings maps. xray dropped the legacy MD5 handshake
// (alterId above 0), the HTTP/2 and QUIC transports and allowInsecure; such
// links fail here, with the reason, rather than in xray's builder or as
// something else.
func outboundFromVMess(link, tag string) (*xrayConf.OutboundDetourConfig, string, string, error) {
	l, err := vmesslink.Parse(link)
	if err != nil {
		return nil, "", "", err
	}
	if l.ID == "" || l.Host == "" {
		return nil, "", "", fmt.Errorf("vmess: missing uuid or server host")
	}
	if l.AlterID > 0 {
		return nil, "", "", fmt.Errorf("vmess: alterId %d (the legacy handshake) is not supported; xray speaks only AEAD, alterId 0", l.AlterID)
	}
	cipher := strings.ToLower(l.Cipher)
	if !slices.Contains(vmessCiphers, cipher) {
		return nil, "", "", fmt.Errorf("vmess: cipher %q is not supported", l.Cipher)
	}
	q := l.Params
	switch network := q.Get("type"); network {
	case "tcp":
		if header := q.Get("headerType"); header != "" && header != "none" {
			return nil, "", "", fmt.Errorf("vmess: tcp header %q is not supported", header)
		}
	case "ws", "grpc", "httpupgrade", "xhttp":
	default:
		return nil, "", "", fmt.Errorf("vmess: transport %q is not supported", network)
	}
	switch security := q.Get("security"); security {
	case "", "none", "tls":
	default:
		return nil, "", "", fmt.Errorf("vmess: security %q is not supported", security)
	}
	// xray refuses allowInsecure outright since 2026-06-01. Without TLS
	// there is no certificate, and the flag means nothing.
	if q.Get("security") == "tls" {
		for _, k := range []string{"allowInsecure", "insecure", "allow_insecure"} {
			if v := strings.ToLower(strings.TrimSpace(q.Get(k))); v == "1" || v == "true" {
				return nil, "", "", fmt.Errorf("vmess: skipping certificate verification is not supported; pin the certificate with pcs")
			}
		}
	}

	user, _ := json.Marshal(map[string]string{"id": l.ID, "security": cipher})
	addrForDial := preResolveIPv4(l.Host)
	settings, _ := json.Marshal(&xrayConf.VMessOutboundConfig{
		Receivers: []*xrayConf.VMessOutboundTarget{{
			Address: &xrayConf.Address{Address: xrayNet.ParseAddress(addrForDial)},
			Port:    uint16(l.Port),
			Users:   []json.RawMessage{user},
		}},
	})
	settingsRaw := json.RawMessage(settings)
	ob := &xrayConf.OutboundDetourConfig{
		Protocol:      "vmess",
		Tag:           tag,
		Settings:      &settingsRaw,
		StreamSetting: buildStreamSettings(l.Host, q),
	}
	if tls := ob.StreamSetting.TLSSettings; tls != nil {
		if pin := strings.TrimSpace(q.Get("pcs")); pin != "" {
			tls.PinnedPeerCertSha256 = pin
		}
		if name := strings.TrimSpace(q.Get("vcn")); name != "" {
			tls.VerifyPeerCertByName = name
		}
		// xray takes ech as a config list or as where to query one; the
		// switch form names neither.
		switch ech := strings.TrimSpace(q.Get("ech")); strings.ToLower(ech) {
		case "", "0", "false":
		case "1", "true":
			return nil, "", "", fmt.Errorf("vmess: ech must name a config list or a DNS server to query")
		default:
			tls.ECHConfigList = ech
		}
	}
	return ob, l.Host, addrForDial, nil
}
