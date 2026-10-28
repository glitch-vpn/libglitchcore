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

// The ciphers xray's VMess account knows. xray reads any other cipher, none
// and zero included, as auto; the core refuses those names so a link never
// runs encrypted where it asked for no encryption.
var vmessCiphers = []string{"auto", "aes-128-gcm", "chacha20-poly1305"}

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
	var gap error
	if l.AlterID > 0 {
		gap = NotCarriedError{fmt.Errorf("vmess: alterId %d (the legacy handshake) is not supported; xray speaks only AEAD, alterId 0", l.AlterID)}
	}
	cipher := strings.ToLower(l.Cipher)
	if !slices.Contains(vmessCiphers, cipher) {
		return nil, "", "", fmt.Errorf("vmess: cipher %q is not supported", l.Cipher)
	}
	q := l.Params
	if strings.ToLower(strings.TrimSpace(q.Get("security"))) == "reality" {
		return nil, "", "", fmt.Errorf("vmess: security \"reality\" is not supported")
	}
	stream, streamGap, err := buildStreamSettings(l.Host, q)
	if err != nil {
		return nil, "", "", fmt.Errorf("vmess: %w", err)
	}
	if gap == nil {
		gap = streamGap
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
		StreamSetting: stream,
	}
	if tls := stream.TLSSettings; tls != nil {
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
	if gap != nil {
		return nil, "", "", gap
	}
	return ob, l.Host, addrForDial, nil
}
