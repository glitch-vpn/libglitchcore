package xrayconfig

import (
	"encoding/json"

	xrayNet "github.com/xtls/xray-core/common/net"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/proxylink"
)

func outboundFromProxy(link, tag string) (*xrayConf.OutboundDetourConfig, string, string, error) {
	l, err := proxylink.Parse(link)
	if err != nil {
		return nil, "", "", err
	}
	address := &xrayConf.Address{Address: xrayNet.ParseAddress(l.Host)}
	var protocol string
	var settings any
	switch l.Protocol {
	case proxylink.Socks:
		protocol = "socks"
		settings = &xrayConf.SocksClientConfig{Address: address, Port: uint16(l.Port), Username: l.Username, Password: l.Password}
	case proxylink.HTTP:
		protocol = "http"
		settings = &xrayConf.HTTPClientConfig{Address: address, Port: uint16(l.Port), Username: l.Username, Password: l.Password}
	}
	settingsBytes, _ := json.Marshal(settings)
	settingsRaw := json.RawMessage(settingsBytes)

	stream := &xrayConf.StreamConfig{SocketSettings: &xrayConf.SocketConfig{TCPKeepAliveInterval: 15}}
	if l.TLS {
		// Without an sni xray verifies the server's own name.
		stream.Security = "tls"
		stream.TLSSettings = &xrayConf.TLSConfig{ServerName: l.SNI, PinnedPeerCertSha256: l.Pin}
	}
	ob := &xrayConf.OutboundDetourConfig{
		Protocol:      protocol,
		Tag:           tag,
		Settings:      &settingsRaw,
		StreamSetting: stream,
	}
	return ob, l.Host, preResolveIPv4(l.Host), nil
}
