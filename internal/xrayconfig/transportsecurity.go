package xrayconfig

import (
	"fmt"
	"slices"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	xrayNet "github.com/xtls/xray-core/common/net"
)

// ssCiphers are the methods xray's Shadowsocks outbound builds, the AEAD and
// the 2022 ones; it reports any other as an unknown cipher.
var ssCiphers = []string{
	"aes-128-gcm", "aead_aes_128_gcm",
	"aes-256-gcm", "aead_aes_256_gcm",
	"chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305",
	"xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

func checkSSCipher(method string) error {
	if !slices.Contains(ssCiphers, strings.ToLower(method)) {
		return fmt.Errorf("shadowsocks: method %q is not supported; xray carries AEAD and 2022 methods only", method)
	}
	return nil
}

// requireTransportSecurity mirrors xray's refusal of a VLESS or Trojan
// outbound with neither TLS, REALITY nor VLESS encryption to a server that is
// not on a private address. address is the one handed to xray, the
// pre-resolved IPv4 when the lookup succeeds, because that is what xray
// judges. A link with none of them is refused here with its reason instead
// of failing the engine start. xray's own private-address lists decide.
func requireTransportSecurity(protocol, address string, secured bool) error {
	if secured || !isPublicHost(address) {
		return nil
	}
	if protocol == "vless" {
		return fmt.Errorf("vless: no TLS, REALITY or VLESS encryption to a public server; xray refuses to carry it in the clear")
	}
	return fmt.Errorf("%s: no TLS or REALITY to a public server; xray refuses to carry it in the clear", protocol)
}

func isPublicHost(host string) bool {
	if parsed := xrayNet.ParseAddress(host); parsed.Family().IsIP() {
		return !geodata.GetPrivateIPMatcher().Match(parsed.IP())
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	return !geodata.GetPrivateDomainMatcher().MatchAny(name)
}
