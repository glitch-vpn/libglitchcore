package xrayconfig

import (
	"strings"

	xrayConf "github.com/xtls/xray-core/infra/conf"
)

// uTLS fingerprints xray accepts; unknown values are dropped (won't fail config load).
var XrayFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge",
	"360", "qq", "random", "randomized", "randomizednoalpn", "unsafe",
}

func ValidXrayFingerprint(fp string) bool {
	for _, f := range XrayFingerprints {
		if f == fp {
			return true
		}
	}
	return false
}

func proxyTagSet(tags []string) map[string]bool {
	set := make(map[string]bool, len(tags))
	for _, t := range tags {
		set[t] = true
	}
	return set
}

// ApplyMux configures Mux on the proxy outbounds. concurrency is the master
// switch: 0 leaves mux off entirely (the default), <0 keeps the outbound
// mux-capable but disables TCP mux, >0 enables TCP mux at that concurrency.
// xudpConcurrency then tunes XUDP (<0 off, 0 leaves it off, >0 enables it).
//
// XTLS Vision and TCP mux are mutually exclusive - the server tears down mux
// connections that carry TCP requests - so for any Vision-flow outbound TCP
// mux is force-disabled (Concurrency=-1) even when the caller asked for it,
// while XUDP is kept.
func ApplyMux(cfg *xrayConf.Config, proxyTags []string, visionTags map[string]bool, concurrency, xudpConcurrency int) {
	if concurrency == 0 {
		return
	}
	tagSet := proxyTagSet(proxyTags)
	for i := range cfg.OutboundConfigs {
		ob := &cfg.OutboundConfigs[i]
		if !tagSet[ob.Tag] {
			continue
		}
		c := concurrency
		if visionTags[ob.Tag] && c > 0 {
			c = -1 // Vision carries TCP; mux over it is server-broken.
		}
		ob.MuxSettings = &xrayConf.MuxConfig{
			Enabled:         true,
			Concurrency:     int16(c),
			XudpConcurrency: int16(xudpConcurrency),
		}
	}
}

func ApplyFingerprint(cfg *xrayConf.Config, proxyTags []string, fp string) {
	fp = strings.TrimSpace(fp)
	if fp == "" || !ValidXrayFingerprint(fp) {
		return
	}
	tagSet := proxyTagSet(proxyTags)
	for i := range cfg.OutboundConfigs {
		ob := &cfg.OutboundConfigs[i]
		if !tagSet[ob.Tag] || ob.StreamSetting == nil {
			continue
		}
		if ob.StreamSetting.TLSSettings != nil {
			ob.StreamSetting.TLSSettings.Fingerprint = fp
		}
		if ob.StreamSetting.REALITYSettings != nil {
			ob.StreamSetting.REALITYSettings.Fingerprint = fp
		}
	}
}
