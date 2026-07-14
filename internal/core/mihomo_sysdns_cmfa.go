//go:build android && cmfa && !no_mihomo

package core

import mihomoDNS "github.com/metacubex/mihomo/dns"

// Under cmfa, mihomo's system resolver is empty unless UpdateSystemDNS is fed.
func seedMihomoSystemDNS(servers []string) {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "8.8.8.8"}
	}
	mihomoDNS.UpdateSystemDNS(servers)
}
