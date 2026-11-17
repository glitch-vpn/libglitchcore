//go:build !windows && !no_xray && with_tun2socks

package core

func configureTunV3(iface string, serverIPs []string, dnsServer string, plan tunPlan) error {
	return nil
}

func cleanupTun(iface string) {}

func physicalInterfaceIP() string { return "" }

func physicalInterfaceName() string { return "" }
