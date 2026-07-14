//go:build !windows

package core

func configureTunV3(iface string, tunCIDR string, serverIPs []string, dnsServer string) error {
	return nil
}

func cleanupTun(iface string) {}

func physicalInterfaceIP() string { return "" }

func physicalInterfaceName() string { return "" }
