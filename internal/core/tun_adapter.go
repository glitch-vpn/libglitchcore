package core

// desktopAdapterName names the TUN the core creates on a desktop, for every
// engine and both TUN layers. The adapter's GUID derives from the name, so
// one name is the one network identity Windows keeps for the VPN. Linux
// limits an interface name to 15 characters.
const desktopAdapterName = "GlitchVPN"

// desktopTunnelType is the adapter's description on Windows, "<type> Tunnel",
// and the label of the firewall filters sing-tun installs for it.
const desktopTunnelType = "Glitch VPN"
