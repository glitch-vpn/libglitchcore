package core

// localNetworkBypass is what stays off the TUN when the profile keeps local
// networks direct. Narrower than routing.LocalNetworkCIDRs on purpose: the
// carrier-grade NAT range (100.64/10) reaches overlay networks and ISP
// equipment, not the user's LAN, and loopback and link-local never leave the
// host.
var localNetworkBypass = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
