//go:build with_tun2socks

package xrayconfig

// AppTrafficTag is the inbound app traffic arrives as: the TUN path dials in
// process under it, and the routing rules key on it. The TUN layer here is
// the tun2socks bridge.
const AppTrafficTag = "tun2socks"
