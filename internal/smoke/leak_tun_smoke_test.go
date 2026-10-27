//go:build integration && linux

package smoke

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	xrayCore "github.com/xtls/xray-core/core"
)

const (
	tunNamespaceEnv = "GLITCH_SMOKE_TUN_NAMESPACE"
	tunUpstreamEnv  = "GLITCH_SMOKE_TUN_UPSTREAM"
	tunDevice       = "glt0"
	tunAppAddr      = "10.77.0.1"
	tunRemoteAddr   = "10.77.0.2"
)

func openTunDevice(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var req [unix.IFNAMSIZ + 64]byte
	copy(req[:unix.IFNAMSIZ], name)
	*(*uint16)(unsafe.Pointer(&req[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		_ = unix.Close(fd)
		return nil, errno
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

func ipCommand(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// The echo server and the VLESS server in front of it: whatever a flow asks
// for, the server answers from the echo.
func TestSmoke_TunUpstreamHelper(t *testing.T) {
	if os.Getenv(tunUpstreamEnv) == "" {
		t.Skip("runs as the upstream of TestSmoke_TunSessionsLeaveNothingBehind")
	}
	ipCommand(t, "link", "set", "lo", "up")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echoPort := l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()

	port := freePort(t)
	cfg := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
			"settings": {"clients": [{"id": %q}], "decryption": "none"}}],
		"outbounds": [{"protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d", "finalRules": [{"action": "allow"}]}}]
	}`, port, testUUID, echoPort)
	inst, err := xrayCore.StartInstance("json", []byte(cfg))
	if err != nil {
		t.Fatalf("vless server: %v", err)
	}
	defer inst.Close()
	fmt.Println("upstream", port)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// startUpstreamProcess runs the servers in a process of their own, so the
// session under test is the only thing whose goroutines and sockets are
// counted.
func startUpstreamProcess(t *testing.T) int {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestSmoke_TunUpstreamHelper$")
	cmd.Env = append(os.Environ(), tunUpstreamEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		if rest, ok := strings.CutPrefix(lines.Text(), "upstream "); ok {
			port, err := strconv.Atoi(rest)
			if err != nil {
				t.Fatal(err)
			}
			return port
		}
	}
	t.Fatal("the upstream process did not come up")
	return 0
}

// Apps keep their connections open until the VPN is gone, which is what a
// session's stop meets. The TUN device lives in a network namespace of its
// own, so no privilege is needed beyond what unshare grants.
func TestSmoke_TunSessionsLeaveNothingBehind(t *testing.T) {
	if os.Getenv(tunNamespaceEnv) == "" {
		if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
			t.Skipf("no user and network namespaces: %v", err)
		}
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "-Urn", self, "-test.run=^TestSmoke_TunSessionsLeaveNothingBehind$", "-test.v", "-test.timeout=5m")
		cmd.Env = append(os.Environ(), tunNamespaceEnv+"=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatalf("in a network namespace: %v", err)
		}
		return
	}

	core.Initialize()
	ipCommand(t, "link", "set", "lo", "up")
	upstream := startUpstreamProcess(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#TunLeak", testUUID, upstream)

	const cycles = 10
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			ev := captureEvents(t)
			session := func() {
				tun, err := openTunDevice(tunDevice)
				if err != nil {
					t.Fatalf("tun: %v", err)
				}
				ipCommand(t, "addr", "add", tunAppAddr+"/16", "dev", tunDevice)
				ipCommand(t, "link", "set", tunDevice, "up")
				if res := core.EngineStart(engine, core.EngineStartRequest{
					Config: link, TunFD: int(tun.Fd()), DNS: "1.1.1.1", LogLevel: 3,
					Opts: map[string]string{"resolveExternalIp": "0", "disableIPv6": "1", "geoAssetsDir": smokeAssetDir},
				}); res != core.ResultSuccess {
					t.Fatalf("EngineStart = %d", res)
				}
				ev.waitFor(t, core.EngineConnected, 30*time.Second)

				var apps []net.Conn
				for _, network := range []string{"tcp", "tcp", "tcp", "udp", "udp"} {
					conn, err := net.DialTimeout(network, net.JoinHostPort(tunRemoteAddr, "5000"), 5*time.Second)
					if err != nil {
						t.Fatalf("%s through the tunnel: %v", network, err)
					}
					apps = append(apps, conn)
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = conn.Write([]byte("ping"))
					if _, err := conn.Read(make([]byte, 4)); err != nil {
						t.Fatalf("%s echo through the tunnel: %v", network, err)
					}
				}
				stopEngine(t, engine)
				_ = tun.Close()
				for _, conn := range apps {
					_ = conn.Close()
				}
				ev.reset()
			}
			session() // one-time pools and listeners
			baseGoroutines, baseSockets := settledResources()
			for range cycles {
				session()
			}
			goroutines, sockets := settledResources()
			t.Logf("%s: goroutines %d -> %d, sockets %d -> %d over %d sessions",
				engine, baseGoroutines, goroutines, baseSockets, sockets, cycles)
			assertNothingLeft(t, cycles, goroutines-baseGoroutines, sockets-baseSockets)
		})
	}
}
