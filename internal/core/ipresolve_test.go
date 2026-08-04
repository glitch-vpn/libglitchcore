package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func directTestDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
}

func echoServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchIPEcho_IPv4(t *testing.T) {
	srv := echoServer(t, "203.0.113.7\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ip, err := fetchIPEcho(ctx, srv.URL, directTestDial, false)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("ip = %q", ip)
	}
}

func TestFetchIPEcho_FamilyMismatch(t *testing.T) {
	srv := echoServer(t, "203.0.113.7")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := fetchIPEcho(ctx, srv.URL, directTestDial, true); err == nil {
		t.Fatal("v4 answer accepted as IPv6")
	}

	srv6 := echoServer(t, "2001:db8::1")
	ip, err := fetchIPEcho(ctx, srv6.URL, directTestDial, true)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "2001:db8::1" {
		t.Fatalf("ip = %q", ip)
	}
	if _, err := fetchIPEcho(ctx, srv6.URL, directTestDial, false); err == nil {
		t.Fatal("v6 answer accepted as IPv4")
	}
}

func TestFetchIPEcho_Garbage(t *testing.T) {
	srv := echoServer(t, "<html>definitely not an ip</html>")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := fetchIPEcho(ctx, srv.URL, directTestDial, false); err == nil {
		t.Fatal("garbage body accepted")
	}
}

func TestFetchExternalIPs_SkipV6(t *testing.T) {
	srv := echoServer(t, "203.0.113.7")
	st := fetchExternalIPs(ipResolveConfig{
		enabled: true, urlV4: srv.URL, urlV6: srv.URL, skipV6: true, dial: directTestDial,
	})
	if st.IPv4 != "203.0.113.7" || st.IPv4Error != "" {
		t.Fatalf("v4: %+v", st)
	}
	if st.IPv6 != "" || st.IPv6Error != "disabled" {
		t.Fatalf("v6 should be disabled: %+v", st)
	}
}

func collectEvents(t *testing.T, code int32) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	setStatusSink(func(c int32, msg string) {
		if c != code {
			return
		}
		mu.Lock()
		got = append(got, msg)
		mu.Unlock()
	})
	t.Cleanup(func() { setStatusSink(nil) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

func TestConfigureIPResolve_NoDialReportsUnsupported(t *testing.T) {
	ctl := &CoreController{}
	events := collectEvents(t, IPEvent)

	ctl.configureIPResolve(ipResolveConfig{enabled: true})

	msgs := events()
	if len(msgs) != 1 {
		t.Fatalf("events = %v", msgs)
	}
	var st externalIPState
	if err := json.Unmarshal([]byte(msgs[0]), &st); err != nil {
		t.Fatal(err)
	}
	if st.IPv4Error != "unsupported" || st.IPv6Error != "unsupported" {
		t.Fatalf("state = %+v", st)
	}
}

func TestTriggerIPResolve_EmitsAndDedupes(t *testing.T) {
	ctl := &CoreController{}
	events := collectEvents(t, IPEvent)

	srv4 := echoServer(t, "203.0.113.7")
	ctl.configureIPResolve(ipResolveConfig{
		enabled: true, urlV4: srv4.URL, skipV6: true, dial: directTestDial,
	})
	ctl.triggerIPResolve("test")

	deadline := time.Now().Add(10 * time.Second)
	for len(events()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	msgs := events()
	if len(msgs) != 1 {
		t.Fatalf("events = %v", msgs)
	}
	if !strings.Contains(msgs[0], `"ipv4":"203.0.113.7"`) || !strings.Contains(msgs[0], `"ipv6Error":"disabled"`) {
		t.Fatalf("payload = %s", msgs[0])
	}

	ctl.triggerIPResolve("again")
	time.Sleep(300 * time.Millisecond)
	if got := events(); len(got) != 1 {
		t.Fatalf("dedupe failed: %v", got)
	}

	ctl.stopIPResolve()
	ctl.triggerIPResolve("after-stop")
	time.Sleep(300 * time.Millisecond)
	if got := events(); len(got) != 1 {
		t.Fatalf("emitted after stop: %v", got)
	}
}

func TestTriggerIPResolve_DisabledDoesNothing(t *testing.T) {
	ctl := &CoreController{}
	events := collectEvents(t, IPEvent)
	ctl.configureIPResolve(ipResolveConfig{enabled: false, dial: directTestDial})
	ctl.triggerIPResolve("test")
	time.Sleep(200 * time.Millisecond)
	if got := events(); len(got) != 0 {
		t.Fatalf("disabled resolver emitted: %v", got)
	}
}
