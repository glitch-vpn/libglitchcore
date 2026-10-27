//go:build !no_awg

package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

func awgTestLink(t *testing.T, address, allowedIPs, name string) string {
	t.Helper()
	ini := "[Interface]\nPrivateKey = AAAA\nAddress = " + address + "\n\n" +
		"[Peer]\nPublicKey = BBBB\nEndpoint = 192.0.2.1:51820\nAllowedIPs = " + allowedIPs + "\n"
	return awgconfig.EncodeLink(ini, name)
}

func stubAwgProbe(t *testing.T, alive func(i int) bool) {
	t.Helper()
	prev := measureAwgLinks
	measureAwgLinks = func(req pinger.Request) []pinger.Result {
		out := make([]pinger.Result, len(req.Links))
		for i := range out {
			out[i] = pinger.Result{Index: i, Engine: "awg", Alive: alive(i), DelayMs: int64(100 - i*10)}
		}
		return out
	}
	t.Cleanup(func() { measureAwgLinks = prev })
}

func TestPickAwg_PoolReturnsTheWinnersOwnAddresses(t *testing.T) {
	links := []string{
		awgTestLink(t, "10.1.0.2/32", "0.0.0.0/0", "a"),
		awgTestLink(t, "10.2.0.2/32, fd00:2::2/128", "0.0.0.0/0, ::/0", "b"),
	}
	stubAwgProbe(t, func(int) bool { return true })

	got, err := PickAwg(EngineStartRequest{Config: strings.Join(links, "\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got.Index != 1 {
		t.Fatalf("picked #%d, want the faster #1", got.Index)
	}
	if strings.Join(got.Addresses, " ") != "10.2.0.2/32 fd00:2::2/128" || !got.PeersCarryIPv6 {
		t.Fatalf("addresses %v, peersCarryV6 %v", got.Addresses, got.PeersCarryIPv6)
	}
}

func TestPickAwg_SingleLinkIsNotProbed(t *testing.T) {
	link := awgTestLink(t, "10.9.0.2/32", "0.0.0.0/0", "")
	prev := measureAwgLinks
	measureAwgLinks = func(pinger.Request) []pinger.Result {
		t.Fatal("a single link must not be probed")
		return nil
	}
	t.Cleanup(func() { measureAwgLinks = prev })

	got, err := PickAwg(EngineStartRequest{Config: link})
	if err != nil {
		t.Fatal(err)
	}
	if got.Index != 0 || len(got.Addresses) != 1 || got.PeersCarryIPv6 {
		t.Fatalf("got %+v", got)
	}
}

func TestPickAwg_RawINIIsASingleLink(t *testing.T) {
	ini := "[Interface]\nPrivateKey = AAAA\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = BBBB\nAllowedIPs = 0.0.0.0/0\n"
	got, err := PickAwg(EngineStartRequest{Config: ini})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 1 || got.Addresses[0] != "10.7.0.2/32" {
		t.Fatalf("addresses %v", got.Addresses)
	}
}

// Every probe failing keeps the start's behaviour: the first link, and its
// own addresses, never a made-up one.
func TestPickAwg_EveryProbeFailingYieldsTheFirstLink(t *testing.T) {
	links := []string{
		awgTestLink(t, "10.1.0.2/32", "0.0.0.0/0", "a"),
		awgTestLink(t, "10.2.0.2/32", "0.0.0.0/0", "b"),
	}
	stubAwgProbe(t, func(int) bool { return false })

	got, err := PickAwg(EngineStartRequest{Config: strings.Join(links, "\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got.Index != 0 || got.Addresses[0] != "10.1.0.2/32" {
		t.Fatalf("got %+v", got)
	}
}

func TestPickAwg_RefusesWhatHasNoTunnelAddress(t *testing.T) {
	noAddress := awgconfig.EncodeLink("[Interface]\nPrivateKey = AAAA\n[Peer]\nPublicKey = BBBB\n", "")
	for name, config := range map[string]string{
		"empty":         "",
		"no address":    noAddress,
		"bad payload":   "awg://%%",
		"raw in a pool": "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBB\n\nawg://AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := PickAwg(EngineStartRequest{Config: config}); err == nil {
				t.Fatalf("got %+v, want an error", got)
			}
		})
	}
}

func TestPickAwg_AnUnusableAddressIsDroppedOrRefused(t *testing.T) {
	_, err := PickAwg(EngineStartRequest{Config: awgTestLink(t, "127.0.0.2/32, 10.8.0.2/33, ::1/128", "0.0.0.0/0", "")})
	if err == nil {
		t.Fatal("a link left with no usable address was picked")
	}
	got, err := PickAwg(EngineStartRequest{Config: awgTestLink(t, "127.0.0.2/32, 10.8.0.2/32", "0.0.0.0/0", "")})
	if err != nil || len(got.Addresses) != 1 || got.Addresses[0] != "10.8.0.2/32" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestChooseAwgLink_FollowsAPreparedPickWithoutProbing(t *testing.T) {
	prev := measureAwgLinks
	measureAwgLinks = func(pinger.Request) []pinger.Result {
		t.Fatal("a prepared pick must not probe again")
		return nil
	}
	t.Cleanup(func() { measureAwgLinks = prev })
	links := []string{"awg://a", "awg://b", "awg://c"}

	link, idx, err := chooseAwgLink(links, engineOpts{awgPicked: "2"})
	if err != nil || link != "awg://c" || idx != 2 {
		t.Fatalf("got %q %d %v", link, idx, err)
	}
	for _, bad := range []string{"3", "-1", "x"} {
		if _, _, err := chooseAwgLink(links, engineOpts{awgPicked: bad}); err == nil {
			t.Errorf("awgPicked %q accepted", bad)
		}
	}
}

func TestPickAwgJSON_AnswersIndexAddressesAndNoLink(t *testing.T) {
	link := awgTestLink(t, "10.9.0.2/32, fd00:9::2/128", "0.0.0.0/0, ::/0", "")
	request, err := json.Marshal(EngineStartRequest{Config: link})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(PickAwgJSON(string(request))), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["index"] != float64(0) || got["peersCarryV6"] != true {
		t.Fatalf("answer %v, want exactly index, addresses, peersCarryV6", got)
	}
	if addresses, _ := got["addresses"].([]any); len(addresses) != 2 || addresses[0] != "10.9.0.2/32" {
		t.Fatalf("addresses %v", got["addresses"])
	}
}

func TestPickAwgJSON_AnErrorIsOneErrorKey(t *testing.T) {
	for name, request := range map[string]string{
		"not json":   "{",
		"no link":    `{"config":""}`,
		"bad opts":   `{"config":"awg://AAAA","opts":{"routingTiers":"x"}}`,
		"no address": `{"config":"` + awgconfig.EncodeLink("[Interface]\nPrivateKey = AAAA\n", "") + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var got map[string]string
			if err := json.Unmarshal([]byte(PickAwgJSON(request)), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got["error"] == "" {
				t.Fatalf("answer %v, want only a non-empty error", got)
			}
		})
	}
}

func TestHandleAwgStart_InvalidAwgPickedIsAnErrorEvent(t *testing.T) {
	for _, picked := range []string{"2", "-1", "first"} {
		t.Run(picked, func(t *testing.T) {
			errors := make(chan string, 8)
			setStatusSink(func(code int32, message string) {
				if code == EngineError {
					errors <- message
				}
			})
			defer setStatusSink(nil)

			ctl := &CoreController{nextHandle: 1}
			got := ctl.HandleAwgStart(EngineStartRequest{
				Config: awgTestLink(t, "10.1.0.2/32", "0.0.0.0/0", "a") + "\n" + awgTestLink(t, "10.2.0.2/32", "0.0.0.0/0", "b"),
				Opts:   map[string]string{"awgPicked": picked},
			})
			if got != glitchCoreResultSuccess {
				t.Fatalf("result = %d, want the start accepted and failed asynchronously", got)
			}
			select {
			case message := <-errors:
				if !strings.Contains(message, "awgPicked") {
					t.Fatalf("EngineError = %q, want it to name awgPicked", message)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no EngineError for an invalid awgPicked")
			}
			if ctl.awgSession.running.Load() {
				t.Fatal("awg marked running after an invalid awgPicked")
			}
		})
	}
}
