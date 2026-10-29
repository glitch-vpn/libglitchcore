//go:build integration

package smoke

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// The pick a caller makes before it builds the TUN lands on the pool's one
// reachable link and answers with that link's own addresses, and the answer
// carries nothing else, the link and its private key included.
func TestSmoke_AwgPickChoosesTheReachableLinkOfAPool(t *testing.T) {
	core.Initialize()
	live := startAwg3Server(t, "198.51.100.66")
	echoURL := "http://" + awgServerAddr + "/"

	deadPrivate, deadPublic := newAwgKey(t)
	dead := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.99.0.2/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n",
		deadPrivate.base64(), deadPublic.base64())
	pool := strings.Join([]string{
		awgconfig.EncodeLink(dead, "dead"),
		awgconfig.EncodeLink(live, "live"),
	}, "\n")

	request, err := json.Marshal(core.EngineStartRequest{
		Config: pool,
		Opts:   map[string]string{"probeUrl": echoURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	answer := core.PickAwgJSON(string(request))
	if strings.Contains(answer, deadPrivate.base64()) || strings.Contains(answer, "awg://") {
		t.Fatalf("the answer carries a link or a key: %s", answer)
	}
	var got struct {
		Index          int      `json:"index"`
		Addresses      []string `json:"addresses"`
		PeersCarryIPv6 bool     `json:"peersCarryV6"`
	}
	if err := json.Unmarshal([]byte(answer), &got); err != nil {
		t.Fatalf("answer %q: %v", answer, err)
	}
	if got.Index != 1 || len(got.Addresses) != 1 || got.Addresses[0] != "10.66.0.2/32" || got.PeersCarryIPv6 {
		t.Fatalf("pick = %+v, want the live link #1 with 10.66.0.2/32", got)
	}
}

// The pick before an awg start reads a wireguard:// link's bare address as a
// host prefix. A pool of one is not probed.
func TestSmoke_AwgPickReadsAWireGuardLink(t *testing.T) {
	core.Initialize()
	clientPrivate, _ := newAwgKey(t)
	_, serverPublic := newAwgKey(t)
	link := "wireguard://" + url.QueryEscape(clientPrivate.base64()) + "@127.0.0.1:9" +
		"?publickey=" + url.QueryEscape(serverPublic.base64()) + "&address=10.66.0.2#WG"

	request, err := json.Marshal(core.EngineStartRequest{Config: link})
	if err != nil {
		t.Fatal(err)
	}
	answer := core.PickAwgJSON(string(request))
	if strings.Contains(answer, clientPrivate.base64()) || strings.Contains(answer, "wireguard://") {
		t.Fatalf("the answer carries a link or a key: %s", answer)
	}
	var got struct {
		Index     int      `json:"index"`
		Addresses []string `json:"addresses"`
	}
	if err := json.Unmarshal([]byte(answer), &got); err != nil {
		t.Fatalf("answer %q: %v", answer, err)
	}
	if got.Index != 0 || len(got.Addresses) != 1 || got.Addresses[0] != "10.66.0.2/32" {
		t.Fatalf("pick = %+v, want 10.66.0.2/32", got)
	}
}
