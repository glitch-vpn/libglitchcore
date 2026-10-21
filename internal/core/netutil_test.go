package core

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const rawINIConfig = `# exported from https://provider.example
[Interface]
PrivateKey = fakefakefakefakefakefakefakefakefakefakefak=
Address = 10.8.0.2/32
Jc = 4

[Peer]
PublicKey = madeupmadeupmadeupmadeupmadeupmadeupmadeu=
Endpoint = 198.51.100.7:51820
AllowedIPs = 0.0.0.0/0`

func TestSplitEngineLinks(t *testing.T) {
	got, err := splitEngineLinks("\n awg://AAAA#one \n\nvless://u@h:443\n")
	if err != nil || !slices.Equal(got, []string{"awg://AAAA#one", "vless://u@h:443"}) {
		t.Errorf("links: got %q, %v", got, err)
	}

	got, err = splitEngineLinks("\n" + rawINIConfig + "\n")
	if err != nil || !slices.Equal(got, []string{rawINIConfig}) {
		t.Errorf("lone raw config: got %q, %v; want it as one unit", got, err)
	}
}

// The caller counts servers by position, and a raw config's lines cannot be
// told from a neighbour's, so a pool holding one is refused rather than guessed.
func TestSplitEngineLinks_RawConfigInPoolRefused(t *testing.T) {
	for name, pool := range map[string]string{
		"link after":  rawINIConfig + "\nvless://u@h:443",
		"link before": "awg://AAAA#one\n" + rawINIConfig,
		"two configs": rawINIConfig + "\n\n" + rawINIConfig,
		"spaced second header": rawINIConfig + "\n\n" +
			strings.Replace(rawINIConfig, "[Interface]", "[ interface ]", 1),
		"spaced header beside a link": strings.Replace(rawINIConfig, "[Interface]", "[ INTERFACE ]", 1) +
			"\nvless://u@h:443",
	} {
		if got, err := splitEngineLinks(pool); !errors.Is(err, errRawConfigInPool) {
			t.Errorf("%s: got %q, %v; want errRawConfigInPool", name, got, err)
		}
	}
}
