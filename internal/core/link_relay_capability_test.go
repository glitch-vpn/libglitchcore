package core

import (
	"encoding/json"
	"slices"
	"testing"
)

// A plugin that checks the feature before opening a relay is never refused by
// a core that lacks the exports.
func TestCoreCapabilities_NamesLinkRelay(t *testing.T) {
	var caps struct {
		Features []string `json:"features"`
	}
	if err := json.Unmarshal([]byte(coreCapabilities()), &caps); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(caps.Features, "linkRelay") {
		t.Errorf("features %v lack linkRelay", caps.Features)
	}
}
