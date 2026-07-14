package conninspect

import (
	"encoding/json"
	"testing"
)

func TestRecordJSON(t *testing.T) {
	r := Record{
		Engine: "mihomo", Src: "127.0.0.1:5000", Status: "accepted",
		Network: "tcp", Host: "youtube.com", Port: "443",
		Outbound: "vpn > proxy-2", Rule: "GeoSite youtube",
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(r.JSON()), &got); err != nil {
		t.Fatalf("JSON not parseable: %v", err)
	}
	for k, want := range map[string]string{
		"engine": "mihomo", "host": "youtube.com", "outbound": "vpn > proxy-2",
		"rule": "GeoSite youtube", "network": "tcp", "status": "accepted",
	} {
		if got[k] != want {
			t.Errorf("field %q = %v, want %q", k, got[k], want)
		}
	}
	if _, ok := got["ts"]; !ok {
		t.Error("ts missing")
	}
	// omitempty: an all-zero record must not carry empty engine/rule keys.
	var min map[string]any
	_ = json.Unmarshal([]byte(Record{Host: "x"}.JSON()), &min)
	if _, ok := min["rule"]; ok {
		t.Error("empty rule should be omitted")
	}
}
