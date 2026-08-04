package core

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
)

func testSelection(selectedIdx int) *serverinfo.Selection {
	servers := serverinfo.FromLinks([]string{
		"vless://u@a.example.com:443#A",
		"vless://u@b.example.com:443#B",
	})
	sel := &serverinfo.Selection{Engine: "xray", Strategy: "leastping", Total: 2, Servers: servers}
	if selectedIdx >= 0 {
		s := servers[selectedIdx]
		sel.Selected = &s
	}
	return sel
}

func TestSetServerSelection_EmitsAndDedupes(t *testing.T) {
	ctl := &CoreController{}
	events := collectEvents(t, ServerEvent)

	ctl.setServerSelection(testSelection(0))
	ctl.setServerSelection(testSelection(0))
	if got := events(); len(got) != 1 {
		t.Fatalf("events = %v", got)
	}

	ctl.setServerSelection(testSelection(1))
	got := events()
	if len(got) != 2 {
		t.Fatalf("events = %v", got)
	}
	if !strings.Contains(got[1], `"host":"b.example.com"`) {
		t.Fatalf("second payload = %s", got[1])
	}
}

func TestReemitSessionState(t *testing.T) {
	ctl := &CoreController{}
	serverEvents := collectEvents(t, ServerEvent)

	ctl.setServerSelection(testSelection(0))
	ctl.reemitSessionState()
	if got := serverEvents(); len(got) != 2 || got[0] != got[1] {
		t.Fatalf("reemit: %v", got)
	}

	ctl.clearSessionState()
	ctl.reemitSessionState()
	if got := serverEvents(); len(got) != 2 {
		t.Fatalf("cleared state re-emitted: %v", got)
	}
}

func TestSelectionWatch_EmitsOnChange(t *testing.T) {
	prev := selectionWatchInterval
	selectionWatchInterval = 10 * time.Millisecond
	t.Cleanup(func() { selectionWatchInterval = prev })

	ctl := &CoreController{}
	events := collectEvents(t, ServerEvent)

	base := testSelection(-1)
	var pick atomic.Int32
	pick.Store(-1)
	ctl.startSelectionWatch(*base, func() int { return int(pick.Load()) })
	t.Cleanup(ctl.stopSelectionWatch)

	time.Sleep(100 * time.Millisecond)
	if got := events(); len(got) != 0 {
		t.Fatalf("unknown pick emitted: %v", got)
	}

	pick.Store(1)
	deadline := time.Now().Add(5 * time.Second)
	for len(events()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := events()
	if len(got) != 1 || !strings.Contains(got[0], `"selected":{"index":1`) {
		t.Fatalf("events = %v", got)
	}

	pick.Store(7)
	time.Sleep(100 * time.Millisecond)
	if got := events(); len(got) != 1 {
		t.Fatalf("out-of-range pick emitted: %v", got)
	}

	ctl.stopSelectionWatch()
	pick.Store(0)
	time.Sleep(100 * time.Millisecond)
	if got := events(); len(got) != 1 {
		t.Fatalf("watch emitted after stop: %v", got)
	}
}
