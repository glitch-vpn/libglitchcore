//go:build !no_xray

package core

import "testing"

type fakeCounter struct{ v int64 }

func (c *fakeCounter) Value() int64      { return c.v }
func (c *fakeCounter) Set(v int64) int64 { old := c.v; c.v = v; return old }
func (c *fakeCounter) Add(v int64) int64 { c.v += v; return c.v }

type fakeStats struct{ counters map[string]*fakeCounter }

func (f *fakeStats) add(tag string, bytes int64) {
	f.counters["outbound>>>"+tag+">>>traffic>>>downlink"].Add(bytes)
}

func newFakeStats(tags []string) *fakeStats {
	f := &fakeStats{counters: map[string]*fakeCounter{}}
	for _, t := range tags {
		f.counters["outbound>>>"+t+">>>traffic>>>uplink"] = &fakeCounter{}
		f.counters["outbound>>>"+t+">>>traffic>>>downlink"] = &fakeCounter{}
	}
	return f
}

func (f *fakeStats) GetCounter(name string) statsCounter {
	if c, ok := f.counters[name]; ok {
		return c
	}
	return nil
}

func TestTagTrafficPicker(t *testing.T) {
	tags := []string{"proxy-0", "proxy-1", "proxy-2"}
	stats := newFakeStats(tags)
	pick := tagTrafficPickerFrom(stats, tags)

	if got := pick(); got != -1 {
		t.Fatalf("first poll = %d, want -1 (seeding)", got)
	}

	// Observatory probes touch every tag evenly - no verdict.
	for _, tag := range tags {
		stats.add(tag, 6*1024)
	}
	if got := pick(); got != -1 {
		t.Fatalf("probe-only poll = %d, want -1", got)
	}

	// Real traffic on proxy-1 while probes continue elsewhere.
	for _, tag := range tags {
		stats.add(tag, 6*1024)
	}
	stats.add("proxy-1", 512*1024)
	if got := pick(); got != 1 {
		t.Fatalf("traffic poll = %d, want 1", got)
	}

	// Idle again: the caller keeps the last pick.
	if got := pick(); got != -1 {
		t.Fatalf("idle poll = %d, want -1", got)
	}

	// A balancer switch shows up as traffic moving to another tag.
	stats.add("proxy-2", 1024*1024)
	if got := pick(); got != 2 {
		t.Fatalf("switch poll = %d, want 2", got)
	}
}

func TestTagTrafficPicker_NoManager(t *testing.T) {
	pick := tagTrafficPickerFrom(nil, []string{"proxy-0", "proxy-1"})
	if got := pick(); got != -1 {
		t.Fatalf("seed = %d", got)
	}
	if got := pick(); got != -1 {
		t.Fatalf("nil manager = %d, want -1", got)
	}
}
