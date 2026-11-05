package mihomoconfig

import "testing"

func TestAmneziaJunkCount_CappedAtDocumentedMaximum(t *testing.T) {
	for _, extra := range []string{"", "RekeyTimeout = 5\n"} {
		if _, err := ProxyMapFromLink(awgINIWith(extra + "Jc = 128\n")); err != nil {
			t.Errorf("Jc = 128: %v", err)
		}
		for _, bad := range []string{"129", "100000", "-1"} {
			if _, err := ProxyMapFromLink(awgINIWith(extra + "Jc = " + bad + "\n")); err == nil {
				t.Errorf("Jc = %s: want an error", bad)
			}
		}
	}
	link := "wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&jc=100000"
	if _, err := ProxyMapFromLink(link); err == nil {
		t.Error("link jc=100000: want an error")
	}
}

func TestAmneziaJunkSize_BoundedAndOrdered(t *testing.T) {
	for _, extra := range []string{"", "RekeyTimeout = 5\n"} {
		for _, ok := range []string{"Jmin = 0\nJmax = 0\n", "Jmin = 40\nJmax = 70\n", "Jmin = 1280\nJmax = 1280\n", "Jmax = 1280\n"} {
			if _, err := ProxyMapFromLink(awgINIWith(extra + ok)); err != nil {
				t.Errorf("%q: %v", ok, err)
			}
		}
		for _, bad := range []string{"Jmax = 1281\n", "Jmin = 100000\nJmax = 100000\n", "Jmin = -1\nJmax = 10\n", "Jmax = -1\n", "Jmin = 70\nJmax = 40\n"} {
			if _, err := ProxyMapFromLink(awgINIWith(extra + bad)); err == nil {
				t.Errorf("%q: want an error", bad)
			}
		}
	}
	link := "wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&jmin=10&jmax=100000"
	if _, err := ProxyMapFromLink(link); err == nil {
		t.Error("link jmax=100000: want an error")
	}
}

// The legacy device reads Itime as seconds into a time.Duration, which a
// large value overflows.
func TestAmneziaItime_BoundedToADay(t *testing.T) {
	for _, ok := range []string{"0", "12", "86400"} {
		if _, err := ProxyMapFromLink(awgINIWith("Itime = " + ok + "\n")); err != nil {
			t.Errorf("Itime = %s: %v", ok, err)
		}
	}
	for _, bad := range []string{"86401", "-1", "9223372036854775807", "9223372037"} {
		if _, err := ProxyMapFromLink(awgINIWith("Itime = " + bad + "\n")); err == nil {
			t.Errorf("Itime = %s: want an error", bad)
		}
	}
	link := "wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&itime=9223372037"
	if _, err := ProxyMapFromLink(link); err == nil {
		t.Error("link itime=9223372037: want an error")
	}
}
