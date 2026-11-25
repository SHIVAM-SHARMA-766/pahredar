package scan

import (
	"net"
	"testing"
)

func TestIPTypeAndVersion(t *testing.T) {
	cases := []struct {
		ip   string
		ver  int
		kind string
	}{
		{"8.8.8.8", 4, "public"},
		{"192.168.1.1", 4, "private"},
		{"127.0.0.1", 4, "loopback"},
		{"10.0.0.5", 4, "private"},
		{"2001:4860:4860::8888", 6, "public"},
		{"::1", 6, "loopback"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %s", c.ip)
		}
		if got := ipVersion(ip); got != c.ver {
			t.Errorf("%s version = %d, want %d", c.ip, got, c.ver)
		}
		if got := ipType(ip); got != c.kind {
			t.Errorf("%s type = %q, want %q", c.ip, got, c.kind)
		}
	}
}

func TestScoreIP(t *testing.T) {
	clean := &IPReport{Blocklist: &BlocklistScan{}, Geo: &GeoInfo{Country: "US"}}
	scoreIP(clean)
	if clean.Verdict != "clean" || clean.Score != 0 {
		t.Errorf("clean IP: score=%d verdict=%q", clean.Score, clean.Verdict)
	}

	proxy := &IPReport{Blocklist: &BlocklistScan{}, Geo: &GeoInfo{Proxy: true}}
	scoreIP(proxy)
	if proxy.Verdict != "suspicious" {
		t.Errorf("proxy IP verdict = %q, want suspicious", proxy.Verdict)
	}

	bad := &IPReport{Blocklist: &BlocklistScan{Listed: 3}, Geo: &GeoInfo{Proxy: true, Hosting: true}}
	scoreIP(bad)
	if bad.Verdict != "malicious" {
		t.Errorf("listed+proxy IP verdict = %q, want malicious", bad.Verdict)
	}
	if bad.Score > 100 {
		t.Errorf("score capped? got %d", bad.Score)
	}
}
