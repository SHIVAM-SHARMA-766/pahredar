package scan

import (
	"net"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct{ in, host, url string }{
		{"example.com", "example.com", "https://example.com"},
		{"http://example.com/path?q=1", "example.com", "http://example.com"},
		{"https://sub.example.com:8443", "sub.example.com", "https://sub.example.com:8443"},
	}
	for _, c := range cases {
		host, base, err := ParseTarget(c.in)
		if err != nil || host != c.host || base.String() != c.url {
			t.Errorf("%q -> %q %v (err %v)", c.in, host, base, err)
		}
	}
	// ParseTarget accepts private hosts (the Scanner decides whether to scan
	// them, based on its allowPrivate setting); it rejects only malformed input.
	for _, bad := range []string{"", "ftp://x", "not a host", "https://"} {
		if _, _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.0.1", "100.64.0.1", "::1", "0.0.0.0"} {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s should be private", s)
		}
	}
}

func TestScore(t *testing.T) {
	rep := &Report{Findings: []Finding{
		{Severity: SevLow}, {Severity: SevCritical}, {Severity: SevMedium}, {Severity: SevGood},
	}}
	score(rep)
	if rep.Findings[0].Severity != SevCritical {
		t.Fatalf("critical should sort first, got %s", rep.Findings[0].Severity)
	}
	if rep.Score != 100-30-8-3 || rep.Grade != "D" {
		t.Fatalf("score=%d grade=%s", rep.Score, rep.Grade)
	}
}
