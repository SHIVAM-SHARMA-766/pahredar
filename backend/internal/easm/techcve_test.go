package easm

import (
	"testing"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

func TestParseTechToken(t *testing.T) {
	cases := []struct {
		tok, product, version string
		ok                    bool
	}{
		{"nginx/1.18.0", "nginx", "1.18.0", true},
		{"Apache/2.4.41", "http_server", "2.4.41", true},
		{"PHP/7.4.3", "php", "7.4.3", true},
		{"nginx", "nginx", "", true},     // no version
		{"cloudflare", "", "", false},    // CDN, skipped
		{"gunicorn/20.1", "", "", false}, // unknown product
		{"", "", "", false},
	}
	for _, c := range cases {
		p, ver, ok := parseTechToken(c.tok)
		if ok != c.ok || p.Product != c.product || ver != c.version {
			t.Errorf("parseTechToken(%q) = (%q,%q,%v), want (%q,%q,%v)", c.tok, p.Product, ver, ok, c.product, c.version, c.ok)
		}
	}
}

func TestTechSeverity(t *testing.T) {
	cases := []struct {
		c    *scan.TechCVEs
		want string
	}{
		{nil, ""},
		{&scan.TechCVEs{Total: 0}, ""},
		{&scan.TechCVEs{Total: 5, KEV: 1}, "high"},
		{&scan.TechCVEs{Total: 5, Critical: 2}, "medium"},
		{&scan.TechCVEs{Total: 5}, "low"},
		{&scan.TechCVEs{Total: 5, KEV: 1, Critical: 3}, "high"}, // KEV wins
	}
	for _, c := range cases {
		if got := techSeverity(c.c); got != c.want {
			t.Errorf("techSeverity(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}
