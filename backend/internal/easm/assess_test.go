package easm

import (
	"encoding/json"
	"testing"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

func srec(category, key, source string, data any) db.AssetRecord {
	raw, _ := json.Marshal(data)
	return db.AssetRecord{Category: category, Key: key, Source: source, Data: raw}
}

func TestBuildFindings(t *testing.T) {
	recs := []db.AssetRecord{
		srec("cert", "live", "tls_probe", map[string]any{"expired": true}),
		srec("cert", "oldserial", "crtsh", map[string]any{"expired": true}), // CT history — must be ignored
		srec("tls", "tls", "tls_probe", map[string]any{"version": "TLS 1.0"}),
		srec("http_security", "strict-transport-security", "http_probe", map[string]any{"present": false}),
		srec("http_security", "content-security-policy", "http_probe", map[string]any{"present": true}), // present — no finding
		srec("port", "1.2.3.4:3306", "port_scan", map[string]any{"port": 3306, "service": "mysql"}),
		srec("port", "1.2.3.4:443", "port_scan", map[string]any{"port": 443, "service": "https"}), // not sensitive
		srec("email", "spf", "dns_txt", map[string]any{"present": false}),
		srec("email", "dmarc", "dns_txt", map[string]any{"present": true, "policy": "none"}),
	}
	got := map[string]string{} // key -> severity
	for _, f := range buildFindings(9, recs) {
		if f.Type != "easm" || f.AssetID == nil || *f.AssetID != 9 {
			t.Fatalf("bad finding shape: %+v", f)
		}
		got[f.CVEID] = f.Severity
	}

	want := map[string]string{
		"cert-expired":      "high",
		"tls-weak":          "medium",
		"hsts-missing":      "low",
		"port-exposed-3306": "high",
		"spf-missing":       "medium",
		"dmarc-weak":        "low",
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("finding %s: want severity %q, got %q", k, sev, got[k])
		}
	}
	// Things that must NOT be findings.
	for _, k := range []string{"csp-missing", "cert-expiring", "dmarc-missing"} {
		if _, bad := got[k]; bad {
			t.Errorf("unexpected finding %s", k)
		}
	}
	if len(got) != len(want) {
		t.Errorf("finding count: want %d, got %d (%v)", len(want), len(got), got)
	}
}
