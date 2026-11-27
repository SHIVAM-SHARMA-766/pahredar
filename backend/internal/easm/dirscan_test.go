package easm

import (
	"strings"
	"testing"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

func TestSensitivePathsSane(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range sensitivePaths {
		if !strings.HasPrefix(p.path, "/") {
			t.Errorf("path %q must start with /", p.path)
		}
		if seen[p.path] {
			t.Errorf("duplicate path %q", p.path)
		}
		seen[p.path] = true
		switch p.severity {
		case "low", "medium", "high":
		default:
			t.Errorf("path %q has bad severity %q", p.path, p.severity)
		}
	}
	if len(sensitivePaths) < 15 {
		t.Errorf("list unexpectedly small: %d", len(sensitivePaths))
	}
}

func TestIsRealHit(t *testing.T) {
	cases := []struct {
		status, bodyLen, baseStatus, baseLen int
		want                                 bool
	}{
		{200, 726, 404, 3678, true},   // normal server, distinct 200 → real
		{200, 3700, 200, 3678, false}, // catch-all, same-ish body → soft-404
		{200, 500, 200, 3678, true},   // catch-all but body differs → real
		{403, 10, 404, 3678, true},    // protected → real
		{401, 10, 200, 3678, true},    // protected even on catch-all
		{404, 3678, 404, 3678, false}, // not found
		{500, 0, 404, 3678, false},    // error → ignore
	}
	for _, c := range cases {
		if got := isRealHit(c.status, c.bodyLen, c.baseStatus, c.baseLen); got != c.want {
			t.Errorf("isRealHit(%d,%d,%d,%d) = %v, want %v", c.status, c.bodyLen, c.baseStatus, c.baseLen, got, c.want)
		}
	}
}

func TestDirScanFindings(t *testing.T) {
	recs := []db.AssetRecord{
		srec("exposed_path", "/.git/config", "http_probe", map[string]any{"path": "/.git/config", "status": 200, "label": "Git repository config", "severity": "high"}),
		srec("exposed_path", "/.env", "http_probe", map[string]any{"path": "/.env", "status": 403, "label": "Environment file", "severity": "high"}), // protected → no finding
		srec("exposed_path", "/phpinfo.php", "http_probe", map[string]any{"path": "/phpinfo.php", "status": 200, "label": "PHP info page", "severity": "medium"}),
	}
	got := map[string]string{}
	for _, f := range buildFindings(1, recs) {
		got[f.CVEID] = f.Severity
	}
	if got["exposed-path-/.git/config"] != "high" {
		t.Errorf(".git/config finding = %q, want high", got["exposed-path-/.git/config"])
	}
	if got["exposed-path-/phpinfo.php"] != "medium" {
		t.Errorf("phpinfo finding = %q, want medium", got["exposed-path-/phpinfo.php"])
	}
	if _, bad := got["exposed-path-/.env"]; bad {
		t.Error("a 403-protected path must not produce a finding")
	}
	if len(got) != 2 {
		t.Errorf("want 2 findings, got %d (%v)", len(got), got)
	}
}
