package easm

import (
	"testing"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

func TestBuildChanges(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)  // since run start
	t0e := t0.Add(2 * time.Minute)                       // since run finish
	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC) // latest run start

	since := &db.ScanRun{ID: 1, StartedAt: t0, FinishedAt: &t0e}
	latest := &db.ScanRun{ID: 2, StartedAt: t1}

	records := []db.AssetRecord{
		// Present at both: first seen in the since run, re-observed by the latest.
		{Category: "subdomain", Key: "www", Source: "crtsh", FirstSeen: t0.Add(time.Minute), LastSeen: t1.Add(time.Minute)},
		// Added: first seen after the since run finished.
		{Category: "subdomain", Key: "api", Source: "crtsh", FirstSeen: t0e.Add(time.Hour), LastSeen: t1.Add(time.Minute)},
		// Removed: last seen before the latest scan started (not re-observed).
		{Category: "port", Key: "8080", Source: "port_scan", FirstSeen: t0.Add(time.Minute), LastSeen: t0.Add(3 * time.Minute)},
	}

	cs := buildChanges(42, records, since, latest)

	if len(cs.Added) != 1 || cs.Added[0].Key != "api" {
		t.Fatalf("added = %+v, want [api]", cs.Added)
	}
	if len(cs.Removed) != 1 || cs.Removed[0].Key != "8080" {
		t.Fatalf("removed = %+v, want [8080]", cs.Removed)
	}
	if cs.AddedBy["subdomain"] != 1 || cs.RemovedBy["port"] != 1 {
		t.Fatalf("category counts wrong: added=%v removed=%v", cs.AddedBy, cs.RemovedBy)
	}
}

func TestBuildChangesNeedsTwoRuns(t *testing.T) {
	cs := buildChanges(1, nil, nil, &db.ScanRun{ID: 1})
	if cs.Note == "" || len(cs.Added) != 0 || len(cs.Removed) != 0 {
		t.Fatalf("want empty change set with a note, got %+v", cs)
	}
}

func TestBuildReportQuality(t *testing.T) {
	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	runs := []db.ScanRun{{ID: 2, StartedAt: t1, Profile: "standard", RecordCount: 2}}
	records := []db.AssetRecord{
		{Category: "cert", Key: "live", Source: "tls_probe", Method: "active", Confidence: "high", Verification: "verified", LastSeen: t1.Add(time.Minute)},
		{Category: "subdomain", Key: "old", Source: "crtsh", Method: "passive", Confidence: "low", Verification: "unverified", LastSeen: t1.Add(-time.Hour)}, // stale
	}
	a := &db.Asset{ID: 7, Value: "example.com"}
	rep := buildReport(a, records, nil, runs)

	if rep.Quality.TotalRecords != 2 {
		t.Fatalf("total = %d, want 2", rep.Quality.TotalRecords)
	}
	if rep.Quality.Unverified != 1 {
		t.Fatalf("unverified = %d, want 1", rep.Quality.Unverified)
	}
	if rep.Quality.Stale != 1 {
		t.Fatalf("stale = %d, want 1 (the old subdomain not re-observed by latest run)", rep.Quality.Stale)
	}
	if rep.Quality.BySource["crtsh"] != 1 || rep.Quality.ByMethod["active"] != 1 {
		t.Fatalf("breakdowns wrong: %+v", rep.Quality)
	}
	if rep.Findings == nil {
		t.Fatalf("findings should be non-nil empty slice for JSON")
	}
}
