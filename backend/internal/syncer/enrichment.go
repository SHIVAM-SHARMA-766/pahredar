package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/cwe"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/epss"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/exploits"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/kev"
)

const (
	SourceKEV   = "kev"
	SourceEPSS  = "epss"
	SourceStats = "stats"
	SourceCWE   = "cwe"
)

// StatsInputs are the sources whose changes make the vendor/product stats
// stale.
var StatsInputs = []string{SourceCVEList, SourceNVD, SourceKEV}

// Enrichment runs the snapshot sources: each run downloads the whole feed
// and makes the stored rows equal to it.
type Enrichment struct {
	http   *http.Client
	store  *db.Store
	runner *Runner
}

func NewEnrichment(client *http.Client, store *db.Store, runner *Runner) *Enrichment {
	return &Enrichment{http: client, store: store, runner: runner}
}

// snapshotPlan is a bootstrap until the source has succeeded once.
func (e *Enrichment) snapshotPlan(source string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		_, found, err := e.store.SyncCursor(ctx, source)
		if err != nil {
			return "", err
		}
		if !found {
			return KindBootstrap, nil
		}
		return KindIncremental, nil
	}
}

func (e *Enrichment) SyncKEV(ctx context.Context) error {
	return e.runner.Run(ctx, SourceKEV, e.snapshotPlan(SourceKEV), func(ctx context.Context, run *Run) error {
		cat, err := kev.Fetch(ctx, e.http)
		if err != nil {
			return err
		}
		rows := make([]db.KEVRow, 0, len(cat.Vulnerabilities))
		seen := map[string]bool{}
		for _, v := range cat.Vulnerabilities {
			if !cverecord.IDPattern.MatchString(v.CVEID) || seen[v.CVEID] {
				slog.Warn("skipping KEV entry", "cve", v.CVEID)
				continue
			}
			seen[v.CVEID] = true
			added, err := kev.ParseDate(v.DateAdded)
			if err != nil || added == nil {
				return fmt.Errorf("KEV %s: bad dateAdded %q", v.CVEID, v.DateAdded)
			}
			due, err := kev.ParseDate(v.DueDate)
			if err != nil {
				return fmt.Errorf("KEV %s: bad dueDate %q", v.CVEID, v.DueDate)
			}
			rows = append(rows, db.KEVRow{
				CVEID: v.CVEID, VendorProject: v.VendorProject, Product: v.Product,
				VulnerabilityName: v.VulnerabilityName, ShortDescription: v.ShortDescription,
				RequiredAction: v.RequiredAction, DateAdded: *added, DueDate: due,
				KnownRansomwareUse: v.KnownRansomwareCampaignUse, ForensicTriage: v.ForensicTriage, Notes: v.Notes,
			})
		}
		run.Inserted, run.Updated, run.Deleted, err = e.store.ReplaceKEV(ctx, rows)
		if err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, SourceKEV, cat.Version)
	})
}

// SyncEPSS loads the day's scores. The cursor is the score date; a run that
// finds the same date again does nothing.
func (e *Enrichment) SyncEPSS(ctx context.Context) error {
	return e.runner.Run(ctx, SourceEPSS, e.snapshotPlan(SourceEPSS), func(ctx context.Context, run *Run) error {
		date, scores, err := epss.Fetch(ctx, e.http)
		if err != nil {
			return err
		}
		day := date.Format(dayLayout)
		if cur, found, err := e.store.SyncCursor(ctx, SourceEPSS); err != nil {
			return err
		} else if found && cur == day {
			slog.Info("epss unchanged", "score_date", day)
			return nil
		}
		rows := make([]db.EPSSRow, len(scores))
		for i, s := range scores {
			rows[i] = db.EPSSRow{CVEID: s.CVEID, Score: s.Score, Percentile: s.Percentile}
		}
		// Counters: updated = current scores loaded, inserted = history rows added.
		run.Updated, run.Inserted, err = e.store.ReplaceEPSS(ctx, date, rows)
		if err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, SourceEPSS, day)
	})
}

// SyncExploits refreshes one exploit index (see exploits.Fetchers).
func (e *Enrichment) SyncExploits(ctx context.Context, source string) error {
	fetchFn, ok := exploits.Fetchers[source]
	if !ok {
		return fmt.Errorf("unknown exploit source %q", source)
	}
	return e.runner.Run(ctx, source, e.snapshotPlan(source), func(ctx context.Context, run *Run) error {
		entries, err := fetchFn(ctx, e.http)
		if err != nil {
			return err
		}
		rows := make([]db.ExploitRow, len(entries))
		for i, en := range entries {
			rows[i] = db.ExploitRow{CVEID: en.CVEID, SourceRef: en.SourceRef, Title: en.Title, URL: en.URL, PublishedAt: en.PublishedAt, Meta: en.Meta}
		}
		run.Inserted, run.Updated, run.Deleted, err = e.store.ReplaceExploits(ctx, source, rows)
		if err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, source, time.Now().UTC().Format(time.RFC3339))
	})
}

// RefreshStats recomputes the vendor/product aggregates. It is scheduled
// like a source so it shares locking, run logging, and retries.
func (e *Enrichment) RefreshStats(ctx context.Context) error {
	return e.runner.Run(ctx, SourceStats, e.snapshotPlan(SourceStats), func(ctx context.Context, run *Run) error {
		if err := e.store.RefreshStats(ctx); err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, SourceStats, time.Now().UTC().Format(time.RFC3339))
	})
}

// SyncCWE refreshes CWE names from MITRE.
func (e *Enrichment) SyncCWE(ctx context.Context) error {
	return e.runner.Run(ctx, SourceCWE, e.snapshotPlan(SourceCWE), func(ctx context.Context, run *Run) error {
		ws, err := cwe.Fetch(ctx, e.http)
		if err != nil {
			return err
		}
		rows := make([]db.CWERow, len(ws))
		for i, w := range ws {
			rows[i] = db.CWERow{ID: w.ID, Name: w.Name}
		}
		run.Inserted, run.Updated, run.Deleted, err = e.store.ReplaceCWE(ctx, rows)
		if err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, SourceCWE, time.Now().UTC().Format(time.RFC3339))
	})
}
