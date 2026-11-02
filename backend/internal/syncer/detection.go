package syncer

import (
	"context"
	"fmt"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/detection"
)

// SyncDetection refreshes one detection-rule source (see
// detection.Fetchers). Like the exploit indexes it is a snapshot.
func (e *Enrichment) SyncDetection(ctx context.Context, source string) error {
	fetchFn, ok := detection.Fetchers[source]
	if !ok {
		return fmt.Errorf("unknown detection source %q", source)
	}
	return e.runner.Run(ctx, source, e.snapshotPlan(source), func(ctx context.Context, run *Run) error {
		rules, err := fetchFn(ctx, e.http)
		if err != nil {
			return err
		}
		rows := make([]db.DetectionRow, len(rules))
		for i, r := range rules {
			rows[i] = db.DetectionRow{RuleID: r.RuleID, Title: r.Title, URL: r.URL, Body: r.Body, Meta: r.Meta, CVEIDs: r.CVEIDs}
		}
		run.Inserted, run.Updated, run.Deleted, err = e.store.ReplaceDetectionRules(ctx, source, rows)
		if err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, source, time.Now().UTC().Format(time.RFC3339))
	})
}
