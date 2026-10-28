package syncer

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/nvd"
)

const (
	SourceNVD = "nvd"

	// nvdBootstrapConcurrency pages in flight during a full pull. NVD takes
	// ~30-40 s to serve each 2000-record page, so the rate limit (not
	// bandwidth) is never the bottleneck at this level.
	nvdBootstrapConcurrency = 4
	// nvdOverlap re-reads a little before the cursor so records modified
	// around the previous run's end are not missed.
	nvdOverlap = 5 * time.Minute
)

type NVD struct {
	client *nvd.Client
	store  *db.Store
	runner *Runner
	now    func() time.Time
}

func NewNVD(client *nvd.Client, store *db.Store, runner *Runner) *NVD {
	return &NVD{client: client, store: store, runner: runner, now: time.Now}
}

// Sync merges NVD analysis into the cve table. The cursor is the RFC 3339
// time up to which records have been read.
func (j *NVD) Sync(ctx context.Context, forceBootstrap bool) error {
	var since time.Time
	plan := func(ctx context.Context) (string, error) {
		stored, found, err := j.store.SyncCursor(ctx, SourceNVD)
		if err != nil {
			return "", err
		}
		if forceBootstrap || !found {
			return KindBootstrap, nil
		}
		if since, err = time.Parse(time.RFC3339, stored); err != nil {
			slog.Warn("discarding cursor", "source", SourceNVD, "cursor", stored, "err", err)
			return KindBootstrap, nil
		}
		if j.now().Sub(since) > nvd.MaxWindow-nvdOverlap {
			return KindBootstrap, nil
		}
		return KindIncremental, nil
	}
	return j.runner.Run(ctx, SourceNVD, plan, func(ctx context.Context, run *Run) error {
		// Records modified while a long pull runs are picked up next time
		// because the cursor is the time this run started.
		started := j.now().UTC()
		var w nvd.Window
		concurrency := nvdBootstrapConcurrency
		if run.Kind == KindIncremental {
			w = nvd.Window{Start: since.Add(-nvdOverlap), End: started}
			concurrency = 1
		}
		var invalid, skipped int
		err := j.client.ForEach(ctx, w, concurrency, func(raws []json.RawMessage) error {
			inv, skip, err := j.writePage(ctx, run, raws)
			invalid += inv
			skipped += skip
			return err
		})
		if err != nil {
			return err
		}
		slog.Info("applied nvd records", "skipped_unchanged", skipped, "invalid", invalid)
		return j.store.SetSyncCursor(ctx, SourceNVD, started.Format(time.RFC3339))
	})
}

func (j *NVD) writePage(ctx context.Context, run *Run, raws []json.RawMessage) (invalid, skipped int, err error) {
	records := make(map[string]*cverecord.NVD, len(raws))
	for _, raw := range raws {
		n, err := cverecord.ParseNVD(raw)
		if err != nil {
			invalid++
			slog.Debug("skipping invalid NVD record", "err", err)
			continue
		}
		records[n.ID] = n
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	ins, upd, err := j.store.WriteCVEBatch(ctx, ids, func(existing map[string]db.ExistingCVE) ([]db.CVERow, error) {
		rows := make([]db.CVERow, 0, len(records))
		for id, n := range records {
			ex, ok := existing[id]
			if ok && ex.RawNVD != nil && ex.NVDLastModified != nil {
				if incoming := n.LastModified.Ptr(); incoming != nil && !incoming.After(*ex.NVDLastModified) {
					skipped++
					continue
				}
			}
			var rec *cverecord.Record
			if ok && ex.RawCvelist != nil {
				var err error
				if rec, err = cverecord.Parse(ex.RawCvelist); err != nil {
					slog.Warn("ignoring unparseable stored cvelist record", "id", id, "err", err)
					rec = nil
				}
			}
			row, err := buildRow(rec, n)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		return rows, nil
	})
	run.Inserted += ins
	run.Updated += upd
	return invalid, skipped, err
}
