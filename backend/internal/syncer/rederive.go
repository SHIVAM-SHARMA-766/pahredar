package syncer

import (
	"context"
	"log/slog"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// SourceRederive names the rederive job in sync_run and its lock.
const SourceRederive = "rederive"

// Rederive rewrites every cve row (and its affected rows) from the stored
// raw records, without downloading anything. Run it after changing
// derivation logic in cverecord: the sync jobs only rewrite a row when its
// upstream record changes. It holds the cvelist and NVD locks so neither
// sync interleaves with it.
func Rederive(ctx context.Context, store *db.Store, runner *Runner) error {
	for _, src := range []string{SourceCVEList, SourceNVD} {
		release, ok, err := store.TryLock(ctx, "sync:"+src)
		if err != nil {
			return err
		}
		if !ok {
			return ErrAlreadyRunning
		}
		defer release()
	}
	plan := func(context.Context) (string, error) { return KindBootstrap, nil }
	return runner.Run(ctx, SourceRederive, plan, func(ctx context.Context, run *Run) error {
		start := time.Now()
		after := ""
		for {
			ids, err := store.CVEIDsAfter(ctx, after, batchSize)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				break
			}
			after = ids[len(ids)-1]
			_, upd, err := store.WriteCVEBatch(ctx, ids, func(existing map[string]db.ExistingCVE) ([]db.CVERow, error) {
				rows := make([]db.CVERow, 0, len(existing))
				for id, ex := range existing {
					var rec *cverecord.Record
					var nvd *cverecord.NVD
					var err error
					if ex.RawCvelist != nil {
						if rec, err = cverecord.Parse(ex.RawCvelist); err != nil {
							slog.Warn("rederive: unparseable cvelist record", "id", id, "err", err)
							rec = nil
						}
					}
					if ex.RawNVD != nil {
						if nvd, err = cverecord.ParseNVD(ex.RawNVD); err != nil {
							slog.Warn("rederive: unparseable NVD record", "id", id, "err", err)
							nvd = nil
						}
					}
					if rec == nil && nvd == nil {
						continue
					}
					row, err := buildRow(rec, nvd)
					if err != nil {
						return nil, err
					}
					rows = append(rows, row)
				}
				return rows, nil
			})
			if err != nil {
				return err
			}
			run.Updated += upd
			if run.Updated%50000 < batchSize {
				slog.Info("rederive progress", "rows", run.Updated, "last_id", after, "elapsed", time.Since(start).Round(time.Second))
			}
		}
		return nil
	})
}
