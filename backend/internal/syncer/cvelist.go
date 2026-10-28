package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/cvelist"
)

const (
	SourceCVEList = "cvelist"

	batchSize = 1000
	// A cursor older than this is not caught up through daily deltas; a fresh
	// baseline is cheaper and guaranteed complete.
	maxCatchUpDays = 14
	dayLayout      = "2006-01-02"
	endOfDay       = "eod"
)

// listCursor records how far the cvelist sync has applied: the UTC day, and
// either the last hourly release applied for it ("0700Z") or "eod" once the
// day's end-of-day delta is applied. Stored as "2026-10-28 0700Z".
type listCursor struct {
	Day  time.Time
	Hour string
}

func (c listCursor) String() string { return c.Day.Format(dayLayout) + " " + c.Hour }

func parseListCursor(s string) (listCursor, error) {
	day, hour, ok := strings.Cut(s, " ")
	if !ok {
		return listCursor{}, fmt.Errorf("malformed cvelist cursor %q", s)
	}
	t, err := time.Parse(dayLayout, day)
	if err != nil {
		return listCursor{}, fmt.Errorf("malformed cvelist cursor %q: %w", s, err)
	}
	return listCursor{Day: t, Hour: hour}, nil
}

type CVEList struct {
	client *cvelist.Client
	store  *db.Store
	runner *Runner
	now    func() time.Time
}

func NewCVEList(client *cvelist.Client, store *db.Store, runner *Runner) *CVEList {
	return &CVEList{client: client, store: store, runner: runner, now: time.Now}
}

// Sync brings the cve table up to date with cvelistV5. It bootstraps from the
// full baseline when there is no usable cursor or forceBootstrap is set.
func (j *CVEList) Sync(ctx context.Context, forceBootstrap bool) error {
	var cur listCursor
	plan := func(ctx context.Context) (string, error) {
		stored, found, err := j.store.SyncCursor(ctx, SourceCVEList)
		if err != nil {
			return "", err
		}
		if forceBootstrap || !found {
			return KindBootstrap, nil
		}
		if cur, err = parseListCursor(stored); err != nil {
			slog.Warn("discarding cursor", "source", SourceCVEList, "err", err)
			return KindBootstrap, nil
		}
		if j.today().Sub(cur.Day) > maxCatchUpDays*24*time.Hour {
			return KindBootstrap, nil
		}
		return KindIncremental, nil
	}
	return j.runner.Run(ctx, SourceCVEList, plan, func(ctx context.Context, run *Run) error {
		if run.Kind == KindBootstrap {
			var err error
			if cur, err = j.bootstrap(ctx, run); err != nil {
				return err
			}
		}
		return j.incremental(ctx, run, cur)
	})
}

func (j *CVEList) today() time.Time {
	return j.now().UTC().Truncate(24 * time.Hour)
}

func (j *CVEList) bootstrap(ctx context.Context, run *Run) (listCursor, error) {
	rel, err := j.client.Latest(ctx)
	if err != nil {
		return listCursor{}, err
	}
	asset, ok := rel.Asset("_all_CVEs_at_midnight.zip.zip")
	if !ok {
		return listCursor{}, fmt.Errorf("release %s has no baseline asset", rel.Tag)
	}
	day, err := time.Parse(dayLayout, strings.SplitN(asset.Name, "_", 2)[0])
	if err != nil {
		return listCursor{}, fmt.Errorf("baseline asset %q: %w", asset.Name, err)
	}

	slog.Info("downloading cvelist baseline", "asset", asset.Name, "size_mb", asset.Size>>20)
	w := newBatchWriter(j.store, run)
	if err := j.client.ForEachInBaseline(ctx, asset, func(raw []byte) error { return w.add(ctx, raw) }); err != nil {
		return listCursor{}, err
	}
	if err := w.flush(ctx); err != nil {
		return listCursor{}, err
	}
	w.logDone(asset.Name)

	// The baseline is the state at 00:00 that day; hourly deltas continue from there.
	cur := listCursor{Day: day, Hour: "0000Z"}
	return cur, j.store.SetSyncCursor(ctx, SourceCVEList, cur.String())
}

// incremental applies, in order: the end-of-day delta for each finished day
// after the cursor, then the newest hourly delta for the cursor's current day.
// Deltas are cumulative per day, so re-applying one is harmless.
func (j *CVEList) incremental(ctx context.Context, run *Run, cur listCursor) error {
	w := newBatchWriter(j.store, run)
	apply := func(asset cvelist.Asset, next listCursor) error {
		if err := j.client.ForEachInDelta(ctx, asset, func(raw []byte) error { return w.add(ctx, raw) }); err != nil {
			return err
		}
		if err := w.flush(ctx); err != nil {
			return err
		}
		w.logDone(asset.Name)
		cur = next
		return j.store.SetSyncCursor(ctx, SourceCVEList, cur.String())
	}

	today := j.today()
	for {
		if cur.Hour == endOfDay {
			if !cur.Day.Before(today) {
				return nil
			}
			cur = listCursor{Day: cur.Day.AddDate(0, 0, 1), Hour: ""}
		}
		day := cur.Day.Format(dayLayout)

		if cur.Day.Before(today) {
			rel, found, err := j.client.ByTag(ctx, "cve_"+day+"_at_end_of_day")
			if err != nil {
				return err
			}
			if found {
				asset, ok := rel.Asset("_delta_CVEs_at_end_of_day.zip")
				if !ok {
					return fmt.Errorf("release %s has no delta asset", rel.Tag)
				}
				if err := apply(asset, listCursor{Day: cur.Day, Hour: endOfDay}); err != nil {
					return err
				}
				continue
			}
			// Not published yet (shortly after midnight): fall through to the
			// day's newest hourly delta and pick up end-of-day next run.
		}

		rel, hour, err := j.newestHourly(ctx, day)
		if err != nil {
			return err
		}
		if rel == nil || hour <= cur.Hour {
			return nil
		}
		asset, ok := rel.Asset("_delta_CVEs_at_" + hour + ".zip")
		if !ok {
			return fmt.Errorf("release %s has no delta asset", rel.Tag)
		}
		return apply(asset, listCursor{Day: cur.Day, Hour: hour})
	}
}

func (j *CVEList) newestHourly(ctx context.Context, day string) (*cvelist.Release, string, error) {
	releases, err := j.client.Recent(ctx)
	if err != nil {
		return nil, "", err
	}
	var best *cvelist.Release
	bestHour := ""
	for i := range releases {
		d, h, ok := releases[i].Hourly()
		if ok && d == day && h > bestHour {
			best, bestHour = &releases[i], h
		}
	}
	return best, bestHour, nil
}

// batchWriter parses records and writes them in batches, skipping any that
// are not newer than what is stored.
type batchWriter struct {
	store   *db.Store
	run     *Run
	pending map[string]*cverecord.Record
	parsed  int
	skipped int
	invalid int
}

func newBatchWriter(store *db.Store, run *Run) *batchWriter {
	return &batchWriter{store: store, run: run, pending: make(map[string]*cverecord.Record, batchSize)}
}

func (w *batchWriter) add(ctx context.Context, raw []byte) error {
	rec, err := cverecord.Parse(raw)
	if err != nil {
		w.invalid++
		slog.Debug("skipping invalid record", "err", err)
		return nil
	}
	w.parsed++
	w.pending[rec.Metadata.ID] = rec
	if w.parsed%50000 == 0 {
		slog.Info("cvelist progress", "parsed", w.parsed, "inserted", w.run.Inserted, "updated", w.run.Updated)
	}
	if len(w.pending) >= batchSize {
		return w.flush(ctx)
	}
	return nil
}

func (w *batchWriter) flush(ctx context.Context) error {
	if len(w.pending) == 0 {
		return nil
	}
	ids := make([]string, 0, len(w.pending))
	for id := range w.pending {
		ids = append(ids, id)
	}
	ins, upd, err := w.store.WriteCVEBatch(ctx, ids, func(existing map[string]db.ExistingCVE) ([]db.CVERow, error) {
		rows := make([]db.CVERow, 0, len(w.pending))
		for id, rec := range w.pending {
			ex, ok := existing[id]
			if ok && ex.RawCvelist != nil && ex.DateUpdated != nil {
				if incoming := rec.Metadata.DateUpdated.Ptr(); incoming != nil && !incoming.After(*ex.DateUpdated) {
					w.skipped++
					continue
				}
			}
			var nvd *cverecord.NVD
			if ok && ex.RawNVD != nil {
				var err error
				if nvd, err = cverecord.ParseNVD(ex.RawNVD); err != nil {
					slog.Warn("ignoring unparseable stored NVD record", "id", id, "err", err)
					nvd = nil
				}
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
	w.run.Inserted += ins
	w.run.Updated += upd
	clear(w.pending)
	return nil
}

func (w *batchWriter) logDone(name string) {
	slog.Info("applied cvelist archive", "archive", name, "parsed", w.parsed, "skipped_unchanged", w.skipped, "invalid", w.invalid)
}
