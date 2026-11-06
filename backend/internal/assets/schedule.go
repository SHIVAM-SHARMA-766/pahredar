package assets

import (
	"context"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/jobs"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scanner"
)

// RescanDue enqueues a scan for every scannable asset not scanned within
// olderThan. It is called on a schedule by the server. Returns how many were
// enqueued.
func RescanDue(ctx context.Context, store *db.Store, queue *jobs.Queue, olderThan time.Duration) (int, error) {
	due, err := store.AssetsDueForRescan(ctx, time.Now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range due {
		host, _, perr := scan.ParseTarget(a.Value)
		if perr != nil {
			continue
		}
		if _, err := queue.Enqueue(ctx, scanner.TaskType, scanner.TaskPayload{Target: a.Value, Host: host, AssetID: a.ID}, 1); err == nil {
			n++
		}
	}
	return n, nil
}
