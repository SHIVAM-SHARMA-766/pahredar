package easm

import (
	"context"
	"errors"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/jobs"
)

// EnqueueScan queues an EASM scan of the given profile for a domain/URL asset.
func EnqueueScan(ctx context.Context, q *jobs.Queue, a *db.Asset, profile string) (int64, error) {
	domain := domainOf(a)
	if domain == "" {
		return 0, errors.New("asset is not a domain or URL")
	}
	return q.Enqueue(ctx, TaskType, scanPayload{AssetID: a.ID, ClientID: a.ClientID, Domain: domain, Profile: profile}, 1)
}

// ScheduleDue enqueues a standard EASM scan for every domain/URL asset not
// scanned within olderThan (continuous monitoring). Returns how many were
// enqueued.
func ScheduleDue(ctx context.Context, store *db.Store, q *jobs.Queue, olderThan time.Duration) (int, error) {
	due, err := store.AssetsDueForEASM(ctx, time.Now().Add(-olderThan), 100)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range due {
		if _, err := EnqueueScan(ctx, q, &due[i], "standard"); err == nil {
			n++
		}
	}
	return n, nil
}
