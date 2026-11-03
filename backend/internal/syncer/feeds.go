package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/feeds"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	SourceFeeds = "feeds"

	feedParallel = 6
	feedTimeout  = 30 * time.Second
	// Article pages read per run to find CVE IDs a feed omits. New items
	// beyond this are picked up on later runs.
	maxPageChecks = 150
	pageParallel  = 4
	pageTimeout   = 8 * time.Second
)

// SyncFeeds reads every feed in feeds.All and stores its items with the CVE
// IDs they mention, then prunes articles past their kind's retention
// (feeds.Retention) unless bookmarked. A failing feed is logged and skipped; the run fails only
// if more than half of the feeds fail.
func (e *Enrichment) SyncFeeds(ctx context.Context) error {
	return e.runner.Run(ctx, SourceFeeds, e.snapshotPlan(SourceFeeds), func(ctx context.Context, run *Run) error {
		now := time.Now()
		type result struct {
			feed  feeds.Feed
			items []feeds.Item
			err   error
		}
		results := make([]result, len(feeds.All))
		sem := make(chan struct{}, feedParallel)
		var wg sync.WaitGroup
		for i, f := range feeds.All {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				fctx, cancel := context.WithTimeout(ctx, feedTimeout)
				defer cancel()
				items, err := feeds.Fetch(fctx, e.http, f)
				results[i] = result{feed: f, items: items, err: err}
			}()
		}
		wg.Wait()

		var failed []string
		var rows []db.ArticleRow
		var urls []string
		seen := map[string]bool{}
		needsPage := map[string]bool{}
		for _, r := range results {
			if r.err != nil {
				failed = append(failed, r.feed.Key)
				slog.Warn("feed failed", "feed", r.feed.Key, "err", r.err)
				continue
			}
			cutoff := now.Add(-feeds.Retention[r.feed.Kind])
			for _, it := range r.items {
				if seen[it.URL] {
					continue
				}
				// Past retention: not stored (pruning would delete it again).
				if it.Published != nil && it.Published.Before(cutoff) {
					continue
				}
				seen[it.URL] = true
				check := r.feed.FetchPage && !it.HasBody
				rows = append(rows, db.ArticleRow{
					Feed: r.feed.Key, URL: it.URL, Title: it.Title, Summary: it.Summary,
					Published: it.Published, CVEIDs: it.CVEIDs, PageChecked: !check,
				})
				urls = append(urls, it.URL)
				if check {
					needsPage[it.URL] = true
				}
			}
		}
		if len(failed) > len(feeds.All)/2 {
			return fmt.Errorf("%d of %d feeds failed: %s", len(failed), len(feeds.All), strings.Join(failed, ", "))
		}

		// Read pages only for articles not checked before.
		known, err := e.store.KnownArticles(ctx, urls)
		if err != nil {
			return err
		}
		var toCheck []int
		for i, r := range rows {
			if needsPage[r.URL] && !known[r.URL].PageChecked && len(toCheck) < maxPageChecks {
				toCheck = append(toCheck, i)
			}
		}
		pages := fetch.PublicOnlyClient(pageTimeout)
		psem := make(chan struct{}, pageParallel)
		var pwg sync.WaitGroup
		for _, i := range toCheck {
			pwg.Add(1)
			go func() {
				defer pwg.Done()
				psem <- struct{}{}
				defer func() { <-psem }()
				pctx, cancel := context.WithTimeout(ctx, pageTimeout)
				defer cancel()
				ids, err := feeds.PageCVEs(pctx, pages, rows[i].URL)
				if err != nil {
					slog.Debug("article page unreadable", "url", rows[i].URL, "err", err)
				} else {
					rows[i].CVEIDs = feeds.ExtractCVEs(strings.Join(append(rows[i].CVEIDs, ids...), " "))
				}
				// Mark checked even on failure so a dead link is not retried
				// every hour; the feed text's CVE IDs are kept either way.
				rows[i].PageChecked = true
			}()
		}
		pwg.Wait()

		run.Inserted, run.Updated, err = e.store.UpsertArticles(ctx, rows)
		if err != nil {
			return err
		}
		byKind := map[string][]string{}
		for _, f := range feeds.All {
			byKind[f.Kind] = append(byKind[f.Kind], f.Key)
		}
		for kind, keys := range byKind {
			n, err := e.store.PruneArticles(ctx, keys, now.Add(-feeds.Retention[kind]))
			if err != nil {
				return err
			}
			run.Deleted += n
		}
		slog.Info("feeds read", "feeds", len(feeds.All)-len(failed), "failed", strings.Join(failed, ","), "items", len(rows), "pages_checked", len(toCheck))
		return e.store.SetSyncCursor(ctx, SourceFeeds, time.Now().UTC().Format(time.RFC3339))
	})
}

// RecheckArticlePages re-reads every checked article page of the
// FetchPage feeds and replaces its CVE IDs with those in the feed text plus
// the page's article text. Run it after changing how pages are read; an
// unreadable page keeps its stored IDs.
func (e *Enrichment) RecheckArticlePages(ctx context.Context) error {
	var keys []string
	for _, f := range feeds.All {
		if f.FetchPage {
			keys = append(keys, f.Key)
		}
	}
	rows, err := e.store.PageCheckedArticles(ctx, keys)
	if err != nil {
		return err
	}
	pages := fetch.PublicOnlyClient(pageTimeout)
	sem := make(chan struct{}, pageParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	changed, unreadable := 0, 0
	for _, r := range rows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, pageTimeout)
			defer cancel()
			ids, err := feeds.PageCVEs(pctx, pages, r.URL)
			if err != nil {
				mu.Lock()
				unreadable++
				mu.Unlock()
				return
			}
			fresh := feeds.ExtractCVEs(strings.Join(append([]string{r.Title, r.Summary}, ids...), " "))
			ok, err := e.store.SetArticleCVEs(ctx, r.URL, fresh)
			if err != nil {
				slog.Warn("update article", "url", r.URL, "err", err)
				return
			}
			if ok {
				mu.Lock()
				changed++
				mu.Unlock()
				slog.Info("article CVEs changed", "url", r.URL, "before", strings.Join(r.CVEIDs, ","), "after", strings.Join(fresh, ","))
			}
		}()
	}
	wg.Wait()
	slog.Info("article pages rechecked", "articles", len(rows), "changed", changed, "unreadable", unreadable)
	return nil
}
