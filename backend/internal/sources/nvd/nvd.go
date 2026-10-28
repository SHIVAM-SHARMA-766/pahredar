// Package nvd pages through the NVD CVE API 2.0
// (https://nvd.nist.gov/developers/vulnerabilities), honouring its rate limit
// and retrying the transient failures it is known for.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// PageSize is the API's maximum resultsPerPage.
	PageSize = 2000
	// MaxWindow is the longest lastMod date range the API accepts.
	MaxWindow = 120 * 24 * time.Hour

	dateLayout  = "2006-01-02T15:04:05.000Z"
	maxAttempts = 6
)

type Client struct {
	http   *http.Client
	apiKey string

	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

// New returns a client. With an API key NVD allows 50 requests per rolling
// 30 s, without one 5; requests are spaced evenly below those limits.
func New(apiKey string) *Client {
	interval := 6500 * time.Millisecond
	if apiKey != "" {
		interval = 700 * time.Millisecond
	}
	return &Client{http: fetch.NewClient(), apiKey: apiKey, interval: interval}
}

// Window limits results to records last modified in [Start, End]. The zero
// Window means all records.
type Window struct {
	Start, End time.Time
}

type page struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

// ForEach fetches every record in w, calling fn once per page with the raw
// "cve" objects. Up to concurrency pages are fetched at once; fn calls are
// serialized but arrive in no particular order.
func (c *Client) ForEach(ctx context.Context, w Window, concurrency int, fn func([]json.RawMessage) error) error {
	if !w.Start.IsZero() && w.End.Sub(w.Start) > MaxWindow {
		return fmt.Errorf("window %s exceeds the API maximum of %s", w.End.Sub(w.Start), MaxWindow)
	}
	first, err := c.fetchPage(ctx, w, 0)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	deliver := func(p page) error {
		raws := make([]json.RawMessage, len(p.Vulnerabilities))
		for i, v := range p.Vulnerabilities {
			raws[i] = v.CVE
		}
		mu.Lock()
		defer mu.Unlock()
		return fn(raws)
	}
	if err := deliver(first); err != nil {
		return err
	}
	pages := (first.TotalResults + PageSize - 1) / PageSize
	slog.Info("nvd fetch", "total_results", first.TotalResults, "pages", pages)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(max(concurrency, 1))
	for i := 1; i < pages; i++ {
		start := i * PageSize
		g.Go(func() error {
			p, err := c.fetchPage(ctx, w, start)
			if err != nil {
				return err
			}
			if err := deliver(p); err != nil {
				return err
			}
			if i%20 == 0 {
				slog.Info("nvd progress", "page", i, "of", pages)
			}
			return nil
		})
	}
	return g.Wait()
}

func (c *Client) fetchPage(ctx context.Context, w Window, startIndex int) (page, error) {
	q := url.Values{}
	q.Set("resultsPerPage", strconv.Itoa(PageSize))
	q.Set("startIndex", strconv.Itoa(startIndex))
	if !w.Start.IsZero() {
		q.Set("lastModStartDate", w.Start.UTC().Format(dateLayout))
		q.Set("lastModEndDate", w.End.UTC().Format(dateLayout))
	}
	u := baseURL + "?" + q.Encode()

	header := http.Header{}
	if c.apiKey != "" {
		header.Set("apiKey", c.apiKey)
	}
	backoff := 10 * time.Second
	for attempt := 1; ; attempt++ {
		if err := c.wait(ctx); err != nil {
			return page{}, err
		}
		p, err := c.get(ctx, u, header)
		if err == nil {
			return p, nil
		}
		if attempt == maxAttempts || !retryable(err) || ctx.Err() != nil {
			return page{}, fmt.Errorf("nvd page at %d: %w", startIndex, err)
		}
		slog.Warn("nvd request failed, retrying", "start_index", startIndex, "attempt", attempt, "in", backoff, "err", err)
		select {
		case <-ctx.Done():
			return page{}, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (c *Client) get(ctx context.Context, u string, header http.Header) (page, error) {
	// NVD pages take tens of seconds to generate; bound each attempt.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	resp, err := fetch.Get(ctx, c.http, u, header)
	if err != nil {
		return page{}, err
	}
	defer resp.Body.Close()
	var p page
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return page{}, fmt.Errorf("decode: %w", err)
	}
	return p, nil
}

// wait blocks until the next request slot.
func (c *Client) wait(ctx context.Context) error {
	c.mu.Lock()
	now := time.Now()
	slot := c.next
	if slot.Before(now) {
		slot = now
	}
	c.next = slot.Add(c.interval)
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(slot.Sub(now)):
		return nil
	}
}

// retryable reports whether an error is worth retrying: network and decode
// failures, rate limiting (NVD answers 403 when throttled), and 5xx.
func retryable(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var se *fetch.StatusError
	if errors.As(err, &se) {
		return se.Code == http.StatusForbidden || se.Code == http.StatusTooManyRequests || se.Code >= 500
	}
	return true
}
