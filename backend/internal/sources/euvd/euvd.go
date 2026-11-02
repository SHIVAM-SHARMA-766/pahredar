// Package euvd reads ENISA's EU Vulnerability Database list of actively
// exploited vulnerabilities (euvdservices.enisa.europa.eu, no key needed).
// It overlaps CISA KEV but is maintained independently, so it adds
// exploitation evidence for CVEs KEV has not listed.
package euvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	searchURL = "https://euvdservices.enisa.europa.eu/api/search?exploited=true&size=%d&page=%d"
	pageSize  = 100
	// maxPages bounds the crawl if the API stops honouring paging.
	maxPages = 200
)

// Entry is one exploited vulnerability, per CVE alias.
type Entry struct {
	CVEID          string
	EUVDID         string
	ExploitedSince *time.Time
	Description    string
}

type item struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	Aliases        string `json:"aliases"`
	ExploitedSince string `json:"exploitedSince"`
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// dateLayout is the API's display format, e.g. "Aug 18, 2026, 12:00:00 AM".
const dateLayout = "Jan 2, 2006, 3:04:05 PM"

// Fetch pages through the exploited list.
func Fetch(ctx context.Context, c *http.Client) ([]Entry, error) {
	var out []Entry
	total := -1
	for page := 0; page < maxPages; page++ {
		items, t, err := fetchPage(ctx, c, page)
		if err != nil {
			return nil, err
		}
		total = t
		for _, it := range items {
			out = append(out, entries(it)...)
		}
		if len(items) < pageSize || (page+1)*pageSize >= total {
			break
		}
	}
	if total > 0 && len(out) == 0 {
		return nil, fmt.Errorf("euvd: %d items reported but none parsed", total)
	}
	return out, nil
}

func fetchPage(ctx context.Context, c *http.Client, page int) ([]item, int, error) {
	resp, err := fetch.Get(ctx, c, fmt.Sprintf(searchURL, pageSize, page), http.Header{"Accept": {"application/json"}})
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var body struct {
		Items []item `json:"items"`
		Total int    `json:"total"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&body); err != nil {
		return nil, 0, fmt.Errorf("decode euvd page %d: %w", page, err)
	}
	return body.Items, body.Total, nil
}

func entries(it item) []Entry {
	var since *time.Time
	if t, err := time.Parse(dateLayout, strings.TrimSpace(it.ExploitedSince)); err == nil {
		since = &t
	}
	var out []Entry
	for _, a := range strings.Fields(it.Aliases) {
		a = strings.ToUpper(strings.TrimSpace(a))
		if cvePattern.MatchString(a) {
			out = append(out, Entry{CVEID: a, EUVDID: it.ID, ExploitedSince: since, Description: it.Description})
		}
	}
	return out
}
