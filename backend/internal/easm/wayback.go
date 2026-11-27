package easm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// wayback collects historical URLs and subdomains for a domain from the Internet
// Archive's Wayback Machine CDX API (passive, free, no key). Spec P07 (search /
// web archive) + P14 (historical). Archived captures often reveal forgotten
// endpoints and subdomains that no longer appear in live DNS or CT logs.
type wayback struct{ client *http.Client }

func (wayback) Name() string { return "wayback" }

// caps keep a noisy domain's archive from flooding the record store.
const (
	waybackRowLimit = 1500 // CDX rows requested
	waybackURLCap   = 150  // distinct historical URLs stored
	waybackSubCap   = 200  // distinct subdomains stored
)

func (w wayback) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	u := "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape(domain) +
		"&matchType=domain&output=json&fl=original&collapse=urlkey&limit=" + fmt.Sprint(waybackRowLimit)
	var rows [][]string
	if err := getJSON(ctx, w.client, u, &rows); err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}
	return waybackRecords(domain, rows), nil
}

// waybackRecords turns CDX rows ([["original"], ["https://…"], …]) into subdomain
// and historical-url evidence records. Pure; no I/O.
func waybackRecords(domain string, rows [][]string) []db.AssetRecord {
	subs := map[string]bool{}
	paths := map[string]bool{} // host+path, deduped
	for i, r := range rows {
		if i == 0 || len(r) == 0 { // row 0 is the ["original"] header
			continue
		}
		pu, err := url.Parse(r[0])
		if err != nil || pu.Hostname() == "" {
			continue
		}
		host := strings.ToLower(pu.Hostname())
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue // off-scope capture
		}
		if host != domain && len(subs) < waybackSubCap {
			subs[host] = true
		}
		if p := pu.EscapedPath(); p != "" && p != "/" && len(paths) < waybackURLCap {
			paths[host+p] = true
		}
	}

	out := []db.AssetRecord{}
	for _, name := range sortedKeys(subs) {
		out = append(out, rec("subdomain", name, "wayback", map[string]any{"host": name}, "Wayback Machine capture"))
	}
	for _, hp := range sortedKeys(paths) {
		host, path, _ := strings.Cut(hp, "/")
		out = append(out, rec("url", hp, "wayback", map[string]any{"url": hp, "host": host, "path": "/" + path}, "Wayback Machine capture"))
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
