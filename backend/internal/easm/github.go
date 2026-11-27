package easm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sort"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// githubSearch finds public GitHub code that references the domain — a lead for
// the organisation's repositories and for domain/API references accidentally
// committed (spec P08). Passive (third-party data, no contact with the target).
// Metadata only: repository names and file paths are recorded as indicators;
// file contents are never fetched or stored (data minimisation).
//
// The GitHub code-search API requires a token; it is read from GITHUB_TOKEN (the
// same credential the intel sources use). Without it, the collector is a no-op.
type githubSearch struct{ client *http.Client }

func (githubSearch) Name() string { return "github" }

const githubRepoCap = 20

func (g githubSearch) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, nil // needs a token; skip silently
	}
	q := url.QueryEscape(`"` + domain + `"`)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/search/code?per_page=50&q="+q, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "pahredar-easm")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil // 403 rate-limit / 422 bad query → nothing to record
	}
	var body struct {
		Items []ghItem `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return githubRecords(body.Items), nil
}

// ghItem is the subset of a code-search hit we use.
type ghItem struct {
	Path       string `json:"path"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

// githubRecords aggregates code-search hits into one record per repository,
// listing the matching file paths (capped).
func githubRecords(hits []ghItem) []db.AssetRecord {
	type agg struct {
		url   string
		paths []string
	}
	byRepo := map[string]*agg{}
	var order []string
	for _, h := range hits {
		name := h.Repository.FullName
		if name == "" {
			continue
		}
		a := byRepo[name]
		if a == nil {
			if len(byRepo) >= githubRepoCap {
				continue
			}
			a = &agg{url: h.Repository.HTMLURL}
			byRepo[name] = a
			order = append(order, name)
		}
		if h.Path != "" && len(a.paths) < 10 {
			a.paths = append(a.paths, h.Path)
		}
	}
	sort.Strings(order)
	out := make([]db.AssetRecord, 0, len(order))
	for _, name := range order {
		a := byRepo[name]
		sort.Strings(a.paths)
		out = append(out, rec("repo_ref", name, "github", map[string]any{
			"repo": name, "url": a.url, "paths": a.paths, "matches": len(a.paths),
		}, "GitHub code search"))
	}
	return out
}
