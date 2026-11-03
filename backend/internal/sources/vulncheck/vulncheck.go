// Package vulncheck reads VulnCheck KEV (api.vulncheck.com, free Community
// token): known exploited vulnerabilities from VulnCheck's own research,
// a superset of CISA KEV that also lists the public reports of exploitation,
// whether VulnCheck's canaries saw it, and links to exploit code (XDB).
package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	kevURL   = "https://api.vulncheck.com/v3/index/vulncheck-kev"
	pageSize = 2000
	// maxPages bounds the crawl if the cursor never ends (~6k entries today).
	maxPages = 20
)

// Entry is one VulnCheck KEV record, per CVE.
type Entry struct {
	CVEID      string
	Name       string
	Vendor     string
	Product    string
	DateAdded  *time.Time
	Ransomware bool
	// Canary is true when VulnCheck's own sensors saw exploitation.
	Canary   bool
	Reported []Report
	XDB      []Exploit
}

// Report is a public source reporting exploitation.
type Report struct {
	URL       string `json:"url"`
	DateAdded string `json:"date_added,omitempty"`
}

// Exploit is a VulnCheck XDB entry: a public exploit repository.
type Exploit struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Type      string `json:"type,omitempty"`
	Repo      string `json:"repo,omitempty"`
	DateAdded string `json:"date_added,omitempty"`
}

type record struct {
	VendorProject string   `json:"vendorProject"`
	Product       string   `json:"product"`
	Name          string   `json:"vulnerabilityName"`
	Ransomware    string   `json:"knownRansomwareCampaignUse"`
	CVE           []string `json:"cve"`
	DateAdded     string   `json:"date_added"`
	Canary        bool     `json:"reported_exploited_by_vulncheck_canaries"`
	Reported      []struct {
		URL       string `json:"url"`
		DateAdded string `json:"date_added"`
	} `json:"vulncheck_reported_exploitation"`
	XDB []struct {
		ID        string `json:"xdb_id"`
		URL       string `json:"xdb_url"`
		Type      string `json:"exploit_type"`
		CloneURL  string `json:"clone_ssh_url"`
		DateAdded string `json:"date_added"`
	} `json:"vulncheck_xdb"`
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Fetch pages through the whole index with VulnCheck's cursor.
func Fetch(ctx context.Context, c *http.Client, token string) ([]Entry, error) {
	header := http.Header{"Accept": {"application/json"}, "Authorization": {"Bearer " + token}}
	q := url.Values{"limit": {fmt.Sprint(pageSize)}, "start_cursor": {"true"}}
	var out []Entry
	total := 0
	for page := 0; page < maxPages; page++ {
		var body struct {
			Meta struct {
				Total      int    `json:"total_documents"`
				NextCursor string `json:"next_cursor"`
			} `json:"_meta"`
			Data []record `json:"data"`
		}
		if err := getPage(ctx, c, kevURL+"?"+q.Encode(), header, &body); err != nil {
			return nil, fmt.Errorf("vulncheck kev page %d: %w", page, err)
		}
		total = body.Meta.Total
		for _, r := range body.Data {
			out = append(out, entries(r)...)
		}
		if body.Meta.NextCursor == "" || len(body.Data) == 0 {
			break
		}
		q = url.Values{"limit": {fmt.Sprint(pageSize)}, "cursor": {body.Meta.NextCursor}}
	}
	if total > 0 && len(out) == 0 {
		return nil, fmt.Errorf("vulncheck kev: %d documents reported but none parsed", total)
	}
	return out, nil
}

func getPage(ctx context.Context, c *http.Client, u string, h http.Header, v any) error {
	resp, err := fetch.Get(ctx, c, u, h)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(v)
}

func entries(r record) []Entry {
	var added *time.Time
	if t, err := time.Parse(time.RFC3339, r.DateAdded); err == nil {
		added = &t
	}
	reported := make([]Report, 0, len(r.Reported))
	for _, x := range r.Reported {
		if x.URL != "" {
			reported = append(reported, Report{URL: x.URL, DateAdded: day(x.DateAdded)})
		}
	}
	// XDB can index one repository several times; keep the first.
	xdb := make([]Exploit, 0, len(r.XDB))
	repos := map[string]bool{}
	for _, x := range r.XDB {
		repo := repoURL(x.CloneURL)
		if x.ID == "" || (repo != "" && repos[strings.ToLower(repo)]) {
			continue
		}
		repos[strings.ToLower(repo)] = true
		xdb = append(xdb, Exploit{ID: x.ID, URL: x.URL, Type: x.Type, Repo: repo, DateAdded: day(x.DateAdded)})
	}
	var out []Entry
	for _, id := range r.CVE {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !cvePattern.MatchString(id) {
			continue
		}
		out = append(out, Entry{
			CVEID: id, Name: strings.TrimSpace(r.Name), Vendor: r.VendorProject, Product: r.Product, DateAdded: added,
			Ransomware: strings.EqualFold(r.Ransomware, "Known"), Canary: r.Canary, Reported: reported, XDB: xdb,
		})
	}
	return out
}

func day(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// repoURL turns "git@github.com:owner/repo.git" into a browsable URL.
func repoURL(clone string) string {
	host, path, ok := strings.Cut(strings.TrimPrefix(clone, "git@"), ":")
	if !ok || host == "" || path == "" {
		return ""
	}
	return "https://" + host + "/" + strings.TrimSuffix(path, ".git")
}
