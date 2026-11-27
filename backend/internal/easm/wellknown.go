package easm

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// wellKnown actively fetches a target's standard discovery files — robots.txt,
// sitemap.xml, and security.txt — and records their presence plus the endpoints
// they reveal (A08/A09). method=active. Low impact: a few plain GETs to
// well-known paths, the same a crawler would request.
type wellKnown struct{}

func (wellKnown) Name() string { return "well_known" }

const wellKnownURLCap = 100 // distinct discovered paths stored per file

var (
	sitemapLocRe = regexp.MustCompile(`(?is)<loc>\s*(.*?)\s*</loc>`)
	contactRe    = regexp.MustCompile(`(?im)^contact:\s*(.+?)\s*$`)
)

func (wk wellKnown) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	client := wellKnownClient()
	out := []db.AssetRecord{}

	// robots.txt — presence + Disallow paths + declared sitemaps.
	if body, ok := wkGet(ctx, client, "https://"+domain+"/robots.txt"); ok {
		disallows, sitemaps := parseRobots(body)
		out = append(out, recActive("well_known", "robots.txt", "http_probe",
			map[string]any{"present": true, "disallow_count": len(disallows), "sitemaps": sitemaps}, "GET /robots.txt"))
		out = append(out, urlRecords(domain, disallows, "robots.txt Disallow")...)
	} else {
		out = append(out, recActive("well_known", "robots.txt", "http_probe", map[string]any{"present": false}, "no robots.txt"))
	}

	// sitemap.xml — presence + a sample of listed URLs.
	if body, ok := wkGet(ctx, client, "https://"+domain+"/sitemap.xml"); ok {
		locs := parseSitemap(body)
		out = append(out, recActive("well_known", "sitemap.xml", "http_probe",
			map[string]any{"present": true, "url_count": len(locs)}, "GET /sitemap.xml"))
		out = append(out, urlRecords(domain, locs, "sitemap.xml")...)
	} else {
		out = append(out, recActive("well_known", "sitemap.xml", "http_probe", map[string]any{"present": false}, "no sitemap.xml"))
	}

	// security.txt — presence + contact (RFC 9116 location, then legacy root).
	body, ok := wkGet(ctx, client, "https://"+domain+"/.well-known/security.txt")
	if !ok {
		body, ok = wkGet(ctx, client, "https://"+domain+"/security.txt")
	}
	if ok {
		contact := ""
		if m := contactRe.FindStringSubmatch(body); m != nil {
			contact = clip(strings.TrimSpace(m[1]), 160)
		}
		out = append(out, recActive("well_known", "security.txt", "http_probe",
			map[string]any{"present": true, "contact": contact}, "GET security.txt"))
	} else {
		out = append(out, recActive("well_known", "security.txt", "http_probe", map[string]any{"present": false}, "no security.txt"))
	}

	return out, nil
}

// parseRobots extracts Disallow paths and declared Sitemap URLs from robots.txt.
func parseRobots(body string) (disallows, sitemaps []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"):
			p := strings.TrimSpace(line[len("disallow:"):])
			if p != "" && p != "/" && !seen[p] {
				seen[p] = true
				disallows = append(disallows, p)
			}
		case strings.HasPrefix(lower, "sitemap:"):
			sitemaps = append(sitemaps, strings.TrimSpace(line[len("sitemap:"):]))
		}
	}
	return disallows, sitemaps
}

// parseSitemap extracts the <loc> URLs/paths from a sitemap.xml body.
func parseSitemap(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range sitemapLocRe.FindAllStringSubmatch(body, -1) {
		loc := strings.TrimSpace(m[1])
		if loc != "" && !seen[loc] {
			seen[loc] = true
			out = append(out, loc)
		}
	}
	return out
}

// urlRecords turns discovered paths/URLs into capped `url` evidence records.
func urlRecords(domain string, items []string, evidence string) []db.AssetRecord {
	out := []db.AssetRecord{}
	keys := map[string]bool{}
	for _, it := range items {
		key := normalizeURLKey(domain, it)
		if key == "" || keys[key] || len(keys) >= wellKnownURLCap {
			continue
		}
		keys[key] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		out = append(out, recActive("url", k, "http_probe", map[string]any{"url": k}, evidence))
	}
	return out
}

// normalizeURLKey reduces a path or absolute URL to a "host/path" key scoped to
// the domain; off-scope absolute URLs are dropped, bare paths get the domain.
func normalizeURLKey(domain, item string) string {
	item = strings.TrimSpace(item)
	if item == "" {
		return ""
	}
	if strings.HasPrefix(item, "/") {
		return domain + item
	}
	// Absolute URL: keep only same-site ones.
	s := strings.TrimPrefix(strings.TrimPrefix(item, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		host := strings.ToLower(s[:i])
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return host + s[i:]
		}
	}
	return ""
}

func wellKnownClient() *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// wkGet fetches a well-known file, returning its (bounded) body on a 200.
func wkGet(ctx context.Context, client *http.Client, u string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "pahredar-easm")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return string(body), true
}
