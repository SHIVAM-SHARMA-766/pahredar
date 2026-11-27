package easm

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// jsAnalysis fetches the root page, inventories its same-site JavaScript, checks
// whether each script's source map is exposed (a code-leak), and extracts API
// endpoint references from the HTML and scripts (A11). method=active, bounded.
type jsAnalysis struct{}

func (jsAnalysis) Name() string { return "js_analysis" }

const (
	jsScriptCap  = 10 // scripts inventoried
	jsFetchCap   = 5  // scripts fetched for source-map + endpoint scan
	jsAPIPathCap = 60 // API path references stored
)

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	apiPathRe   = regexp.MustCompile(`["'](/(?:api|v\d+|graphql|rest|internal)[A-Za-z0-9._/\-]*)["']`)
)

func (jsAnalysis) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	client := wellKnownClient()
	html, ok := wkGet(ctx, client, "https://"+domain)
	if !ok {
		return nil, nil
	}

	scripts := sameSiteScripts(domain, html)
	apiPaths := map[string]bool{}
	for _, p := range extractAPIPaths(html) {
		apiPaths[domain+p] = true
	}

	out := []db.AssetRecord{}
	for i, src := range scripts {
		if i >= jsScriptCap {
			break
		}
		data := map[string]any{"url": src}
		if i < jsFetchCap {
			// Source-map exposure: <script>.map served → the original source is
			// downloadable. Also mine the script body for API endpoints.
			if body, ok := wkGet(ctx, client, "https://"+src+".map"); ok && looksLikeSourceMap(body) {
				data["source_map_exposed"] = true
			}
			if body, ok := wkGet(ctx, client, "https://"+src); ok {
				for _, p := range extractAPIPaths(body) {
					apiPaths[domain+p] = true
				}
			}
		}
		out = append(out, recActive("script", src, "http_probe", data, "page script"))
	}

	paths := make([]string, 0, len(apiPaths))
	for p := range apiPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for i, p := range paths {
		if i >= jsAPIPathCap {
			break
		}
		out = append(out, recActive("url", p, "js_analysis", map[string]any{"url": p, "kind": "api_reference"}, "endpoint referenced in page/script"))
	}
	return out, nil
}

// sameSiteScripts returns the host+path of each same-site <script src> in the
// HTML, deduped. Off-site CDNs are dropped (we only inventory our own code).
func sameSiteScripts(domain, html string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		if key := scriptKey(domain, m[1]); key != "" && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// scriptKey resolves a script src to a same-site "host/path" key, or "".
func scriptKey(domain, src string) string {
	src = strings.TrimSpace(src)
	switch {
	case src == "" || strings.HasPrefix(src, "data:"):
		return ""
	case strings.HasPrefix(src, "//"):
		src = "https:" + src
	case strings.HasPrefix(src, "/"):
		return domain + src
	case !strings.Contains(src, "://"):
		return domain + "/" + strings.TrimPrefix(src, "./")
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return host + u.EscapedPath()
	}
	return ""
}

// extractAPIPaths pulls quoted API-looking paths (/api, /v1, /graphql, …) out of
// a text body.
func extractAPIPaths(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range apiPathRe.FindAllStringSubmatch(text, -1) {
		p := m[1]
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// looksLikeSourceMap reports whether a body is a JS source map (not a 200 error
// page served for a missing .map).
func looksLikeSourceMap(body string) bool {
	b := strings.TrimSpace(body)
	return strings.HasPrefix(b, "{") && strings.Contains(b, `"version"`) &&
		(strings.Contains(b, `"mappings"`) || strings.Contains(b, `"sources"`))
}
