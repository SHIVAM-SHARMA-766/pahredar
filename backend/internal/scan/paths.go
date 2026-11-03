package scan

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// PathOut is one probed path and whether it is exposed.
type PathOut struct {
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Exposed bool   `json:"exposed"`
}

// Related holds extra resources found around the endpoint.
type Related struct {
	SecurityTxt bool     `json:"security_txt"`
	Contacts    []string `json:"contacts"`
	Subdomains  []string `json:"subdomains"` // from the certificate SANs
	Assets      []string `json:"assets"`     // external hosts serving scripts/styles
	Disallowed  []string `json:"disallowed"` // robots.txt Disallow entries
}

// probe is a path worth checking. signature (a substring) and re (a stronger
// pattern) confirm the response is the real file; jsonLike/textOnly guard
// against a single-page app that returns its HTML shell with 200 for every
// path (the usual source of false positives).
type probe struct {
	path, signature, severity, title string
	re                               *regexp.Regexp
}

var (
	reEnvLine  = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]*=`)
	reRandPath = "/pahredar-probe-9f3a7c1e2b"
)

var probes = []probe{
	{path: "/.git/config", signature: "[core]", severity: SevHigh, title: "Exposed Git repository (.git/config)"},
	{path: "/.git/HEAD", signature: "ref:", severity: SevHigh, title: "Exposed Git repository (.git/HEAD)"},
	{path: "/.env", severity: SevCritical, title: "Exposed environment file (.env)", re: reEnvLine},
	{path: "/.DS_Store", signature: "\x00\x00\x00\x01Bud1", severity: SevLow, title: "Exposed .DS_Store"},
	{path: "/server-status", signature: "Apache Server Status", severity: SevMedium, title: "Apache server-status exposed"},
	{path: "/actuator/env", signature: "\"propertySources\"", severity: SevCritical, title: "Spring Boot actuator /env exposed"},
	{path: "/actuator/health", signature: "\"status\"", severity: SevLow, title: "Spring Boot actuator exposed"},
	{path: "/phpinfo.php", signature: "phpinfo()", severity: SevMedium, title: "phpinfo() exposed"},
	{path: "/.well-known/security.txt", signature: "ontact", severity: SevGood, title: "security.txt published"},
	{path: "/wp-config.php.bak", signature: "DB_PASSWORD", severity: SevCritical, title: "WordPress config backup exposed"},
	{path: "/config.json", signature: "{", severity: SevInfo, title: "config.json reachable"},
}

// baseline is how the server answers a path that certainly does not exist. A
// probe whose response matches this is a catch-all (e.g. an SPA serving
// index.html for everything), not a real exposure.
type baseline struct {
	status int
	ctype  string
	length int
	ok     bool
}

func normType(resp *http.Response) string {
	ct := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// matchesBaseline reports whether this response looks like the server's
// catch-all answer rather than a distinct file.
func (b baseline) matches(resp *http.Response, bodyLen int) bool {
	if !b.ok || resp.StatusCode != b.status {
		return false
	}
	if normType(resp) != b.ctype {
		return false
	}
	// Same status and content type: treat near-equal body sizes as the same
	// generated page (SPA shells vary slightly between paths).
	d := bodyLen - b.length
	if d < 0 {
		d = -d
	}
	return b.length == 0 || d*20 <= b.length // within 5%
}

// checkPaths probes a small, fixed list of commonly exposed paths with plain
// GETs (no payloads) and flags the ones that are actually reachable, after
// filtering out catch-all responses and the SPA HTML shell.
func (sc *Scanner) checkPaths(ctx context.Context, base *url.URL, rep *Report, mu *sync.Mutex) {
	root := strings.TrimRight(base.String(), "/")

	// Establish the catch-all baseline from a path that cannot exist.
	var bl baseline
	if resp, body, err := sc.get(ctx, root+reRandPath); err == nil {
		bl = baseline{status: resp.StatusCode, ctype: normType(resp), length: len(body), ok: true}
		resp.Body.Close()
	}

	out := make([]PathOut, 0, len(probes))
	var lk sync.Mutex
	var wg sync.WaitGroup
	for _, p := range probes {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, body, err := sc.get(ctx, root+p.path)
			if err != nil {
				return
			}
			resp.Body.Close()
			exposed := pathExposed(p, resp, body, bl)
			lk.Lock()
			out = append(out, PathOut{Path: p.path, Status: resp.StatusCode, Exposed: exposed})
			lk.Unlock()
			if !exposed {
				return
			}
			mu.Lock()
			if p.severity == SevGood {
				rep.add(SevGood, "exposure", p.title, "")
			} else {
				rep.add(p.severity, "exposure", p.title, "GET "+p.path+" → "+resp.Status+" ("+normType(resp)+", "+byteLen(len(body))+"); the response matches a real file, so it is reachable from the internet and should not be.")
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	mu.Lock()
	rep.Paths = out
	mu.Unlock()
}

// pathExposed decides whether a probe response is a genuine exposure.
func pathExposed(p probe, resp *http.Response, body []byte, bl baseline) bool {
	if resp.StatusCode != 200 {
		return false
	}
	// Catch-all / SPA shell: identical to the non-existent-path response.
	if bl.matches(resp, len(body)) {
		return false
	}
	// Sensitive files are not HTML; an HTML body is almost always the app shell.
	if ct := normType(resp); strings.HasPrefix(ct, "text/html") && p.severity != SevGood {
		return false
	}
	if p.re != nil {
		return p.re.Match(body)
	}
	if p.signature != "" {
		return strings.Contains(string(body), p.signature)
	}
	return true
}

func byteLen(n int) string {
	switch {
	case n >= 1<<20:
		return strconv.Itoa(n/(1<<20)) + " MB"
	case n >= 1<<10:
		return strconv.Itoa(n/(1<<10)) + " KB"
	default:
		return strconv.Itoa(n) + " B"
	}
}

// checkRelated gathers security.txt contacts, certificate SAN subdomains,
// external asset hosts from the page, and robots.txt Disallow entries.
func (sc *Scanner) checkRelated(ctx context.Context, host string, base *url.URL, body []byte, rep *Report, mu *sync.Mutex) {
	rel := &Related{Contacts: []string{}, Subdomains: []string{}, Assets: []string{}, Disallowed: []string{}}

	if resp, b, err := sc.get(ctx, strings.TrimRight(base.String(), "/")+"/.well-known/security.txt"); err == nil {
		if resp.StatusCode == 200 {
			rel.SecurityTxt = true
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.ToLower(line), "contact:") {
					rel.Contacts = append(rel.Contacts, strings.TrimSpace(line[len("contact:"):]))
				}
			}
		}
		resp.Body.Close()
	}
	if resp, b, err := sc.get(ctx, strings.TrimRight(base.String(), "/")+"/robots.txt"); err == nil {
		if resp.StatusCode == 200 {
			seen := map[string]bool{}
			for _, line := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(line)), "disallow:"); ok {
					v = strings.TrimSpace(v)
					if v != "" && v != "/" && !seen[v] && len(rel.Disallowed) < 25 {
						seen[v] = true
						rel.Disallowed = append(rel.Disallowed, v)
					}
				}
			}
		}
		resp.Body.Close()
	}

	// Subdomains from the certificate SANs recorded by the TLS check.
	mu.Lock()
	if rep.TLS != nil {
		seen := map[string]bool{}
		for _, san := range rep.TLS.SANs {
			san = strings.TrimPrefix(san, "*.")
			if san != host && strings.HasSuffix(san, baseDomain(host)) && !seen[san] {
				seen[san] = true
				rel.Subdomains = append(rel.Subdomains, san)
			}
		}
	}
	mu.Unlock()

	// External asset hosts from script/link URLs.
	seen := map[string]bool{}
	for _, m := range reAssetURL.FindAllStringSubmatch(string(body), -1) {
		if u, err := url.Parse(m[1]); err == nil && u.Host != "" && u.Hostname() != host && !seen[u.Hostname()] {
			seen[u.Hostname()] = true
			if len(rel.Assets) < 20 {
				rel.Assets = append(rel.Assets, u.Hostname())
			}
		}
	}

	mu.Lock()
	rep.Related = rel
	mu.Unlock()
}

var reAssetURL = regexp.MustCompile(`(?i)(?:src|href)=["'](https?://[^"']+\.(?:js|css))["']`)

func baseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// clip trims a string to n runes with an ellipsis (shared with other files
// via package scope; defined once here).
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
