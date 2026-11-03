package scan

import (
	"context"
	"net/url"
	"regexp"
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

// probe is a path worth checking and a signature that confirms a real
// exposure (not just a 200 from a catch-all app).
type probe struct {
	path, signature, severity, title string
}

var probes = []probe{
	{"/.git/config", "[core]", SevHigh, "Exposed Git repository (.git/config)"},
	{"/.git/HEAD", "ref:", SevHigh, "Exposed Git repository (.git/HEAD)"},
	{"/.env", "=", SevCritical, "Exposed environment file (.env)"},
	{"/.DS_Store", "\x00\x00\x00\x01Bud1", SevLow, "Exposed .DS_Store"},
	{"/server-status", "Apache Server Status", SevMedium, "Apache server-status exposed"},
	{"/actuator/env", "\"propertySources\"", SevCritical, "Spring Boot actuator /env exposed"},
	{"/actuator/health", "\"status\"", SevLow, "Spring Boot actuator exposed"},
	{"/phpinfo.php", "phpinfo()", SevMedium, "phpinfo() exposed"},
	{"/.well-known/security.txt", "", SevGood, "security.txt published"},
	{"/wp-config.php.bak", "DB_PASSWORD", SevCritical, "WordPress config backup exposed"},
	{"/config.json", "", SevInfo, "config.json reachable"},
}

// checkPaths probes a small, fixed list of commonly exposed paths with plain
// GETs (no payloads) and flags the ones that are actually reachable.
func (sc *Scanner) checkPaths(ctx context.Context, base *url.URL, rep *Report, mu *sync.Mutex) {
	out := make([]PathOut, 0, len(probes))
	var lk sync.Mutex
	var wg sync.WaitGroup
	for _, p := range probes {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, body, err := sc.get(ctx, strings.TrimRight(base.String(), "/")+p.path)
			if err != nil {
				return
			}
			resp.Body.Close()
			exposed := resp.StatusCode == 200 && (p.signature == "" || strings.Contains(string(body), p.signature))
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
				rep.add(p.severity, "exposure", p.title, "The path "+p.path+" returns 200 and looks like a real file. It should not be reachable from the internet.")
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	mu.Lock()
	rep.Paths = out
	mu.Unlock()
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
