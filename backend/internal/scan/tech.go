package scan

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// TechOut is one detected technology and the CVEs Pahredar knows for it.
type TechOut struct {
	Name    string    `json:"name"`
	Version string    `json:"version,omitempty"`
	From    string    `json:"from"` // where it was detected
	CVEs    *TechCVEs `json:"cves,omitempty"`
}

// TechCVEs is a product's CVE counts from Pahredar's data. It is
// product-level, not matched to the detected version.
type TechCVEs struct {
	Vendor   string    `json:"vendor"`
	Product  string    `json:"product"`
	Total    int       `json:"total"`
	KEV      int       `json:"kev"`
	Critical int       `json:"critical"`
	Examples []TechCVE `json:"examples"`
}

type TechCVE struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	KEV      bool   `json:"kev"`
}

// detector finds a technology in the response. productKey is the canonical
// key to match against Pahredar's products ("" means do not look up CVEs).
type tech struct {
	name, version, vendor, product, from string
}

var (
	reGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reScriptVer = regexp.MustCompile(`(?i)/([a-z][a-z0-9_.-]*?)[-/](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js`)
	reVersion   = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
)

// knownScripts maps a library seen in a script URL to its canonical product.
var knownScripts = map[string]tech{
	"jquery":    {name: "jQuery", vendor: "jquery", product: "jquery"},
	"bootstrap": {name: "Bootstrap", vendor: "getbootstrap", product: "bootstrap"},
	"angular":   {name: "Angular", vendor: "angular", product: "angular"},
	"vue":       {name: "Vue.js", vendor: "vuejs", product: "vue"},
	"react":     {name: "React", vendor: "facebook", product: "react"},
	"lodash":    {name: "Lodash", vendor: "lodash", product: "lodash"},
	"moment":    {name: "Moment.js", vendor: "momentjs", product: "moment"},
}

// fingerprint detects technologies from the response headers, cookies, and
// body, then looks up each one's CVEs.
func (sc *Scanner) fingerprint(ctx context.Context, resp *http.Response, body []byte, mu *sync.Mutex, rep *Report) []TechOut {
	found := map[string]tech{}
	add := func(t tech) {
		key := strings.ToLower(t.name)
		if cur, ok := found[key]; !ok || (cur.version == "" && t.version != "") {
			found[key] = t
		}
	}

	// Server and X-Powered-By headers: "nginx/1.18.0", "PHP/7.4.3".
	for _, hv := range []struct{ h, from string }{{"Server", "Server header"}, {"X-Powered-By", "X-Powered-By header"}, {"X-Generator", "X-Generator header"}} {
		for _, part := range strings.Split(resp.Header.Get(hv.h), " ") {
			if t, ok := serverToken(part); ok {
				t.from = hv.from
				add(t)
			}
		}
	}
	if v := resp.Header.Get("X-AspNet-Version"); v != "" {
		add(tech{name: "ASP.NET", version: v, vendor: "microsoft", product: ".net_framework", from: "X-AspNet-Version header"})
	}
	// Meta generator: "WordPress 6.2", "Drupal 10".
	if m := reGenerator.FindSubmatch(body); m != nil {
		if t, ok := generatorToken(string(m[1])); ok {
			t.from = "meta generator"
			add(t)
		}
	}
	// WordPress and Drupal paths in the HTML.
	bodyStr := string(body)
	if strings.Contains(bodyStr, "/wp-content/") || strings.Contains(bodyStr, "/wp-includes/") {
		add(tech{name: "WordPress", vendor: "wordpress", product: "wordpress", from: "wp-content path"})
	}
	// JS libraries in script URLs.
	for _, m := range reScriptVer.FindAllStringSubmatch(bodyStr, -1) {
		lib := strings.ToLower(strings.TrimSuffix(m[1], ".min"))
		if base, ok := knownScripts[lib]; ok {
			base.version = m[2]
			base.from = "script URL"
			add(base)
		}
	}

	out := make([]TechOut, 0, len(found))
	var lk sync.Mutex
	var wg sync.WaitGroup
	for _, t := range found {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := TechOut{Name: t.name, Version: t.version, From: t.from}
			if t.product != "" && sc.matcher != nil {
				if c, err := sc.matcher.MatchTech(ctx, t.vendor, t.product); err == nil {
					o.CVEs = c
				}
			}
			lk.Lock()
			out = append(out, o)
			lk.Unlock()
		}()
	}
	wg.Wait()

	// Findings: a detected product that is in KEV, and version disclosure.
	mu.Lock()
	for _, o := range out {
		if o.CVEs != nil && o.CVEs.KEV > 0 {
			rep.add(SevInfo, "tech", o.Name+": "+itoa(o.CVEs.KEV)+" known-exploited CVEs for this product", "Pahredar lists "+itoa(o.CVEs.Total)+" CVEs for "+o.CVEs.Product+" overall. Confirm the running version against them.")
		}
	}
	if resp.Header.Get("Server") != "" && reVersion.MatchString(resp.Header.Get("Server")) {
		rep.add(SevInfo, "tech", "Server version disclosed", "The Server header reveals the exact version ("+resp.Header.Get("Server")+"), which helps an attacker pick exploits. Consider hiding the version.")
	}
	mu.Unlock()
	return out
}

// serverToken parses a "product/version" header token into a tech.
func serverToken(tok string) (tech, bool) {
	name, ver, _ := strings.Cut(tok, "/")
	switch strings.ToLower(name) {
	case "nginx":
		return tech{name: "nginx", version: ver, vendor: "f5", product: "nginx"}, true
	case "apache":
		return tech{name: "Apache httpd", version: ver, vendor: "apache", product: "http_server"}, true
	case "php":
		return tech{name: "PHP", version: ver, vendor: "php", product: "php"}, true
	case "openssl":
		return tech{name: "OpenSSL", version: ver, vendor: "openssl", product: "openssl"}, true
	case "microsoft-iis":
		return tech{name: "Microsoft IIS", version: ver, vendor: "microsoft", product: "internet_information_services"}, true
	case "apache-coyote":
		return tech{name: "Apache Tomcat", version: ver, vendor: "apache", product: "tomcat"}, true
	case "litespeed":
		return tech{name: "LiteSpeed", version: ver, vendor: "litespeedtech", product: "litespeed_web_server"}, true
	case "cloudflare", "cloudfront", "akamaighost":
		return tech{name: name, from: ""}, true // CDN, no product CVE lookup
	}
	return tech{}, false
}

func generatorToken(s string) (tech, bool) {
	l := strings.ToLower(s)
	ver := ""
	if m := reVersion.FindString(s); m != "" {
		ver = m
	}
	switch {
	case strings.HasPrefix(l, "wordpress"):
		return tech{name: "WordPress", version: ver, vendor: "wordpress", product: "wordpress"}, true
	case strings.HasPrefix(l, "drupal"):
		return tech{name: "Drupal", version: ver, vendor: "drupal", product: "drupal"}, true
	case strings.HasPrefix(l, "joomla"):
		return tech{name: "Joomla", version: ver, vendor: "joomla", product: "joomla!"}, true
	case strings.HasPrefix(l, "typo3"):
		return tech{name: "TYPO3", version: ver, vendor: "typo3", product: "typo3"}, true
	}
	return tech{}, false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
