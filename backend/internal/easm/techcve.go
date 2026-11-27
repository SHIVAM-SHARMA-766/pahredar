package easm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

// Version→CVE assessment (spec A18 / §9 "version→CVE associations"): an active
// scan records the target's `Server` / `X-Powered-By` headers (e.g.
// "nginx/1.18.0"); this maps the detected product to Pahredar's CVE data and
// raises a finding when that product has known vulnerabilities. Matching is
// product-level (not version-precise), so findings are unverified — the operator
// confirms against the detected version. This connects the EASM surface to
// Pahredar's core CVE/KEV/EPSS engine, the platform's whole point.

// techProduct is a server-header token mapped to a Pahredar product.
type techProduct struct {
	Name, Vendor, Product string
}

// serverProducts maps a lower-cased Server/X-Powered-By token to its canonical
// Pahredar product (mirrors the scanner's fingerprint table). Products absent
// here (and CDNs) are not looked up.
var serverProducts = map[string]techProduct{
	"nginx":         {"nginx", "f5", "nginx"},
	"apache":        {"Apache httpd", "apache", "http_server"},
	"php":           {"PHP", "php", "php"},
	"openssl":       {"OpenSSL", "openssl", "openssl"},
	"microsoft-iis": {"Microsoft IIS", "microsoft", "internet_information_services"},
	"apache-coyote": {"Apache Tomcat", "apache", "tomcat"},
	"litespeed":     {"LiteSpeed", "litespeedtech", "litespeed_web_server"},
}

// parseTechToken maps a Server/X-Powered-By token ("nginx/1.18.0") to a known
// product and its version. ok is false for CDNs and unrecognised products.
func parseTechToken(tok string) (p techProduct, version string, ok bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return techProduct{}, "", false
	}
	name, ver, _ := strings.Cut(tok, "/")
	p, ok = serverProducts[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return techProduct{}, "", false
	}
	return p, strings.TrimSpace(ver), true
}

// techSeverity grades a product-level CVE match: KEV present → high, else a
// critical CVE → medium, else any CVE → low.
func techSeverity(c *scan.TechCVEs) string {
	switch {
	case c == nil || c.Total == 0:
		return ""
	case c.KEV > 0:
		return "high"
	case c.Critical > 0:
		return "medium"
	default:
		return "low"
	}
}

// techCVEFindings reads an asset's http records, maps detected server software to
// Pahredar's CVE data, and returns a finding per vulnerable product. DB-backed
// (MatchTech), so it is not part of the pure buildFindings.
func (s *Service) techCVEFindings(ctx context.Context, assetID int64, records []db.AssetRecord) []db.Alert {
	// Collect product→version from the http records' Server / X-Powered-By.
	versions := map[string]string{} // product key → detected version
	seen := map[string]techProduct{}
	for _, rec := range records {
		if rec.Category != "http" {
			continue
		}
		var d struct {
			Server    string `json:"server"`
			PoweredBy string `json:"powered_by"`
		}
		if json.Unmarshal(rec.Data, &d) != nil {
			continue
		}
		for _, raw := range []string{d.Server, d.PoweredBy} {
			for _, tok := range strings.Fields(raw) {
				if p, ver, ok := parseTechToken(tok); ok {
					seen[p.Product] = p
					if ver != "" {
						versions[p.Product] = ver
					}
				}
			}
		}
	}

	var findings []db.Alert
	for productKey, p := range seen {
		c, err := s.Store.MatchTech(ctx, p.Vendor, p.Product)
		if err != nil {
			continue // no product_stats row → nothing known
		}
		sev := techSeverity(c)
		if sev == "" {
			continue
		}
		ver := versions[productKey]
		label := p.Name
		if ver != "" {
			label += " " + ver
		}
		title := fmt.Sprintf("%s — %d known CVEs", label, c.Total)
		if c.KEV > 0 {
			title += fmt.Sprintf(", %d in KEV", c.KEV)
		} else if c.Critical > 0 {
			title += fmt.Sprintf(", %d critical", c.Critical)
		}
		detail := fmt.Sprintf(
			"The server exposes %s. Pahredar tracks %d CVEs for %s/%s (%d KEV, %d critical). "+
				"This match is product-level — confirm each CVE against the detected version %q, then patch or upgrade.",
			label, c.Total, c.Vendor, c.Product, c.KEV, c.Critical, ver)
		if len(c.Examples) > 0 {
			ids := make([]string, 0, len(c.Examples))
			for _, e := range c.Examples {
				ids = append(ids, e.ID)
			}
			detail += " Examples: " + strings.Join(ids, ", ") + "."
		}
		id := assetID
		findings = append(findings, db.Alert{
			Type: "easm", AssetID: &id, CVEID: "tech:" + p.Product,
			Severity: sev, Title: title, Detail: detail,
		})
	}
	return findings
}
