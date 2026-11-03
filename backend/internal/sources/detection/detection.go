// Package detection reads free detection content that names CVEs:
//
//   - Sigma rules (SigmaHQ/sigma): log and SIEM detections, from the
//     repository archive. CVEs come from cve.* tags, the title, and the path.
//   - Suricata rules (Proofpoint ET Open): network signatures, from
//     emerging-all.rules. CVEs come from reference:cve options. Rules that
//     ship commented out (disabled by default) are kept and marked.
//   - Nmap NSE scripts: active checks, from scripts/script.db. CVEs come
//     from the script name (e.g. http-vuln-cve2017-5638).
package detection

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	SourceSigma    = "sigma"
	SourceSuricata = "suricata"
	SourceNmap     = "nmap"

	sigmaURL    = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
	suricataURL = "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"
	// The SVN mirror: raw.githubusercontent.com is intercepted on some networks.
	nmapURL = "https://svn.nmap.org/nmap/scripts/script.db"

	// maxRuleSize skips oversized files in the Sigma archive.
	maxRuleSize = 64 << 10
)

// Rule is one detection rule and the CVEs it names.
type Rule struct {
	RuleID string
	Title  string
	URL    string
	Body   string
	Meta   map[string]any
	CVEIDs []string
}

// Fetchers maps each source name to its fetch function.
var Fetchers = map[string]func(context.Context, *http.Client) ([]Rule, error){
	SourceSigma:    Sigma,
	SourceSuricata: Suricata,
	SourceNmap:     Nmap,
}

var (
	cveText   = regexp.MustCompile(`(?i)CVE[-_ ](\d{4})[-_](\d{4,7})(?:\D|$)`)
	cveTag    = regexp.MustCompile(`(?i)^cve\.(\d{4})[.-](\d{4,7})$`)
	cveScript = regexp.MustCompile(`(?i)cve-?(\d{4})-(\d{4,7})`)
)

// addCVE appends CVE-year-num to ids unless already present.
func addCVE(ids []string, year, num string) []string {
	id := "CVE-" + year + "-" + num
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

func textCVEs(ids []string, s string) []string {
	for _, m := range cveText.FindAllStringSubmatch(s, -1) {
		ids = addCVE(ids, m[1], m[2])
	}
	return ids
}

// Sigma reads every rule in the repository archive's rule folders.
// Deprecated and unsupported rules are skipped.
func Sigma(ctx context.Context, c *http.Client) ([]Rule, error) {
	resp, err := fetch.Get(ctx, c, sigmaURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseSigmaArchive(gz)
}

func parseSigmaArchive(r io.Reader) ([]Rule, error) {
	tr := tar.NewReader(r)
	var out []Rule
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		// Paths look like "sigma-master/rules/windows/...yml".
		_, path, _ := strings.Cut(h.Name, "/")
		if h.Typeflag != tar.TypeReg || h.Size > maxRuleSize || !strings.HasPrefix(path, "rules") || !strings.HasSuffix(path, ".yml") {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if rule, ok := parseSigma(path, string(body)); ok {
			out = append(out, rule)
		}
	}
}

// parseSigma reads the few top-level fields Pahredar shows. Sigma rules
// are flat enough that a line scanner is sufficient; the full YAML is kept
// as the body.
func parseSigma(path, body string) (Rule, bool) {
	meta := map[string]any{}
	var title, id, section string
	var cves, techniques []string
	logsource := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' && line[0] != '-' {
			key, val, _ := strings.Cut(line, ":")
			section, val = key, unquote(val)
			switch key {
			case "title":
				title = val
			case "id":
				id = val
			case "status", "level", "date", "modified", "author":
				if val != "" {
					meta[key] = val
				}
			}
			continue
		}
		item := strings.TrimSpace(line)
		switch section {
		case "tags":
			tag := unquote(strings.TrimPrefix(item, "-"))
			if m := cveTag.FindStringSubmatch(tag); m != nil {
				cves = addCVE(cves, m[1], m[2])
			} else if t, ok := strings.CutPrefix(strings.ToLower(tag), "attack.t"); ok {
				techniques = append(techniques, "T"+strings.ToUpper(t))
			}
		case "logsource":
			if k, v, ok := strings.Cut(item, ":"); ok && (k == "product" || k == "service" || k == "category") {
				logsource[k] = unquote(v)
			}
		}
	}
	cves = textCVEs(cves, title+" "+path)
	if len(cves) == 0 || title == "" {
		return Rule{}, false
	}
	if meta["status"] == "deprecated" || meta["status"] == "unsupported" {
		return Rule{}, false
	}
	if id == "" {
		id = path
	}
	if len(logsource) > 0 {
		meta["logsource"] = logsource
	}
	if len(techniques) > 0 {
		meta["attack"] = techniques
	}
	return Rule{
		RuleID: id, Title: title, Body: body, Meta: meta, CVEIDs: cves,
		URL: "https://github.com/SigmaHQ/sigma/blob/master/" + path,
	}, true
}

func unquote(s string) string {
	return strings.Trim(strings.TrimSpace(s), `'"`)
}

var (
	ruleMsg       = regexp.MustCompile(`msg:"((?:[^"\\]|\\.)*)"`)
	ruleSID       = regexp.MustCompile(`\bsid:\s*(\d+)\s*;`)
	ruleClass     = regexp.MustCompile(`\bclasstype:\s*([^;]+);`)
	ruleCVE       = regexp.MustCompile(`(?i)reference:\s*cve\s*,\s*(?:cve-)?(\d{4})-(\d{4,7})`)
	ruleMetaField = regexp.MustCompile(`\b(signature_severity|confidence|created_at|updated_at|attack_target|deployment) ([A-Za-z0-9_]+)`)
)

// Suricata reads ET Open's single-file ruleset.
func Suricata(ctx context.Context, c *http.Client) ([]Rule, error) {
	resp, err := fetch.Get(ctx, c, suricataURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parseSuricata(resp.Body)
}

func parseSuricata(r io.Reader) ([]Rule, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var out []Rule
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, "reference:cve") && !strings.Contains(line, "reference: cve") {
			continue
		}
		enabled := !strings.HasPrefix(line, "#")
		line = strings.TrimSpace(strings.TrimLeft(line, "#"))
		sid := ruleSID.FindStringSubmatch(line)
		msg := ruleMsg.FindStringSubmatch(line)
		if sid == nil || msg == nil {
			continue
		}
		var cves []string
		for _, m := range ruleCVE.FindAllStringSubmatch(line, -1) {
			cves = addCVE(cves, m[1], m[2])
		}
		if len(cves) == 0 {
			continue
		}
		meta := map[string]any{"enabled": enabled, "ruleset": "ET Open"}
		if cl := ruleClass.FindStringSubmatch(line); cl != nil {
			meta["classtype"] = strings.TrimSpace(cl[1])
		}
		for _, m := range ruleMetaField.FindAllStringSubmatch(line, -1) {
			meta[m[1]] = m[2]
		}
		out = append(out, Rule{RuleID: sid[1], Title: msg[1], Body: line, Meta: meta, CVEIDs: cves})
	}
	return out, sc.Err()
}

var scriptEntry = regexp.MustCompile(`filename = "([^"]+)\.nse", categories = \{([^}]*)\}`)

// Nmap reads the NSE script index and keeps scripts named after a CVE.
func Nmap(ctx context.Context, c *http.Client) ([]Rule, error) {
	resp, err := fetch.Get(ctx, c, nmapURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parseNmap(resp.Body)
}

func parseNmap(r io.Reader) ([]Rule, error) {
	sc := bufio.NewScanner(r)
	var out []Rule
	for sc.Scan() {
		m := scriptEntry.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var cves []string
		for _, c := range cveScript.FindAllStringSubmatch(m[1], -1) {
			cves = addCVE(cves, c[1], c[2])
		}
		if len(cves) == 0 {
			continue
		}
		var cats []string
		for _, c := range strings.Split(m[2], ",") {
			if c = unquote(c); c != "" {
				cats = append(cats, c)
			}
		}
		out = append(out, Rule{
			RuleID: m[1], Title: m[1], Body: m[1] + ".nse",
			URL:  "https://nmap.org/nsedoc/scripts/" + m[1] + ".html",
			Meta: map[string]any{"categories": cats}, CVEIDs: cves,
		})
	}
	return out, sc.Err()
}
