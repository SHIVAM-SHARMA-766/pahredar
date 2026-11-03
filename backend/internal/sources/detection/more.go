package detection

// More free detection content that names CVEs:
//
//   - Splunk security_content (Apache-2.0): SPL detections with a cve tag
//     list, data sources, and ATT&CK techniques.
//   - Elastic detection-rules (Elastic License v2): EQL / KQL / ES|QL rules
//     for the Elastic stack.
//   - Snort 3 community rules (GPLv2): network signatures with
//     reference:cve options; commented-out rules are kept and marked.
//   - YARA rules from Florian Roth's signature-base (Detection Rule License
//     1.1): file and memory signatures for exploit tools and webshells.
//
// Only rules that name a CVE are kept. GitHub repositories are read as
// codeload tarballs, like Sigma.

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
	"go.yaml.in/yaml/v3"
)

const (
	SourceSplunk  = "splunk"
	SourceElastic = "elastic"
	SourceSnort   = "snort"
	SourceYARA    = "yara"

	splunkURL  = "https://codeload.github.com/splunk/security_content/tar.gz/refs/heads/develop"
	elasticURL = "https://codeload.github.com/elastic/detection-rules/tar.gz/refs/heads/main"
	snortURL   = "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
	yaraURL    = "https://codeload.github.com/Neo23x0/signature-base/tar.gz/refs/heads/master"
)

func init() {
	Fetchers[SourceSplunk] = Splunk
	Fetchers[SourceElastic] = Elastic
	Fetchers[SourceSnort] = Snort
	Fetchers[SourceYARA] = YARA
}

// walkTarball streams a .tar.gz and calls fn for each regular file of at
// most maxSize bytes whose path (without the archive's top folder) keep
// accepts.
func walkTarball(ctx context.Context, c *http.Client, url string, maxSize int64, keep func(path string) bool, fn func(path string, body []byte) error) error {
	resp, err := fetch.Get(ctx, c, url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	return walkTar(gz, maxSize, keep, fn)
}

func walkTar(r io.Reader, maxSize int64, keep func(string) bool, fn func(string, []byte) error) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		_, path, _ := strings.Cut(h.Name, "/")
		if h.Typeflag != tar.TypeReg || h.Size > maxSize || !keep(path) {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := fn(path, body); err != nil {
			return err
		}
	}
}

func emptyErr(source string, n int) error {
	if n == 0 {
		return fmt.Errorf("%s: no rules naming a CVE found; the archive layout may have changed", source)
	}
	return nil
}

// --- Splunk -------------------------------------------------------------------

type splunkDetection struct {
	Name           string   `yaml:"name"`
	ID             string   `yaml:"id"`
	Type           string   `yaml:"type"`
	Status         string   `yaml:"status"`
	Description    string   `yaml:"description"`
	Search         string   `yaml:"search"`
	HowToImplement string   `yaml:"how_to_implement"`
	DataSource     []string `yaml:"data_source"`
	References     []string `yaml:"references"`
	Tags           struct {
		CVE           []string `yaml:"cve"`
		MitreAttackID []string `yaml:"mitre_attack_id"`
	} `yaml:"tags"`
}

func Splunk(ctx context.Context, c *http.Client) ([]Rule, error) {
	var out []Rule
	err := walkTarball(ctx, c, splunkURL, maxRuleSize,
		func(p string) bool {
			return strings.HasPrefix(p, "detections/") && !strings.HasPrefix(p, "detections/deprecated/") && strings.HasSuffix(p, ".yml")
		},
		func(p string, body []byte) error {
			if r, ok := parseSplunk(p, body); ok {
				out = append(out, r)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, emptyErr(SourceSplunk, len(out))
}

func parseSplunk(path string, body []byte) (Rule, bool) {
	var d splunkDetection
	if yaml.Unmarshal(body, &d) != nil || d.ID == "" || d.Search == "" || strings.EqualFold(d.Status, "deprecated") {
		return Rule{}, false
	}
	var cves []string
	for _, t := range d.Tags.CVE {
		cves = textCVEs(cves, t+" ")
	}
	cves = textCVEs(cves, d.Name+" "+d.Description+" ")
	meta := map[string]any{"type": d.Type, "status": d.Status, "license": "Apache-2.0"}
	if len(cves) == 0 {
		// A behaviour detection whose write-up cites the CVE (PrintNightmare's
		// spoolsv rules); shown as related rather than CVE-specific.
		if cves = textCVEs(nil, strings.Join(d.References, " ")+" "); len(cves) == 0 {
			return Rule{}, false
		}
		meta["related"] = true
	}
	if len(d.DataSource) > 0 {
		meta["data_source"] = d.DataSource
	}
	if len(d.Tags.MitreAttackID) > 0 {
		meta["attack"] = d.Tags.MitreAttackID
	}
	if s := strings.TrimSpace(d.HowToImplement); s != "" {
		meta["how_to_implement"] = truncate(s, 600)
	}
	if s := strings.TrimSpace(d.Description); s != "" {
		meta["description"] = truncate(s, 600)
	}
	return Rule{
		RuleID: d.ID, Title: strings.TrimSpace(d.Name), Body: strings.TrimSpace(d.Search), Meta: meta, CVEIDs: cves,
		URL: "https://github.com/splunk/security_content/blob/develop/" + path,
	}, true
}

// --- Elastic ------------------------------------------------------------------

type elasticFile struct {
	Metadata struct {
		Maturity string `toml:"maturity"`
	} `toml:"metadata"`
	Rule struct {
		RuleID      string   `toml:"rule_id"`
		Name        string   `toml:"name"`
		Description string   `toml:"description"`
		Language    string   `toml:"language"`
		Type        string   `toml:"type"`
		Severity    string   `toml:"severity"`
		RiskScore   int      `toml:"risk_score"`
		Query       string   `toml:"query"`
		Index       []string `toml:"index"`
		References  []string `toml:"references"`
		Tags        []string `toml:"tags"`
		Threat      []struct {
			Technique []struct {
				ID string `toml:"id"`
			} `toml:"technique"`
		} `toml:"threat"`
	} `toml:"rule"`
}

func Elastic(ctx context.Context, c *http.Client) ([]Rule, error) {
	var out []Rule
	err := walkTarball(ctx, c, elasticURL, maxRuleSize,
		func(p string) bool {
			return strings.HasPrefix(p, "rules") && !strings.Contains(p, "/_deprecated/") && strings.HasSuffix(p, ".toml")
		},
		func(p string, body []byte) error {
			if r, ok := parseElastic(p, body); ok {
				out = append(out, r)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, emptyErr(SourceElastic, len(out))
}

func parseElastic(path string, body []byte) (Rule, bool) {
	var f elasticFile
	if _, err := toml.Decode(string(body), &f); err != nil || f.Rule.RuleID == "" || f.Metadata.Maturity == "deprecated" {
		return Rule{}, false
	}
	r := f.Rule
	cves := textCVEs(nil, r.Name+" "+r.Description+" "+strings.Join(r.Tags, " ")+" ")
	meta := map[string]any{"language": r.Language, "type": r.Type, "severity": r.Severity, "risk_score": r.RiskScore, "license": "Elastic License v2"}
	if len(cves) == 0 {
		// Only the references cite a CVE: related, not CVE-specific.
		if cves = textCVEs(nil, strings.Join(r.References, " ")+" "); len(cves) == 0 {
			return Rule{}, false
		}
		meta["related"] = true
	}
	if len(r.Index) > 0 {
		meta["index"] = r.Index
	}
	var techniques []string
	for _, t := range r.Threat {
		for _, x := range t.Technique {
			techniques = append(techniques, x.ID)
		}
	}
	if len(techniques) > 0 {
		meta["attack"] = techniques
	}
	if s := strings.TrimSpace(r.Description); s != "" {
		meta["description"] = truncate(s, 600)
	}
	query := strings.TrimSpace(r.Query)
	if query == "" {
		// Machine-learning and threshold rules have no query to show.
		query = "(" + r.Type + " rule; open it in Kibana)"
	}
	return Rule{
		RuleID: r.RuleID, Title: strings.TrimSpace(r.Name), Body: query, Meta: meta, CVEIDs: cves,
		URL: "https://github.com/elastic/detection-rules/blob/main/" + path,
	}, true
}

// --- Snort 3 ------------------------------------------------------------------

var (
	snortMsg      = regexp.MustCompile(`msg:\s*"([^"]*)"`)
	snortSID      = regexp.MustCompile(`\bsid:\s*(\d+)`)
	snortClass    = regexp.MustCompile(`classtype:\s*([\w-]+)`)
	snortCVE      = regexp.MustCompile(`reference:\s*cve,\s*(\d{4})-(\d{4,7})`)
	snortRuleLine = regexp.MustCompile(`^#?\s*(alert|drop|block|reject)\s`)
)

func Snort(ctx context.Context, c *http.Client) ([]Rule, error) {
	var out []Rule
	err := walkTarball(ctx, c, snortURL, 16<<20,
		func(p string) bool { return strings.HasSuffix(p, ".rules") },
		func(_ string, body []byte) error {
			rules, err := parseSnort(strings.NewReader(string(body)))
			out = append(out, rules...)
			return err
		})
	if err != nil {
		return nil, err
	}
	return out, emptyErr(SourceSnort, len(out))
}

func parseSnort(r io.Reader) ([]Rule, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []Rule
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !snortRuleLine.MatchString(line) {
			continue
		}
		var cves []string
		for _, m := range snortCVE.FindAllStringSubmatch(line, -1) {
			cves = addCVE(cves, m[1], m[2])
		}
		sid := snortSID.FindStringSubmatch(line)
		if len(cves) == 0 || sid == nil {
			continue
		}
		enabled := !strings.HasPrefix(line, "#")
		body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		meta := map[string]any{"enabled": enabled, "license": "GPL-2.0"}
		if m := snortClass.FindStringSubmatch(line); m != nil {
			meta["classtype"] = m[1]
		}
		title := ""
		if m := snortMsg.FindStringSubmatch(line); m != nil {
			title = m[1]
		}
		out = append(out, Rule{RuleID: sid[1], Title: title, Body: body, Meta: meta, CVEIDs: cves, URL: "https://www.snort.org/rule_docs/1-" + sid[1]})
	}
	return out, sc.Err()
}

// --- YARA ---------------------------------------------------------------------

var (
	yaraStart  = regexp.MustCompile(`(?m)^[ \t]*(?:(?:private|global)\s+)*rule\s+(\w+)`)
	yaraImport = regexp.MustCompile(`(?m)^\s*import\s+"(\w+)"`)
	yaraWord   = regexp.MustCompile(`\b\w+\b`)
	yaraMeta   = regexp.MustCompile(`(?m)^\s*(description|author|reference|score|date)\s*=\s*"?([^"\n]*)"?`)
)

func YARA(ctx context.Context, c *http.Client) ([]Rule, error) {
	var out []Rule
	seen := map[string]bool{}
	err := walkTarball(ctx, c, yaraURL, 4<<20,
		func(p string) bool {
			return strings.HasPrefix(p, "yara/") && (strings.HasSuffix(p, ".yar") || strings.HasSuffix(p, ".yara"))
		},
		func(p string, body []byte) error {
			// Rule names are the key; the first file defining one wins.
			for _, r := range parseYARA(p, string(body)) {
				if !seen[r.RuleID] {
					seen[r.RuleID] = true
					out = append(out, r)
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, emptyErr(SourceYARA, len(out))
}

// parseYARA splits a file at each rule declaration; a rule's text runs to
// the next declaration. Braces are not counted: hex strings contain them.
// A rule cut out of its file still needs the file's imports it uses
// (meta.imports) and the other rules of the file its condition names
// (meta.requires, their texts with dependencies first), or it will not
// compile on its own.
func parseYARA(path, text string) []Rule {
	starts := yaraStart.FindAllStringSubmatchIndex(text, -1)
	var imports []string
	for _, m := range yaraImport.FindAllStringSubmatch(text, -1) {
		imports = append(imports, m[1])
	}
	blocks := map[string]string{}
	var names []string
	for i, s := range starts {
		end := len(text)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		name := text[s[2]:s[3]]
		blocks[name] = strings.TrimSpace(text[s[0]:end])
		names = append(names, name)
	}
	var out []Rule
	for _, name := range names {
		block := blocks[name]
		meta := map[string]any{"file": path, "license": "DRL-1.1"}
		desc := ""
		for _, m := range yaraMeta.FindAllStringSubmatch(block, -1) {
			if _, seen := meta[m[1]]; !seen {
				meta[m[1]] = strings.TrimSpace(m[2])
			}
			if m[1] == "description" && desc == "" {
				desc = strings.TrimSpace(m[2])
			}
		}
		cves := textCVEs(nil, name+" "+desc+" ")
		if len(cves) == 0 {
			continue
		}
		title := desc
		if title == "" {
			title = name
		}
		meta["name"] = name
		var used []string
		for _, imp := range imports {
			if strings.Contains(block, imp+".") {
				used = append(used, imp)
			}
		}
		requires := yaraRequires(name, blocks)
		for _, b := range requires {
			for _, imp := range imports {
				if strings.Contains(b, imp+".") && !containsString(used, imp) {
					used = append(used, imp)
				}
			}
		}
		if len(used) > 0 {
			meta["imports"] = used
		}
		if len(requires) > 0 {
			meta["requires"] = requires
		}
		out = append(out, Rule{
			RuleID: name, Title: title, Body: truncate(block, maxRuleSize), Meta: meta, CVEIDs: cves,
			URL: "https://github.com/Neo23x0/signature-base/blob/master/" + path,
		})
	}
	return out
}

// truncate cuts s to at most n bytes, at a character boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// yaraRequires returns the texts of the other rules of the file that a
// rule's condition names, and theirs in turn, dependencies first (YARA
// needs a rule defined before a condition refers to it).
func yaraRequires(name string, blocks map[string]string) []string {
	var out []string
	seen := map[string]bool{name: true}
	var visit func(string)
	visit = func(n string) {
		_, cond, ok := strings.Cut(blocks[n], "condition:")
		if !ok {
			return
		}
		for _, w := range yaraWord.FindAllString(cond, -1) {
			if _, isRule := blocks[w]; isRule && !seen[w] {
				seen[w] = true
				visit(w)
				out = append(out, blocks[w])
			}
		}
	}
	visit(name)
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
