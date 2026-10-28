package cverecord

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Provider identifies who supplied a metric.
const (
	ProviderCNA = "cna"
	ProviderADP = "adp"
	ProviderNVD = "nvd"
)

// Metric is one CVSS score from one provider.
type Metric struct {
	Provider     string  `json:"provider"`
	ProviderName string  `json:"provider_name,omitempty"`
	Version      string  `json:"version"`
	Score        float64 `json:"score"`
	Vector       string  `json:"vector"`
	Severity     string  `json:"severity"`
}

// Source is the short provenance label stored in cve.severity_source.
func (m Metric) Source() string { return m.Provider + ":cvss" + m.Version }

// precedence orders metrics for choosing effective scores and severity; see
// ARCHITECTURE.md "Severity precedence". Lower rank wins.
var precedence = map[string]int{
	"cna:4.0": 0, "nvd:4.0": 1,
	"cna:3.1": 2, "cna:3.0": 3, "nvd:3.1": 4, "nvd:3.0": 5,
	"adp:4.0": 6, "adp:3.1": 7, "adp:3.0": 8,
	"cna:2.0": 9, "nvd:2.0": 10,
}

// Metrics returns every CVSS metric from both sources, best first.
// Either argument may be nil.
func Metrics(rec *Record, nvd *NVD) []Metric {
	var out []Metric
	if rec != nil {
		out = appendContainerMetrics(out, ProviderCNA, rec.Metadata.AssignerShortName, rec.Containers.CNA)
		for _, adp := range rec.Containers.ADP {
			out = appendContainerMetrics(out, ProviderADP, adp.ProviderMetadata.ShortName, adp)
		}
	}
	if nvd != nil {
		// Primary (NVD's own analysis) before Secondary (CNA-supplied copies).
		for _, group := range []struct {
			version string
			items   []nvdMetric
		}{{"4.0", nvd.Metrics.V40}, {"3.1", nvd.Metrics.V31}, {"3.0", nvd.Metrics.V30}, {"2.0", nvd.Metrics.V2}} {
			items := slices.Clone(group.items)
			sort.SliceStable(items, func(i, j int) bool { return items[i].Type == "Primary" && items[j].Type != "Primary" })
			for _, m := range items {
				sev := m.CVSSData.BaseSeverity
				if sev == "" {
					sev = m.BaseSeverity
				}
				out = appendMetric(out, ProviderNVD, m.Source, group.version, &CVSS{m.CVSSData.BaseScore, m.CVSSData.VectorString, sev})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return precedence[out[i].Provider+":"+out[i].Version] < precedence[out[j].Provider+":"+out[j].Version]
	})
	return out
}

func appendContainerMetrics(out []Metric, provider, name string, c Container) []Metric {
	for _, m := range c.Metrics {
		out = appendMetric(out, provider, name, "4.0", m.CVSSv40)
		out = appendMetric(out, provider, name, "3.1", m.CVSSv31)
		out = appendMetric(out, provider, name, "3.0", m.CVSSv30)
		out = appendMetric(out, provider, name, "2.0", m.CVSSv20)
	}
	return out
}

func appendMetric(out []Metric, provider, name, version string, c *CVSS) []Metric {
	if c == nil || (c.BaseScore == 0 && c.VectorString == "") {
		return out
	}
	score := float64(c.BaseScore)
	return append(out, Metric{
		Provider:     provider,
		ProviderName: name,
		Version:      version,
		Score:        score,
		Vector:       strings.TrimSpace(c.VectorString),
		Severity:     severity(version, score, c.BaseSeverity),
	})
}

// severity prefers the provider's stated severity and falls back to the
// standard score bands for the CVSS version.
func severity(version string, score float64, stated string) string {
	switch s := strings.ToUpper(strings.TrimSpace(stated)); s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return s
	}
	if version == "2.0" {
		switch {
		case score >= 7:
			return "HIGH"
		case score >= 4:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

// SSVC is CISA's Stakeholder-Specific Vulnerability Categorization decision
// points, published in the CISA-ADP container.
type SSVC struct {
	Exploitation    string `json:"exploitation,omitempty"`
	Automatable     string `json:"automatable,omitempty"`
	TechnicalImpact string `json:"technical_impact,omitempty"`
}

// CISASSVC returns the SSVC decision points from the CISA-ADP container, or
// nil if there are none.
func CISASSVC(rec *Record) *SSVC {
	if rec == nil {
		return nil
	}
	for _, adp := range rec.Containers.ADP {
		for _, m := range adp.Metrics {
			if m.Other == nil || !strings.EqualFold(m.Other.Type, "ssvc") {
				continue
			}
			var content struct {
				Options []map[string]string `json:"options"`
			}
			if json.Unmarshal(m.Other.Content, &content) != nil {
				continue
			}
			var s SSVC
			for _, opt := range content.Options {
				for k, v := range opt {
					switch strings.ToLower(k) {
					case "exploitation":
						s.Exploitation = v
					case "automatable":
						s.Automatable = v
					case "technical impact":
						s.TechnicalImpact = v
					}
				}
			}
			if s != (SSVC{}) {
				return &s
			}
		}
	}
	return nil
}

// AffectedRow is one normalized affected product.
type AffectedRow struct {
	Source string
	// Vendor and Product are canonical keys (see CanonicalVendor); the
	// labels keep the published spelling for display.
	Vendor       string
	Product      string
	VendorLabel  string
	ProductLabel string
	CPEs         []string
	Versions     json.RawMessage
}

// Derived holds every column Pahredar computes from the raw records.
type Derived struct {
	Title          string
	Description    string
	CWEs           []string
	V4, V3, V2     *Metric
	Severity       string
	SeveritySource string
	References     []Reference
	// ExploitRef is true when any reference is tagged as an exploit.
	ExploitRef bool
	Affected   []AffectedRow
	// SearchText is the vendor and product names, for the full-text index.
	SearchText string
}

var cwePattern = regexp.MustCompile(`^CWE-\d+$`)

// Derive computes the stored fields from a cvelist record and an optional NVD
// record. rec may be nil when only NVD data exists.
func Derive(rec *Record, nvd *NVD) Derived {
	if rec == nil {
		rec = &Record{}
	}
	var d Derived
	cna := rec.Containers.CNA

	d.Title = clean(cna.Title)
	if rec.Metadata.State == "REJECTED" {
		d.Description = english(cna.RejectedReasons)
	} else {
		d.Description = english(cna.Descriptions)
	}
	if d.Description == "" && nvd != nil {
		d.Description = english(nvd.Descriptions)
	}

	metrics := Metrics(rec, nvd)
	for i := range metrics {
		m := &metrics[i]
		switch {
		case m.Version == "4.0" && d.V4 == nil:
			d.V4 = m
		case strings.HasPrefix(m.Version, "3.") && d.V3 == nil:
			d.V3 = m
		case m.Version == "2.0" && d.V2 == nil:
			d.V2 = m
		}
	}
	d.Severity = "UNKNOWN"
	if len(metrics) > 0 && rec.Metadata.State != "REJECTED" {
		d.Severity = metrics[0].Severity
		d.SeveritySource = metrics[0].Source()
	}

	cwes := map[string]bool{}
	containers := append([]Container{cna}, rec.Containers.ADP...)
	for _, c := range containers {
		for _, pt := range c.ProblemTypes {
			for _, desc := range pt.Descriptions {
				if id := strings.ToUpper(strings.TrimSpace(desc.CWEID)); cwePattern.MatchString(id) {
					cwes[id] = true
				}
			}
		}
	}
	if nvd != nil {
		for _, w := range nvd.Weaknesses {
			for _, desc := range w.Description {
				if id := strings.ToUpper(strings.TrimSpace(desc.Value)); cwePattern.MatchString(id) {
					cwes[id] = true
				}
			}
		}
	}
	d.CWEs = make([]string, 0, len(cwes))
	for id := range cwes {
		d.CWEs = append(d.CWEs, id)
	}
	sort.Strings(d.CWEs)

	d.References = mergeReferences(rec, nvd)
	for _, ref := range d.References {
		for _, t := range ref.Tags {
			if strings.EqualFold(t, "exploit") {
				d.ExploitRef = true
			}
		}
	}

	names := map[string]bool{}
	var nameList []string
	addAffected := func(source string, list []Affected) {
		for _, a := range list {
			vendorLabel, productLabel := displayName(a.Vendor), displayName(a.Product)
			vendor, product := CanonicalVendor(a.Vendor), CanonicalProduct(a.Product)
			if product == "" {
				continue
			}
			if vendor == "" {
				vendorLabel = ""
			}
			versions := a.Versions
			if len(versions) == 0 || string(versions) == "null" {
				versions = json.RawMessage("[]")
			}
			d.Affected = append(d.Affected, AffectedRow{
				Source: source, Vendor: vendor, Product: product, VendorLabel: vendorLabel, ProductLabel: productLabel,
				CPEs: a.CPEs, Versions: versions,
			})
			for _, n := range []string{vendor, product} {
				if n != "" && !names[n] {
					names[n] = true
					nameList = append(nameList, n)
				}
			}
		}
	}
	addAffected(ProviderCNA, cna.Affected)
	for _, adp := range rec.Containers.ADP {
		addAffected(ProviderADP, adp.Affected)
	}
	if nvd != nil {
		addAffected(ProviderNVD, nvdAffected(nvd))
	}
	d.SearchText = strings.Join(nameList, " ")
	return d
}

// nvdAffected groups an NVD record's vulnerable CPE criteria by vendor and
// product. Versions holds the CPEMatch objects (criteria plus version bounds),
// a different shape from the CNA/ADP version entries.
func nvdAffected(nvd *NVD) []Affected {
	type group struct {
		vendor, product string
		cpes            []string
		matches         []CPEMatch
	}
	var groups []*group
	index := map[string]*group{}
	for _, cfg := range nvd.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				vendor, product, ok := cpeVendorProduct(m.Criteria)
				if !ok {
					continue
				}
				key := vendor + "\x00" + product
				g, ok := index[key]
				if !ok {
					g = &group{vendor: vendor, product: product}
					index[key] = g
					groups = append(groups, g)
				}
				if !slices.Contains(g.cpes, m.Criteria) {
					g.cpes = append(g.cpes, m.Criteria)
				}
				g.matches = append(g.matches, m)
			}
		}
	}
	out := make([]Affected, 0, len(groups))
	for _, g := range groups {
		versions, _ := json.Marshal(g.matches)
		out = append(out, Affected{Vendor: g.vendor, Product: g.product, CPEs: g.cpes, Versions: versions})
	}
	return out
}

// Vendor and product names arrive in many spellings for the same thing:
// CNA free text ("Oracle Corporation", "Qualcomm, Inc."), NVD CPE fields
// ("oracle", "windows_server_2016"). Canonical keys group them: lower-case,
// underscores as spaces, single spaces, trailing legal-entity suffixes
// removed, and a short alias list for well-known duplicates. Placeholders
// ("n/a", "unknown") become "".

// legalSuffixes are stripped from the end of vendor names, repeatedly, so
// "Foo Systems Co., Ltd." loses both. Only unambiguous forms are listed;
// two-letter ones without a dot (" ag", " sa", " ab") are not, to avoid
// truncating real names.
var legalSuffixes = []string{
	" incorporated", " inc.", " inc", " corporation", " corp.", " corp",
	" co., ltd.", " co., ltd", " co. ltd.", " co. ltd", " co.,ltd.", " co.,ltd", " co.",
	" limited", " ltd.", " ltd", " l.l.c.", " llc", " gmbh", " s.a.", " plc", " b.v.", " s.r.l.",
}

// vendorAliases maps a suffix-stripped name to the key other sources use.
var vendorAliases = map[string]string{
	"redhat":                           "red hat",
	"the apache software foundation":   "apache",
	"apache software foundation":       "apache",
	"cisco systems":                    "cisco",
	"f5 networks":                      "f5",
	"jenkins project":                  "jenkins",
	"the linux foundation":             "linux foundation",
	"hewlett packard enterprise":       "hpe",
	"hewlett packard enterprise (hpe)": "hpe",
	"hewlett-packard":                  "hp",
	"fedoraproject":                    "fedora project",
	"wordpress.org":                    "wordpress",
}

func isPlaceholder(s string) bool {
	switch s {
	case "", "n/a", "na", "-", "*", "unknown", "unspecified", "none":
		return true
	}
	return false
}

func baseName(s string) string {
	s = strings.ToLower(clean(s))
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.Join(strings.Fields(s), " ")
	return strings.Trim(s, " ,")
}

// CanonicalVendor returns the grouping key for a vendor name.
func CanonicalVendor(s string) string {
	s = baseName(s)
	if isPlaceholder(s) {
		return ""
	}
	for changed := true; changed; {
		changed = false
		for _, suf := range legalSuffixes {
			if strings.HasSuffix(s, suf) && len(s) > len(suf) {
				s = strings.Trim(strings.TrimSuffix(s, suf), " ,")
				changed = true
			}
		}
	}
	if alias, ok := vendorAliases[s]; ok {
		s = alias
	}
	return s
}

// CanonicalProduct returns the grouping key for a product name.
func CanonicalProduct(s string) string {
	s = baseName(s)
	if isPlaceholder(s) {
		return ""
	}
	return s
}

// displayName is a name as published, with CPE underscores turned to spaces.
func displayName(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(clean(s), "_", " ")), " ")
	if isPlaceholder(strings.ToLower(s)) {
		return ""
	}
	return s
}

func mergeReferences(rec *Record, nvd *NVD) []Reference {
	var out []Reference
	index := map[string]int{}
	add := func(r Reference) {
		url := strings.TrimSpace(r.URL)
		if url == "" {
			return
		}
		if i, ok := index[url]; ok {
			for _, t := range r.Tags {
				if !slices.Contains(out[i].Tags, t) {
					out[i].Tags = append(out[i].Tags, t)
				}
			}
			if out[i].Name == "" {
				out[i].Name = r.Name
			}
			return
		}
		index[url] = len(out)
		out = append(out, Reference{URL: url, Name: clean(r.Name), Tags: slices.Clone(r.Tags)})
	}
	for _, r := range rec.Containers.CNA.References {
		add(r)
	}
	for _, adp := range rec.Containers.ADP {
		for _, r := range adp.References {
			add(r)
		}
	}
	if nvd != nil {
		for _, r := range nvd.References {
			add(Reference{URL: r.URL, Tags: r.Tags})
		}
	}
	if out == nil {
		out = []Reference{}
	}
	return out
}

// Advisory is the CNA's free-text advisory content, for the detail page.
type Advisory struct {
	Solutions         []string        `json:"solutions"`
	Workarounds       []string        `json:"workarounds"`
	ExploitStatements []string        `json:"exploit_statements"`
	Configurations    []string        `json:"configurations"`
	Credits           []Credit        `json:"credits"`
	Capec             []Capec         `json:"capec"`
	Timeline          []AdvisoryEvent `json:"timeline"`
}

type Credit struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type Capec struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type AdvisoryEvent struct {
	Date  string `json:"date"`
	Value string `json:"value"`
}

// CNAAdvisory extracts the CNA's advisory sections. Each list keeps English
// entries (falling back to any language) and is never nil.
func CNAAdvisory(rec *Record) Advisory {
	a := Advisory{
		Solutions: []string{}, Workarounds: []string{}, ExploitStatements: []string{}, Configurations: []string{},
		Credits: []Credit{}, Capec: []Capec{}, Timeline: []AdvisoryEvent{},
	}
	if rec == nil {
		return a
	}
	cna := rec.Containers.CNA
	texts := func(values []LangValue) []string {
		out := []string{}
		seen := map[string]bool{}
		for _, v := range values {
			if !strings.HasPrefix(strings.ToLower(v.Lang), "en") && hasEnglish(values) {
				continue
			}
			if t := clean(v.Value); t != "" && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
		return out
	}
	a.Solutions = texts(cna.Solutions)
	a.Workarounds = texts(cna.Workarounds)
	a.ExploitStatements = texts(cna.Exploits)
	a.Configurations = texts(cna.Configurations)
	for _, c := range cna.Credits {
		if name := clean(c.Value); name != "" {
			a.Credits = append(a.Credits, Credit{Name: name, Type: c.Type})
		}
	}
	for _, im := range cna.Impacts {
		id := strings.ToUpper(strings.TrimSpace(im.CapecID))
		if id == "" {
			continue
		}
		a.Capec = append(a.Capec, Capec{ID: id, Description: english(im.Descriptions)})
	}
	for _, t := range cna.Timeline {
		if v := clean(t.Value); v != "" && !t.Time.IsZero() {
			a.Timeline = append(a.Timeline, AdvisoryEvent{Date: t.Time.Format("2006-01-02"), Value: v})
		}
	}
	return a
}

func hasEnglish(values []LangValue) bool {
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v.Lang), "en") {
			return true
		}
	}
	return false
}
