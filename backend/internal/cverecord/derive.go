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
	Source   string
	Vendor   string
	Product  string
	CPEs     []string
	Versions json.RawMessage
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
	Affected       []AffectedRow
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

	names := map[string]bool{}
	var nameList []string
	addAffected := func(source string, list []Affected) {
		for _, a := range list {
			vendor, product := normalizeName(a.Vendor), normalizeName(a.Product)
			if product == "" {
				continue
			}
			versions := a.Versions
			if len(versions) == 0 || string(versions) == "null" {
				versions = json.RawMessage("[]")
			}
			d.Affected = append(d.Affected, AffectedRow{Source: source, Vendor: vendor, Product: product, CPEs: a.CPEs, Versions: versions})
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
	d.SearchText = strings.Join(nameList, " ")
	return d
}

// normalizeName lower-cases a vendor or product and maps placeholders to "".
func normalizeName(s string) string {
	s = strings.ToLower(clean(s))
	switch s {
	case "n/a", "na", "-", "unknown", "unspecified":
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
