// Package attack reads two MITRE-derived datasets that place a CVE in an
// attack:
//
//   - The Center for Threat-Informed Defense's KEV mappings
//     (mappings-explorer): for CISA KEV CVEs, the ATT&CK techniques used to
//     exploit them and their primary and secondary impact.
//   - MITRE CAPEC (attack patterns): each pattern's related CWEs, ATT&CK
//     techniques, prerequisites, execution flow, indicators, and
//     mitigations. A CVE reaches CAPEC through its CWEs.
package attack

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

// kevMappingURLs are the enterprise-domain KEV mapping files, oldest first;
// a later file's mappings replace an earlier file's for the same CVE.
var kevMappingURLs = []string{
	"https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-15.1/kev-02.13.2025/enterprise/kev-02.13.2025_attack-15.1-enterprise.json",
	"https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json",
}

const capecURL = "https://capec.mitre.org/data/csv/1000.csv.zip"

// Mapping is one (CVE, technique, mapping type) row.
type Mapping struct {
	CVEID           string
	TechniqueID     string
	TechniqueName   string
	MappingType     string // exploitation_technique, primary_impact, secondary_impact, uncategorized
	CapabilityGroup string
	Comments        string
	References      []string
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// KEVMappings downloads every mapping file; for a CVE present in several,
// the newest file wins.
func KEVMappings(ctx context.Context, c *http.Client) ([]Mapping, error) {
	byCVE := map[string][]Mapping{}
	var order []string
	for _, url := range kevMappingURLs {
		ms, err := kevFile(ctx, c, url)
		if err != nil {
			return nil, err
		}
		fresh := map[string][]Mapping{}
		for _, m := range ms {
			fresh[m.CVEID] = append(fresh[m.CVEID], m)
		}
		for id, list := range fresh {
			if _, seen := byCVE[id]; !seen {
				order = append(order, id)
			}
			byCVE[id] = list
		}
	}
	var out []Mapping
	for _, id := range order {
		out = append(out, byCVE[id]...)
	}
	return out, nil
}

func kevFile(ctx context.Context, c *http.Client, url string) ([]Mapping, error) {
	resp, err := fetch.Get(ctx, c, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		Metadata struct {
			CapabilityGroups map[string]string `json:"capability_groups"`
		} `json:"metadata"`
		Objects []struct {
			CapabilityID    string   `json:"capability_id"`
			MappingType     string   `json:"mapping_type"`
			AttackID        string   `json:"attack_object_id"`
			AttackName      string   `json:"attack_object_name"`
			CapabilityGroup string   `json:"capability_group"`
			Comments        string   `json:"comments"`
			References      []string `json:"references"`
		} `json:"mapping_objects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	var out []Mapping
	for _, o := range doc.Objects {
		id := strings.ToUpper(strings.TrimSpace(o.CapabilityID))
		if !cvePattern.MatchString(id) || o.AttackID == "" {
			continue
		}
		group := doc.Metadata.CapabilityGroups[o.CapabilityGroup]
		if group == "" {
			group = o.CapabilityGroup
		}
		out = append(out, Mapping{
			CVEID: id, TechniqueID: o.AttackID, TechniqueName: o.AttackName, MappingType: o.MappingType,
			CapabilityGroup: group, Comments: strings.TrimSpace(o.Comments), References: o.References,
		})
	}
	return out, nil
}

// Technique is an ATT&CK technique reference.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Pattern is one CAPEC attack pattern.
type Pattern struct {
	ID            string // CAPEC-123
	Name          string
	Abstraction   string
	Likelihood    string
	Severity      string
	Description   string
	Prerequisites []string
	ExecutionFlow []string
	Indicators    []string
	Mitigations   []string
	CWEs          []string
	Attack        []Technique
}

// CAPEC reads the CAPEC CSV (the zip holds one file). Deprecated and
// obsolete patterns are skipped.
func CAPEC(ctx context.Context, c *http.Client) ([]Pattern, error) {
	resp, err := fetch.Get(ctx, c, capecURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open capec zip: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("capec zip is empty")
	}
	f, err := zr.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCAPEC(f)
}

var (
	listItem   = regexp.MustCompile(`::+`)
	attackItem = regexp.MustCompile(`TAXONOMY NAME:ATTACK:ENTRY ID:([0-9.]+):ENTRY NAME:([^:]+(?::[^:]+)?)`)
	// Execution flow entries: "::STEP:1:PHASE:Explore:DESCRIPTION:...:TECHNIQUE:...".
	flowStep = regexp.MustCompile(`STEP:(\d+):PHASE:([^:]+):DESCRIPTION:(.*?)(?::TECHNIQUE:|$)`)
)

func parseCAPEC(r io.Reader) ([]Pattern, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimPrefix(h, "'")] = i
	}
	for _, k := range []string{"ID", "Name", "Status", "Related Weaknesses", "Taxonomy Mappings"} {
		if _, ok := col[k]; !ok {
			return nil, fmt.Errorf("capec csv: missing column %q", k)
		}
	}
	get := func(rec []string, k string) string {
		i, ok := col[k]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var out []Pattern
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		status := get(rec, "Status")
		if status == "Deprecated" || status == "Obsolete" {
			continue
		}
		p := Pattern{
			ID: "CAPEC-" + get(rec, "ID"), Name: get(rec, "Name"), Abstraction: get(rec, "Abstraction"),
			Likelihood: get(rec, "Likelihood Of Attack"), Severity: get(rec, "Typical Severity"),
			Description:   get(rec, "Description"),
			Prerequisites: splitList(get(rec, "Prerequisites")),
			Indicators:    splitList(get(rec, "Indicators")),
			Mitigations:   splitList(get(rec, "Mitigations")),
		}
		for _, w := range splitList(get(rec, "Related Weaknesses")) {
			p.CWEs = append(p.CWEs, "CWE-"+w)
		}
		for _, m := range attackItem.FindAllStringSubmatch(get(rec, "Taxonomy Mappings"), -1) {
			p.Attack = append(p.Attack, Technique{ID: "T" + m[1], Name: strings.TrimSpace(m[2])})
		}
		for _, step := range listItem.Split(get(rec, "Execution Flow"), -1) {
			if m := flowStep.FindStringSubmatch(step); m != nil {
				p.ExecutionFlow = append(p.ExecutionFlow, m[2]+": "+strings.TrimSpace(m[3]))
			}
		}
		out = append(out, p)
	}
}

// splitList splits CAPEC's "::a::b::" list cells.
func splitList(s string) []string {
	var out []string
	for _, x := range listItem.Split(s, -1) {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
