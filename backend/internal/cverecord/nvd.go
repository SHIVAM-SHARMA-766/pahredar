package cverecord

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NVD is the subset of an NVD CVE API 2.0 record (the "cve" object of a
// vulnerabilities[] item) that Pahredar reads.
type NVD struct {
	// Raw is the input with NUL escapes removed (see Parse).
	Raw          []byte      `json:"-"`
	ID           string      `json:"id"`
	VulnStatus   string      `json:"vulnStatus"`
	Published    Timestamp   `json:"published"`
	LastModified Timestamp   `json:"lastModified"`
	Descriptions []LangValue `json:"descriptions"`
	Metrics      struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []LangValue `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []CPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// CPEMatch is one NVD applicability criterion. Its JSON form is what Pahredar
// stores in cve_affected.versions for source 'nvd'.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData CVSS   `json:"cvssData"`
	// CVSS v2 entries carry severity outside cvssData.
	BaseSeverity string `json:"baseSeverity"`
}

func ParseNVD(raw []byte) (*NVD, error) {
	raw, err := stripNUL(raw)
	if err != nil {
		return nil, err
	}
	var n NVD
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil, err
	}
	n.ID = strings.ToUpper(strings.TrimSpace(n.ID))
	if !IDPattern.MatchString(n.ID) {
		return nil, fmt.Errorf("invalid NVD CVE ID %q", n.ID)
	}
	n.Raw = raw
	return &n, nil
}

// cpeVendorProduct extracts the vendor and product fields from a CPE 2.3
// formatted string, honouring backslash escapes. ok is false for malformed
// strings and for wildcard or not-applicable values.
func cpeVendorProduct(cpe string) (vendor, product string, ok bool) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return "", "", false
	}
	// Fields: cpe, 2.3, part, vendor, product, version, ... Only the first
	// five are needed.
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range cpe {
		if len(fields) == 5 {
			break
		}
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if len(fields) < 5 {
		return "", "", false
	}
	vendor, product = fields[3], fields[4]
	if vendor == "*" || vendor == "-" || product == "*" || product == "-" || product == "" {
		return "", "", false
	}
	return vendor, product, true
}
