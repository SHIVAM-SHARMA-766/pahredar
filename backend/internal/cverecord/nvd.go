package cverecord

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NVD is the subset of an NVD CVE API 2.0 record (the "cve" object of a
// vulnerabilities[] item) that Pahredar reads.
type NVD struct {
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
	return &n, nil
}
