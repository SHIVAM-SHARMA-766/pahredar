// Package cverecord parses upstream CVE records (CVE JSON 5 from cvelistV5,
// CVE API 2.0 from NVD) and derives the normalized fields Pahredar stores:
// effective CVSS scores, severity, CWEs, references, and affected products.
// It has no database or network dependencies.
package cverecord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// IDPattern matches a canonical, upper-case CVE ID.
var IDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Record is the subset of a CVE JSON 5 record that Pahredar reads.
type Record struct {
	Raw        []byte   `json:"-"`
	Metadata   Metadata `json:"cveMetadata"`
	Containers struct {
		CNA Container   `json:"cna"`
		ADP []Container `json:"adp"`
	} `json:"containers"`
}

type Metadata struct {
	ID                string    `json:"cveId"`
	State             string    `json:"state"`
	AssignerShortName string    `json:"assignerShortName"`
	DateReserved      Timestamp `json:"dateReserved"`
	DatePublished     Timestamp `json:"datePublished"`
	DateUpdated       Timestamp `json:"dateUpdated"`
}

// Container is a CNA or ADP container. ADP containers use the same shape.
type Container struct {
	ProviderMetadata struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Title           string      `json:"title"`
	Descriptions    []LangValue `json:"descriptions"`
	RejectedReasons []LangValue `json:"rejectedReasons"`
	ProblemTypes    []struct {
		Descriptions []struct {
			CWEID string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	Affected   []Affected    `json:"affected"`
	Metrics    []MetricEntry `json:"metrics"`
	References []Reference   `json:"references"`

	// Free-text advisory sections a CNA may publish.
	Solutions      []LangValue `json:"solutions"`
	Workarounds    []LangValue `json:"workarounds"`
	Exploits       []LangValue `json:"exploits"`
	Configurations []LangValue `json:"configurations"`
	Credits        []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"credits"`
	Impacts []struct {
		CapecID      string      `json:"capecId"`
		Descriptions []LangValue `json:"descriptions"`
	} `json:"impacts"`
	Timeline []struct {
		Time  Timestamp `json:"time"`
		Lang  string    `json:"lang"`
		Value string    `json:"value"`
	} `json:"timeline"`
}

type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Affected struct {
	Vendor   string          `json:"vendor"`
	Product  string          `json:"product"`
	CPEs     []string        `json:"cpes"`
	Versions json.RawMessage `json:"versions"`
}

type MetricEntry struct {
	CVSSv40 *CVSS `json:"cvssV4_0"`
	CVSSv31 *CVSS `json:"cvssV3_1"`
	CVSSv30 *CVSS `json:"cvssV3_0"`
	CVSSv20 *CVSS `json:"cvssV2_0"`
	Other   *struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	} `json:"other"`
}

type CVSS struct {
	BaseScore    Score  `json:"baseScore"`
	VectorString string `json:"vectorString"`
	BaseSeverity string `json:"baseSeverity"`
}

type Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// Parse decodes a CVE JSON 5 record and validates its ID and state.
// Record.Raw holds the input with NUL escapes removed, because Postgres jsonb
// rejects \u0000.
func Parse(raw []byte) (*Record, error) {
	raw, err := stripNUL(raw)
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	r.Metadata.ID = strings.ToUpper(strings.TrimSpace(r.Metadata.ID))
	if !IDPattern.MatchString(r.Metadata.ID) {
		return nil, fmt.Errorf("invalid CVE ID %q", r.Metadata.ID)
	}
	r.Metadata.State = strings.ToUpper(r.Metadata.State)
	if r.Metadata.State != "PUBLISHED" && r.Metadata.State != "REJECTED" {
		return nil, fmt.Errorf("%s: unexpected state %q", r.Metadata.ID, r.Metadata.State)
	}
	r.Raw = raw
	return &r, nil
}

// Timestamp accepts the layouts seen in CVE records, some of which omit the
// zone (treated as UTC). Unparseable values decode to the zero time rather
// than failing the whole record.
type Timestamp struct{ time.Time }

var timestampLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02"}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || s == "" {
		return nil
	}
	for _, layout := range timestampLayouts {
		if v, err := time.Parse(layout, s); err == nil {
			t.Time = v.UTC()
			return nil
		}
	}
	return nil
}

// Ptr returns nil for the zero time, for nullable columns.
func (t Timestamp) Ptr() *time.Time {
	if t.IsZero() {
		return nil
	}
	v := t.Time
	return &v
}

// Score accepts a CVSS base score encoded as a JSON number or string.
type Score float64

func (s *Score) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseFloat(strings.Trim(string(b), `"`), 64)
	if err == nil {
		*s = Score(v)
	}
	return nil
}

// stripNUL removes NUL characters from every string in a JSON document. The
// fast path returns the input untouched when it contains no \u0000 escape.
func stripNUL(raw []byte) ([]byte, error) {
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(cleanValue(v))
}

func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return clean(t)
	case []any:
		for i := range t {
			t[i] = cleanValue(t[i])
		}
	case map[string]any:
		for k, val := range t {
			t[k] = cleanValue(val)
		}
	}
	return v
}

func clean(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
}

// english returns the first English value, falling back to the first value.
func english(values []LangValue) string {
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v.Lang), "en") && strings.TrimSpace(v.Value) != "" {
			return clean(v.Value)
		}
	}
	for _, v := range values {
		if strings.TrimSpace(v.Value) != "" {
			return clean(v.Value)
		}
	}
	return ""
}
