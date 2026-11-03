package reports

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const nvdHistoryURL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId="

// HistoryChange is one NVD change event (e.g. "Initial Analysis",
// "CVE Modified", "CISA KEV Update") with its field-level details.
type HistoryChange struct {
	Event   string          `json:"event"`
	Created string          `json:"created"`
	Source  string          `json:"source,omitempty"`
	Details []HistoryDetail `json:"details"`
}

type HistoryDetail struct {
	Action string `json:"action"` // Added, Removed, Changed
	Type   string `json:"type"`   // CVSS V3.1, CPE Configuration, Reference, CWE, ...
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
}

// history returns NVD's change log for the CVE, newest first.
func (c *Client) history(ctx context.Context, cveID string) ([]HistoryChange, error) {
	h := http.Header{"Accept": {"application/json"}}
	if c.keys.NVD != "" {
		h.Set("apiKey", c.keys.NVD)
	}
	resp, err := fetch.Get(ctx, c.http, nvdHistoryURL+url.QueryEscape(cveID), h)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Changes []struct {
			Change struct {
				EventName        string `json:"eventName"`
				Created          string `json:"created"`
				SourceIdentifier string `json:"sourceIdentifier"`
				Details          []struct {
					Action string `json:"action"`
					Type   string `json:"type"`
					// Usually strings, but some change types carry objects.
					OldValue json.RawMessage `json:"oldValue"`
					NewValue json.RawMessage `json:"newValue"`
				} `json:"details"`
			} `json:"change"`
		} `json:"cveChanges"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.Changes) == 0 {
		return nil, ErrNotFound
	}
	out := make([]HistoryChange, 0, len(doc.Changes))
	for i := len(doc.Changes) - 1; i >= 0; i-- {
		ch := doc.Changes[i].Change
		hc := HistoryChange{Event: ch.EventName, Created: ch.Created, Source: ch.SourceIdentifier, Details: []HistoryDetail{}}
		for _, d := range ch.Details {
			hc.Details = append(hc.Details, HistoryDetail{Action: d.Action, Type: d.Type, Old: clip(rawText(d.OldValue), 2000), New: clip(rawText(d.NewValue), 2000)})
		}
		out = append(out, hc)
	}
	return out, nil
}

// rawText returns a JSON string's value, or other JSON as compact text.
func rawText(v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	return string(v)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
