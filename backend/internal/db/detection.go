package db

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

type DetectionRow struct {
	RuleID string
	Title  string
	URL    string
	Body   string
	Meta   map[string]any
	CVEIDs []string
}

// ReplaceDetectionRules makes the detection_rule rows for one source equal
// to rows. Duplicate rule IDs keep the first occurrence.
func (s *Store) ReplaceDetectionRules(ctx context.Context, source string, rows []DetectionRow) (inserted, updated, deleted int, err error) {
	seen := map[string]bool{}
	data := make([][]any, 0, len(rows))
	for _, r := range rows {
		if seen[r.RuleID] {
			continue
		}
		seen[r.RuleID] = true
		meta := r.Meta
		if meta == nil {
			meta = map[string]any{}
		}
		var url any
		if r.URL != "" {
			url = r.URL
		}
		data = append(data, []any{source, r.RuleID, r.Title, url, r.Body, meta, r.CVEIDs})
	}
	return s.replaceSnapshot(ctx, snapshot{
		table:   "detection_rule",
		columns: []string{"source", "rule_id", "title", "url", "body", "meta", "cve_ids"},
		key:     []string{"source", "rule_id"},
		scope:   "source", scopeValue: source,
		rows: data,
	})
}

type DetectionOut struct {
	Source string          `json:"source"`
	RuleID string          `json:"rule_id"`
	Title  string          `json:"title"`
	URL    *string         `json:"url"`
	Body   string          `json:"body"`
	Meta   json.RawMessage `json:"meta"`
	CVEIDs []string        `json:"cve_ids"`
}

// DetectionForCVE returns the rules naming a CVE: active checks (Nmap,
// Greenbone),
// log rules (Sigma, Splunk, Elastic), network rules (Suricata, Snort), then
// YARA; within a source, CVE-specific before related (cited only in a
// rule's references) and enabled-by-default before disabled.
func (s *Store) DetectionForCVE(ctx context.Context, cveID string, limit int) ([]DetectionOut, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT source, rule_id, title, url, body, meta, cve_ids FROM detection_rule
		WHERE cve_ids @> ARRAY[$1]::text[]
		ORDER BY array_position(ARRAY['nmap', 'greenbone', 'sigma', 'splunk', 'elastic', 'suricata', 'snort', 'yara'], source),
		         (meta ->> 'related') = 'true', (meta ->> 'enabled') = 'false', cardinality(cve_ids), title
		LIMIT $2`, cveID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[DetectionOut])
}
