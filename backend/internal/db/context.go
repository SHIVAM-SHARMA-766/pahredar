package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Snapshot writers and per-CVE readers for the context datasets: ENISA
// EUVD exploited list, CTID ATT&CK mappings, CAPEC, and the Debian
// Security Tracker (migration 00012).

type EUVDRow struct {
	CVEID          string
	EUVDID         string
	ExploitedSince *time.Time
	Description    string
}

func (s *Store) ReplaceEUVD(ctx context.Context, rows []EUVDRow) (inserted, updated, deleted int, err error) {
	seen := map[string]bool{}
	data := make([][]any, 0, len(rows))
	for _, r := range rows {
		if seen[r.CVEID] {
			continue
		}
		seen[r.CVEID] = true
		data = append(data, []any{r.CVEID, r.EUVDID, r.ExploitedSince, r.Description})
	}
	return s.replaceSnapshot(ctx, snapshot{
		table: "euvd_exploited", columns: []string{"cve_id", "euvd_id", "exploited_since", "description"},
		key: []string{"cve_id"}, rows: data,
	})
}

type AttackRow struct {
	CVEID, TechniqueID, MappingType, TechniqueName, CapabilityGroup, Comments string
	Refs                                                                      []string
}

func (s *Store) ReplaceAttackMappings(ctx context.Context, rows []AttackRow) (inserted, updated, deleted int, err error) {
	seen := map[[3]string]bool{}
	data := make([][]any, 0, len(rows))
	for _, r := range rows {
		k := [3]string{r.CVEID, r.TechniqueID, r.MappingType}
		if seen[k] {
			continue
		}
		seen[k] = true
		refs := r.Refs
		if refs == nil {
			refs = []string{}
		}
		data = append(data, []any{r.CVEID, r.TechniqueID, r.MappingType, r.TechniqueName, r.CapabilityGroup, r.Comments, refs})
	}
	return s.replaceSnapshot(ctx, snapshot{
		table:   "attack_mapping",
		columns: []string{"cve_id", "technique_id", "mapping_type", "technique_name", "capability_group", "comments", "refs"},
		key:     []string{"cve_id", "technique_id", "mapping_type"}, rows: data,
	})
}

type CAPECRow struct {
	ID, Name, Abstraction, Likelihood, Severity, Description    string
	Prerequisites, ExecutionFlow, Indicators, Mitigations, CWEs []string
	// Attack is a JSON-encodable list of {id, name}.
	Attack any
}

func (s *Store) ReplaceCAPEC(ctx context.Context, rows []CAPECRow) (inserted, updated, deleted int, err error) {
	nz := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	data := make([][]any, 0, len(rows))
	for _, r := range rows {
		attack := r.Attack
		if attack == nil {
			attack = []any{}
		}
		data = append(data, []any{r.ID, r.Name, r.Abstraction, r.Likelihood, r.Severity, r.Description,
			nz(r.Prerequisites), nz(r.ExecutionFlow), nz(r.Indicators), nz(r.Mitigations), nz(r.CWEs), attack})
	}
	return s.replaceSnapshot(ctx, snapshot{
		table: "capec",
		columns: []string{"id", "name", "abstraction", "likelihood", "severity", "description",
			"prerequisites", "execution_flow", "indicators", "mitigations", "cwes", "attack"},
		key: []string{"id"}, rows: data,
	})
}

type DebianRow struct {
	CVEID, Package, Release, Status, FixedVersion, Urgency string
}

func (s *Store) ReplaceDebian(ctx context.Context, rows []DebianRow) (inserted, updated, deleted int, err error) {
	data := make([][]any, len(rows))
	for i, r := range rows {
		data[i] = []any{r.CVEID, r.Package, r.Release, r.Status, nilIfEmpty(r.FixedVersion), nilIfEmpty(r.Urgency)}
	}
	return s.replaceSnapshot(ctx, snapshot{
		table:   "debian_status",
		columns: []string{"cve_id", "package", "release", "status", "fixed_version", "urgency"},
		key:     []string{"cve_id", "package", "release"}, rows: data,
	})
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type EUVDOut struct {
	EUVDID         string     `json:"euvd_id"`
	ExploitedSince *time.Time `json:"exploited_since"`
}

type DebianOut struct {
	Package      string  `json:"package"`
	Release      string  `json:"release"`
	Status       string  `json:"status"`
	FixedVersion *string `json:"fixed_version"`
	Urgency      *string `json:"urgency"`
}

// readContext fills the EUVD and Debian parts of a CVE detail.
func (s *Store) readContext(ctx context.Context, d *CVEDetail) error {
	var e EUVDOut
	err := s.pool.QueryRow(ctx, `SELECT euvd_id, exploited_since FROM euvd_exploited WHERE cve_id = $1`, d.ID).Scan(&e.EUVDID, &e.ExploitedSince)
	switch {
	case err == nil:
		d.EUVD = &e
	case err != pgx.ErrNoRows:
		return err
	}
	// Releases in Debian's order: oldest supported first, unstable last.
	rows, err := s.pool.Query(ctx, `
		SELECT package, release, status, fixed_version, urgency FROM debian_status WHERE cve_id = $1
		ORDER BY package, array_position(ARRAY['bullseye', 'bookworm', 'trixie', 'forky', 'sid'], release) NULLS LAST, release`, d.ID)
	if err != nil {
		return err
	}
	d.Debian, err = pgx.CollectRows(rows, pgx.RowToStructByPos[DebianOut])
	return err
}

type AttackOut struct {
	TechniqueID     string   `json:"technique_id"`
	MappingType     string   `json:"mapping_type"`
	TechniqueName   string   `json:"technique_name"`
	CapabilityGroup *string  `json:"capability_group"`
	Comments        *string  `json:"comments"`
	Refs            []string `json:"refs"`
}

type CAPECOut struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Abstraction   *string         `json:"abstraction"`
	Likelihood    *string         `json:"likelihood"`
	Severity      *string         `json:"severity"`
	Description   *string         `json:"description"`
	Prerequisites []string        `json:"prerequisites"`
	ExecutionFlow []string        `json:"execution_flow"`
	Indicators    []string        `json:"indicators"`
	Mitigations   []string        `json:"mitigations"`
	CWEs          []string        `json:"cwes"`
	Attack        json.RawMessage `json:"attack"`
}

// AttackMappings returns the CTID mappings for a CVE, exploitation
// techniques first.
func (s *Store) AttackMappings(ctx context.Context, cveID string) ([]AttackOut, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT technique_id, mapping_type, technique_name, capability_group, comments, refs FROM attack_mapping
		WHERE cve_id = $1
		ORDER BY array_position(ARRAY['exploitation_technique', 'primary_impact', 'secondary_impact'], mapping_type) NULLS LAST, technique_id`, cveID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AttackOut])
}

// CAPECForCWEs returns attack patterns related to any of the CWEs, most
// relevant first.
func (s *Store) CAPECForCWEs(ctx context.Context, cwes []string, limit int) ([]CAPECOut, error) {
	if len(cwes) == 0 {
		return []CAPECOut{}, nil
	}
	// Rank by how specific the shared CWEs are: a CWE linked to few patterns
	// (CWE-502: deserialization) says more than one linked to dozens
	// (CWE-20: input validation), so each shared CWE adds 1/(its pattern
	// count). Ties go to the more specific abstraction.
	rows, err := s.pool.Query(ctx, `
		WITH weight AS (
			SELECT cwe, 1.0 / count(*) AS w FROM capec, unnest(cwes) AS cwe WHERE cwe = ANY($1) GROUP BY cwe
		)
		, scored AS (
			SELECT c.*, (SELECT sum(w) FROM weight WHERE cwe = ANY(c.cwes)) AS score FROM capec c WHERE c.cwes && $1
		)
		SELECT id, name, abstraction, likelihood, severity, description, prerequisites, execution_flow,
		       indicators, mitigations, cwes, attack
		FROM scored
		-- Drop patterns reached only through a CWE shared by more than 40
		-- patterns, unless that is all there is.
		WHERE score >= 0.025 OR NOT EXISTS (SELECT 1 FROM scored WHERE score >= 0.025)
		ORDER BY score DESC,
		         array_position(ARRAY['Detailed', 'Standard', 'Meta'], abstraction) NULLS LAST,
		         (substr(id, 7))::int
		LIMIT $2`, cwes, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[CAPECOut])
}
