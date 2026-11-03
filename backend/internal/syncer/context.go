package syncer

import (
	"context"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/attack"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/debian"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/euvd"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/vulncheck"
)

const (
	SourceEUVD      = "euvd"
	SourceAttack    = "attack"
	SourceCAPEC     = "capec"
	SourceDebian    = "debian"
	SourceVulnCheck = "vulncheck"
)

// snapshotRun wraps a snapshot sync: fetch, replace, record the run time
// as the cursor.
func (e *Enrichment) snapshotRun(ctx context.Context, source string, replace func(context.Context) (int, int, int, error)) error {
	return e.runner.Run(ctx, source, e.snapshotPlan(source), func(ctx context.Context, run *Run) error {
		var err error
		if run.Inserted, run.Updated, run.Deleted, err = replace(ctx); err != nil {
			return err
		}
		return e.store.SetSyncCursor(ctx, source, time.Now().UTC().Format(time.RFC3339))
	})
}

func (e *Enrichment) SyncEUVD(ctx context.Context) error {
	return e.snapshotRun(ctx, SourceEUVD, func(ctx context.Context) (int, int, int, error) {
		entries, err := euvd.Fetch(ctx, e.http)
		if err != nil {
			return 0, 0, 0, err
		}
		rows := make([]db.EUVDRow, len(entries))
		for i, en := range entries {
			rows[i] = db.EUVDRow{CVEID: en.CVEID, EUVDID: en.EUVDID, ExploitedSince: en.ExploitedSince, Description: en.Description}
		}
		return e.store.ReplaceEUVD(ctx, rows)
	})
}

func (e *Enrichment) SyncAttack(ctx context.Context) error {
	return e.snapshotRun(ctx, SourceAttack, func(ctx context.Context) (int, int, int, error) {
		ms, err := attack.KEVMappings(ctx, e.http)
		if err != nil {
			return 0, 0, 0, err
		}
		rows := make([]db.AttackRow, len(ms))
		for i, m := range ms {
			rows[i] = db.AttackRow{CVEID: m.CVEID, TechniqueID: m.TechniqueID, MappingType: m.MappingType, TechniqueName: m.TechniqueName,
				CapabilityGroup: m.CapabilityGroup, Comments: m.Comments, Refs: m.References}
		}
		return e.store.ReplaceAttackMappings(ctx, rows)
	})
}

func (e *Enrichment) SyncCAPEC(ctx context.Context) error {
	return e.snapshotRun(ctx, SourceCAPEC, func(ctx context.Context) (int, int, int, error) {
		ps, err := attack.CAPEC(ctx, e.http)
		if err != nil {
			return 0, 0, 0, err
		}
		rows := make([]db.CAPECRow, len(ps))
		for i, p := range ps {
			techniques := p.Attack
			if techniques == nil {
				techniques = []attack.Technique{}
			}
			rows[i] = db.CAPECRow{ID: p.ID, Name: p.Name, Abstraction: p.Abstraction, Likelihood: p.Likelihood, Severity: p.Severity,
				Description: p.Description, Prerequisites: p.Prerequisites, ExecutionFlow: p.ExecutionFlow, Indicators: p.Indicators,
				Mitigations: p.Mitigations, CWEs: p.CWEs, Attack: techniques}
		}
		return e.store.ReplaceCAPEC(ctx, rows)
	})
}

func (e *Enrichment) SyncDebian(ctx context.Context) error {
	return e.snapshotRun(ctx, SourceDebian, func(ctx context.Context) (int, int, int, error) {
		st, err := debian.Fetch(ctx, e.http)
		if err != nil {
			return 0, 0, 0, err
		}
		rows := make([]db.DebianRow, len(st))
		for i, s := range st {
			rows[i] = db.DebianRow{CVEID: s.CVEID, Package: s.Package, Release: s.Release, Status: s.Status, FixedVersion: s.FixedVersion, Urgency: s.Urgency}
		}
		return e.store.ReplaceDebian(ctx, rows)
	})
}

// SyncVulnCheck snapshots VulnCheck KEV; it needs a (free) API token.
func (e *Enrichment) SyncVulnCheck(ctx context.Context, token string) error {
	return e.snapshotRun(ctx, SourceVulnCheck, func(ctx context.Context) (int, int, int, error) {
		entries, err := vulncheck.Fetch(ctx, e.http, token)
		if err != nil {
			return 0, 0, 0, err
		}
		rows := make([]db.VulnCheckRow, len(entries))
		for i, en := range entries {
			rows[i] = db.VulnCheckRow{CVEID: en.CVEID, Name: en.Name, Vendor: en.Vendor, Product: en.Product, DateAdded: en.DateAdded,
				Ransomware: en.Ransomware, Canary: en.Canary, Reported: en.Reported, XDB: en.XDB}
		}
		return e.store.ReplaceVulnCheckKEV(ctx, rows)
	})
}
