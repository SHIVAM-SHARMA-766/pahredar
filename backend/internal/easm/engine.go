package easm

import (
	"context"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// runScan opens a scan run, runs the profile's collectors against the domain,
// enriches discovered IPs via RDAP, and upserts every evidence record. A
// collector failure is logged and skipped; the run fails only when nothing at
// all was collected.
func (s *Service) runScan(ctx context.Context, assetID int64, clientID *int64, domain, profile string) error {
	runID, err := s.Store.CreateScanRun(ctx, assetID, clientID, profile)
	if err != nil {
		return err
	}
	client := httpClient()

	var records []db.AssetRecord
	var firstErr error
	for _, c := range collectorsFor(profile, client) {
		recs, cerr := c.Collect(ctx, domain)
		if cerr != nil {
			s.Log.Warn("easm collector failed", "collector", c.Name(), "domain", domain, "err", cerr)
			if firstErr == nil {
				firstErr = cerr
			}
			continue
		}
		records = append(records, recs...)
	}

	// Enrich unique IPs (from DNS) with network/owner via RDAP.
	for _, ip := range uniqueIPs(records) {
		if enriched, ok := enrichIP(ctx, client, ip); ok {
			records = append(records, enriched)
		}
	}

	count := 0
	for _, r := range records {
		r.AssetID = assetID
		r.ClientID = clientID
		r.RunID = &runID
		if _, uerr := s.Store.UpsertRecord(ctx, r); uerr != nil {
			s.Log.Warn("easm record upsert failed", "err", uerr)
			continue
		}
		count++
	}

	status, errMsg := "done", ""
	if count == 0 && firstErr != nil {
		status, errMsg = "failed", firstErr.Error()
	}
	s.Log.Info("easm scan complete", "asset_id", assetID, "records", count, "status", status)
	return s.Store.FinishScanRun(ctx, runID, status, count, errMsg)
}

// uniqueIPs returns the distinct IPs across the gathered ip records.
func uniqueIPs(records []db.AssetRecord) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range records {
		if r.Category == "ip" && !seen[r.Key] {
			seen[r.Key] = true
			out = append(out, r.Key)
		}
	}
	return out
}
