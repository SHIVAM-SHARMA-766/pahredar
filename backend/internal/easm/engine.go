package easm

import "context"

// runPassive opens a scan run, runs every passive collector against the domain,
// upserts their evidence records, and closes the run. A collector failure is
// logged and skipped; the run fails only when nothing at all was collected.
func (s *Service) runPassive(ctx context.Context, assetID int64, clientID *int64, domain string) error {
	runID, err := s.Store.CreateScanRun(ctx, assetID, clientID, "passive")
	if err != nil {
		return err
	}
	client := httpClient()
	count := 0
	var firstErr error
	for _, c := range passiveCollectors(client) {
		recs, cerr := c.Collect(ctx, domain)
		if cerr != nil {
			s.Log.Warn("easm collector failed", "collector", c.Name(), "domain", domain, "err", cerr)
			if firstErr == nil {
				firstErr = cerr
			}
			continue
		}
		for _, r := range recs {
			r.AssetID = assetID
			r.ClientID = clientID
			r.RunID = &runID
			if _, uerr := s.Store.UpsertRecord(ctx, r); uerr != nil {
				s.Log.Warn("easm record upsert failed", "err", uerr)
				continue
			}
			count++
		}
	}
	status, errMsg := "done", ""
	if count == 0 && firstErr != nil {
		status, errMsg = "failed", firstErr.Error()
	}
	s.Log.Info("easm passive scan complete", "asset_id", assetID, "records", count, "status", status)
	return s.Store.FinishScanRun(ctx, runID, status, count, errMsg)
}
