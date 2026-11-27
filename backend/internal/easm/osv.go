package easm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// osvVuln is the subset of an OSV vulnerability we keep.
type osvVuln struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Aliases          []string        `json:"aliases"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

func (v osvVuln) cveAlias() string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// severity reads GHSA's database_specific.severity, mapped to our scale.
func (v osvVuln) severity() string {
	var ds struct {
		Severity string `json:"severity"`
	}
	_ = json.Unmarshal(v.DatabaseSpecific, &ds)
	switch strings.ToUpper(ds.Severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

type osvQuery struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

// osvBatch returns the vuln IDs for each query, in order (OSV /v1/querybatch,
// free, no key). Only IDs come back; details are fetched separately.
func osvBatch(ctx context.Context, client *http.Client, queries []osvQuery) ([][]string, error) {
	body, _ := json.Marshal(map[string]any{"queries": queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv batch status %d", resp.StatusCode)
	}
	var out struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	ids := make([][]string, len(out.Results))
	for i, r := range out.Results {
		for _, v := range r.Vulns {
			ids[i] = append(ids[i], v.ID)
		}
	}
	return ids, nil
}

// osvDetail fetches one vulnerability's details.
func osvDetail(ctx context.Context, client *http.Client, id string) (osvVuln, error) {
	var v osvVuln
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.osv.dev/v1/vulns/"+id, nil)
	if err != nil {
		return v, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("osv vuln status %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&v)
	return v, err
}

// analyzeDeps batch-queries OSV for every dependency record (handling large
// SBOMs), fetches the details of the distinct vulnerabilities found, and returns
// one finding per (dependency, vuln).
func (s *Service) analyzeDeps(ctx context.Context, assetID int64, records []db.AssetRecord) []db.Alert {
	client := httpClient()
	type dep struct{ ecosystem, name, version string }
	var deps []dep
	var queries []osvQuery
	for _, r := range records {
		if r.Category != "dependency" {
			continue
		}
		var d struct{ Ecosystem, Name, Version string }
		if json.Unmarshal(r.Data, &d) != nil || d.Name == "" || d.Version == "" {
			continue
		}
		deps = append(deps, dep{d.Ecosystem, d.Name, d.Version})
		var q osvQuery
		q.Package.Ecosystem, q.Package.Name, q.Version = d.Ecosystem, d.Name, d.Version
		queries = append(queries, q)
	}
	if len(queries) == 0 {
		return nil
	}

	// Batch in chunks; collect vuln IDs per dependency.
	idsPerDep := make([][]string, len(queries))
	const chunk = 500
	for i := 0; i < len(queries); i += chunk {
		end := min(i+chunk, len(queries))
		res, err := osvBatch(ctx, client, queries[i:end])
		if err != nil {
			s.Log.Warn("osv batch failed", "err", err)
			continue
		}
		copy(idsPerDep[i:end], res)
	}

	// Fetch details for the distinct vulns found (bounded concurrency).
	distinct := map[string]bool{}
	for _, ids := range idsPerDep {
		for _, id := range ids {
			distinct[id] = true
		}
	}
	details := map[string]osvVuln{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for id := range distinct {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			if v, err := osvDetail(ctx, client, id); err == nil {
				mu.Lock()
				details[id] = v
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()

	var findings []db.Alert
	for i, ids := range idsPerDep {
		for _, id := range ids {
			v, ok := details[id]
			if !ok {
				v = osvVuln{ID: id}
			}
			aid := assetID
			findings = append(findings, db.Alert{
				Type:     "dependency",
				AssetID:  &aid,
				CVEID:    "dep:" + deps[i].name + ":" + id,
				Severity: v.severity(),
				Title:    fmt.Sprintf("Vulnerable dependency %s@%s", deps[i].name, deps[i].version),
				Detail:   fmt.Sprintf("%s (%s): %s", v.cveAlias(), id, clip(v.Summary, 300)),
			})
		}
	}
	return findings
}
