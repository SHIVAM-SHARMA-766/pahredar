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

// queryOSV asks OSV (free, no key) whether a package version is vulnerable.
func queryOSV(ctx context.Context, client *http.Client, ecosystem, name, version string) ([]osvVuln, error) {
	body, _ := json.Marshal(map[string]any{
		"package": map[string]string{"ecosystem": ecosystem, "name": name},
		"version": version,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(body))
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
		return nil, fmt.Errorf("osv status %d", resp.StatusCode)
	}
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Vulns, nil
}

// cveAlias returns the CVE id from a vuln's aliases, if any.
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

// analyzeDeps queries OSV for every dependency record of an asset and returns
// the findings (alert rows). Bounded concurrency; a per-package failure is
// skipped.
func (s *Service) analyzeDeps(ctx context.Context, assetID int64, records []db.AssetRecord) []db.Alert {
	client := httpClient()
	type dep struct{ ecosystem, name, version string }
	deps := []dep{}
	for _, r := range records {
		if r.Category != "dependency" {
			continue
		}
		var d struct{ Ecosystem, Name, Version string }
		if json.Unmarshal(r.Data, &d) != nil || d.Name == "" || d.Version == "" {
			continue
		}
		deps = append(deps, dep{d.Ecosystem, d.Name, d.Version})
	}

	var mu sync.Mutex
	var findings []db.Alert
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, d := range deps {
		wg.Add(1)
		sem <- struct{}{}
		go func(d dep) {
			defer wg.Done()
			defer func() { <-sem }()
			vulns, err := queryOSV(ctx, client, d.ecosystem, d.name, d.version)
			if err != nil {
				s.Log.Warn("osv query failed", "pkg", d.name, "err", err)
				return
			}
			mu.Lock()
			for _, v := range vulns {
				id := assetID
				findings = append(findings, db.Alert{
					Type:     "dependency",
					AssetID:  &id,
					CVEID:    "dep:" + d.name + ":" + v.ID,
					Severity: v.severity(),
					Title:    fmt.Sprintf("Vulnerable dependency %s@%s", d.name, d.version),
					Detail:   fmt.Sprintf("%s (%s): %s", v.cveAlias(), v.ID, clip(v.Summary, 300)),
				})
			}
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return findings
}
