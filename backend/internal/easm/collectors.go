// Package easm is the External Attack Surface Management engine (Domain
// Intelligence / Active Recon / Security Assessment) over a shared evidence
// store. S1 builds the passive Domain Intelligence engine. See
// docs/scanner-easm.md.
package easm

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// Collector gathers evidence records for a domain from one source. It fills the
// category/key/method/source/data/evidence fields; the engine attaches the
// asset, client, and run.
type Collector interface {
	Name() string
	Collect(ctx context.Context, domain string) ([]db.AssetRecord, error)
}

// passiveCollectors are the Domain Intelligence collectors (free, no-key, third-
// party data — no contact with the target). See docs/scanner-easm.md §6, §12.
func passiveCollectors(client *http.Client) []Collector {
	return []Collector{
		crtSh{client: client},
		rdap{client: client},
		wayback{client: client},
	}
}

// lightActiveCollectors contact the target's DNS directly (live resolution) —
// low impact, but tagged method=active and kept separate.
func lightActiveCollectors() []Collector {
	return []Collector{
		dnsCollector{},
		emailAuth{},
	}
}

// activeCollectors contact the target's services directly (HTTP/TLS). Gated by
// the "active" profile + operator authorisation. Heavier probing (ports, dir
// discovery, Nuclei) comes later.
func activeCollectors() []Collector {
	return []Collector{
		httpProbe{},
		portScan{},
		wellKnown{},
		subBrute{},
		apiProbe{},
		cdnWAF{},
		jsAnalysis{},
		dirScan{},
		smtpProbe{},
	}
}

// collectorsFor returns the collectors a scan profile runs:
//   - passive:  third-party data only (no target contact)
//   - standard: passive + light-active DNS/email (default, monitor-first)
//   - active:   standard + direct HTTP/TLS probing (needs authorisation)
func collectorsFor(profile string, client *http.Client) []Collector {
	cs := passiveCollectors(client)
	if profile == "passive" {
		return cs
	}
	cs = append(cs, lightActiveCollectors()...)
	if profile == "active" {
		cs = append(cs, activeCollectors()...)
	}
	return cs
}

// httpClient is a shared client with a sane timeout for the collectors.
func httpClient() *http.Client { return &http.Client{Timeout: 20 * time.Second} }

// rec builds a passive evidence record with the common fields set.
func rec(category, key, source string, data any, evidence string) db.AssetRecord {
	return recM("passive", category, key, source, data, evidence)
}

// recActive builds an active (live) evidence record.
func recActive(category, key, source string, data any, evidence string) db.AssetRecord {
	return recM("active", category, key, source, data, evidence)
}

func recM(method, category, key, source string, data any, evidence string) db.AssetRecord {
	raw, _ := json.Marshal(data)
	verification := "unverified"
	if method == "active" {
		verification = "verified" // a live observation is verified
	}
	return db.AssetRecord{
		Category:     category,
		Key:          key,
		Method:       method,
		Source:       source,
		Data:         raw,
		Evidence:     evidence,
		Confidence:   "high",
		Verification: verification,
		Scope:        "in_scope",
	}
}

// getJSON fetches url and decodes JSON into v.
func getJSON(ctx context.Context, client *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pahredar-easm")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}
