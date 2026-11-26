package easm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// crtSh collects subdomains and certificates from Certificate Transparency logs
// via crt.sh (passive, free, no key). Spec P04 + P06.
type crtSh struct{ client *http.Client }

func (crtSh) Name() string { return "crtsh" }

type crtEntry struct {
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	SerialNum  string `json:"serial_number"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

// fetchCRT gets crt.sh JSON with retries — crt.sh intermittently returns an
// HTML "please wait"/error page under load, so a non-JSON body is retried.
func fetchCRT(ctx context.Context, client *http.Client, u string) ([]crtEntry, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "pahredar-easm")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
		resp.Body.Close()
		trimmed := bytes.TrimSpace(body)
		if resp.StatusCode != http.StatusOK || len(trimmed) == 0 || trimmed[0] != '[' {
			lastErr = fmt.Errorf("status %d, non-JSON body", resp.StatusCode)
			continue
		}
		var entries []crtEntry
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			lastErr = err
			continue
		}
		return entries, nil
	}
	return nil, lastErr
}

func (c crtSh) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	entries, err := fetchCRT(ctx, c.client, u)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}

	subs := map[string]bool{} // dedup subdomains
	out := []db.AssetRecord{}
	certSeen := map[string]bool{}

	for _, e := range entries {
		// Subdomains from the SAN list (name_value is newline-separated).
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			if name == "" || name == domain || !strings.HasSuffix(name, "."+domain) {
				continue
			}
			subs[name] = true
		}
		// One record per certificate (dedup by serial).
		if e.SerialNum != "" && !certSeen[e.SerialNum] && len(certSeen) < 100 {
			certSeen[e.SerialNum] = true
			out = append(out, rec("cert", e.SerialNum, "crtsh", map[string]any{
				"common_name": e.CommonName,
				"issuer":      e.IssuerName,
				"not_before":  e.NotBefore,
				"not_after":   e.NotAfter,
			}, "crt.sh CT log"))
		}
	}

	names := make([]string, 0, len(subs))
	for s := range subs {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, rec("subdomain", name, "crtsh", map[string]any{"host": name}, "crt.sh CT log"))
	}
	return out, nil
}
