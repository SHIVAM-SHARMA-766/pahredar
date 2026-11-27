package easm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// Sensitive services that should rarely be exposed to the internet (A18 /
// Security Assessment). An open one is a high-severity finding.
var sensitivePorts = map[int]string{
	23: "Telnet", 21: "FTP", 445: "SMB", 1433: "MSSQL", 1521: "Oracle DB",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5672: "RabbitMQ",
	6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}

// certExpiryWarn is how close to expiry raises a warning finding.
const certExpiryWarn = 21 * 24 * time.Hour

// assess reads an asset's current evidence records and turns them into findings
// (stored as alert rows, type "easm"), which the incident loop rolls up into the
// asset's incident. Deduped on (type, asset, key); safe to run every scan.
func (s *Service) assess(ctx context.Context, assetID int64, clientID *int64) error {
	records, err := s.Store.ListRecords(ctx, assetID, "")
	if err != nil {
		return err
	}
	findings := buildFindings(assetID, records)
	if len(findings) == 0 {
		return nil
	}
	newOnes, err := s.Store.InsertAlerts(ctx, findings)
	if err != nil {
		return err
	}
	s.Log.Info("easm assessment", "asset_id", assetID, "findings", len(findings), "new", len(newOnes))
	// Roll the findings into the asset's incident now (same as dependency
	// analysis), so a scan's results surface immediately instead of waiting for
	// the 15-minute incident sweep.
	if rerr := s.Store.RefreshIncidents(ctx); rerr != nil {
		s.Log.Warn("refresh incidents after easm assessment failed", "err", rerr)
	}
	return nil
}

// buildFindings runs the security checks over an asset's records and returns the
// findings as alert rows (pure; no I/O).
func buildFindings(assetID int64, records []db.AssetRecord) []db.Alert {
	var findings []db.Alert
	add := func(key, severity, title, detail string) {
		id := assetID
		findings = append(findings, db.Alert{Type: "easm", AssetID: &id, CVEID: key, Severity: severity, Title: title, Detail: detail})
	}

	for _, r := range records {
		switch r.Category {
		case "cert":
			if r.Source != "tls_probe" { // assess only the live cert, not CT history
				continue
			}
			var d struct {
				NotAfter   string `json:"not_after"`
				Expired    bool   `json:"expired"`
				SelfSigned bool   `json:"self_signed"`
			}
			_ = json.Unmarshal(r.Data, &d)
			if d.Expired {
				add("cert-expired", "high", "TLS certificate expired", "The live certificate has expired.")
			} else if t, perr := time.Parse(time.RFC3339, d.NotAfter); perr == nil && time.Until(t) < certExpiryWarn {
				add("cert-expiring", "medium", "TLS certificate expiring soon", fmt.Sprintf("The certificate expires on %s.", d.NotAfter))
			}
			if d.SelfSigned {
				add("cert-self-signed", "medium", "Self-signed TLS certificate", "The live certificate is self-signed.")
			}
		case "tls":
			if r.Source != "tls_probe" {
				continue
			}
			var d struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(r.Data, &d)
			if d.Version == "TLS 1.0" || d.Version == "TLS 1.1" {
				add("tls-weak", "medium", "Deprecated TLS version", "The server negotiated "+d.Version+", which is deprecated.")
			}
		case "http_security":
			var d struct {
				Present bool `json:"present"`
			}
			_ = json.Unmarshal(r.Data, &d)
			if d.Present {
				continue
			}
			switch r.Key {
			case "strict-transport-security":
				add("hsts-missing", "low", "Missing HSTS header", "The HTTPS response has no Strict-Transport-Security header.")
			case "content-security-policy":
				add("csp-missing", "low", "Missing Content-Security-Policy", "The response has no Content-Security-Policy header.")
			}
		case "port":
			var d struct {
				Port    int    `json:"port"`
				Service string `json:"service"`
			}
			_ = json.Unmarshal(r.Data, &d)
			if name, ok := sensitivePorts[d.Port]; ok {
				add(fmt.Sprintf("port-exposed-%d", d.Port), "high", "Exposed "+name+" service",
					fmt.Sprintf("%s (port %d) is reachable from the internet on %s.", name, d.Port, r.Key))
			}
		case "email":
			var d struct {
				Present bool   `json:"present"`
				Policy  string `json:"policy"`
			}
			_ = json.Unmarshal(r.Data, &d)
			if r.Key == "spf" && !d.Present {
				add("spf-missing", "medium", "No SPF record", "The domain has no SPF record; email can be spoofed.")
			}
			if r.Key == "dmarc" {
				if !d.Present {
					add("dmarc-missing", "medium", "No DMARC record", "The domain has no DMARC record.")
				} else if d.Policy == "none" || d.Policy == "" {
					add("dmarc-weak", "low", "Weak DMARC policy", "DMARC policy is p=none (monitoring only).")
				}
			}
		}
	}
	return findings
}
