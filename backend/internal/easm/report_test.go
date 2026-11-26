package easm

import (
	"encoding/json"
	"testing"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

func rawrec(category, key string, data any) db.AssetRecord {
	raw, _ := json.Marshal(data)
	return db.AssetRecord{Category: category, Key: key, Data: raw}
}

func TestBuildSummary(t *testing.T) {
	recs := []db.AssetRecord{
		rawrec("whois", "registration", map[string]any{"registrar": "Example Registrar"}),
		rawrec("subdomain", "api.example.com", map[string]any{"host": "api.example.com"}),
		rawrec("subdomain", "www.example.com", map[string]any{"host": "www.example.com"}),
		rawrec("ip", "1.2.3.4", map[string]any{"ip": "1.2.3.4"}),
		rawrec("ip", "1.2.3.4", map[string]any{"org": "Acme", "network": "ACME-NET", "country": "US"}), // merges onto same ip
		rawrec("cert", "serialA", map[string]any{"not_after": "2027-05-01T00:00:00"}),
		rawrec("cert", "serialB", map[string]any{"not_after": "2026-12-01T00:00:00"}),
		rawrec("email", "spf", map[string]any{"present": true}),
		rawrec("email", "dmarc", map[string]any{"present": true, "policy": "reject"}),
	}
	s := buildSummary(7, recs)

	if s.AssetID != 7 {
		t.Fatalf("asset id: got %d", s.AssetID)
	}
	if len(s.Subdomains) != 2 || s.Subdomains[0] != "api.example.com" {
		t.Fatalf("subdomains: %v", s.Subdomains)
	}
	if len(s.IPs) != 1 || s.IPs[0].Org != "Acme" || s.IPs[0].Country != "US" {
		t.Fatalf("ips not merged: %+v", s.IPs)
	}
	if s.Certs.Count != 2 || s.Certs.SoonestNotAfter != "2026-12-01T00:00:00" {
		t.Fatalf("certs: %+v", s.Certs)
	}
	if s.Email.SPF == nil || !*s.Email.SPF || s.Email.Policy != "reject" {
		t.Fatalf("email: %+v", s.Email)
	}
	if s.Counts["subdomain"] != 2 || s.Counts["ip"] != 2 {
		t.Fatalf("counts: %v", s.Counts)
	}
}
