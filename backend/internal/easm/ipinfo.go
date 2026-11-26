package easm

import (
	"context"
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// ipRDAP is the subset of an RDAP IP response we keep.
type ipRDAP struct {
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	Country      string       `json:"country"`
	Type         string       `json:"type"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Entities     []rdapEntity `json:"entities"`
}

// enrichIP looks up an IP's network/owner via RDAP (RIR databases — passive,
// free, no key). Spec P05. Returns an enriched `ip` record, or ok=false.
func enrichIP(ctx context.Context, client *http.Client, ip string) (db.AssetRecord, bool) {
	var r ipRDAP
	if err := getJSON(ctx, client, "https://rdap.org/ip/"+ip, &r); err != nil {
		return db.AssetRecord{}, false
	}
	org := ""
	for _, e := range r.Entities {
		if n := vcardName(e.VCardArray); n != "" {
			org = n
			break
		}
		if org == "" {
			org = e.Handle
		}
	}
	return rec("ip", ip, "rdap_ip", map[string]any{
		"ip":      ip,
		"network": r.Name,
		"handle":  r.Handle,
		"country": r.Country,
		"range":   rangeStr(r.StartAddress, r.EndAddress),
		"org":     org,
	}, "RDAP IP"), true
}

func rangeStr(start, end string) string {
	if start == "" {
		return ""
	}
	if end == "" {
		return start
	}
	return start + " – " + end
}
