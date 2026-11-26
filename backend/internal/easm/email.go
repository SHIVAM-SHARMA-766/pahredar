package easm

import (
	"context"
	"net"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// emailAuth collects email authentication posture — SPF (TXT v=spf1) and DMARC
// (_dmarc TXT) — via live DNS. Spec P09. method=active.
type emailAuth struct{}

func (emailAuth) Name() string { return "email_auth" }

func (emailAuth) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	r := net.DefaultResolver
	out := []db.AssetRecord{}

	// SPF: the TXT record starting with v=spf1.
	if txts, err := r.LookupTXT(ctx, domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				out = append(out, recActive("email", "spf", "dns_txt", map[string]any{"present": true, "record": t}, "live DNS TXT"))
				break
			}
		}
	}
	if !has(out, "spf") {
		out = append(out, recActive("email", "spf", "dns_txt", map[string]any{"present": false}, "no v=spf1 TXT"))
	}

	// DMARC: _dmarc.<domain> TXT starting with v=DMARC1.
	dmarcFound := false
	if txts, err := r.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				out = append(out, recActive("email", "dmarc", "dns_txt", map[string]any{"present": true, "record": t, "policy": dmarcPolicy(t)}, "live DNS TXT"))
				dmarcFound = true
				break
			}
		}
	}
	if !dmarcFound {
		out = append(out, recActive("email", "dmarc", "dns_txt", map[string]any{"present": false}, "no DMARC record"))
	}

	return out, nil
}

func has(recs []db.AssetRecord, key string) bool {
	for _, r := range recs {
		if r.Key == key {
			return true
		}
	}
	return false
}

// dmarcPolicy extracts the p= policy tag from a DMARC record.
func dmarcPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "p=") {
			return strings.TrimSpace(part[2:])
		}
	}
	return ""
}
