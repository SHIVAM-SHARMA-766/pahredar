package easm

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// dnsCollector resolves the domain's live DNS records (A/AAAA/NS/MX/TXT/CNAME)
// and emits one record per value, plus an `ip` record per resolved address.
// Live resolution → method=active. Spec P03/A01.
type dnsCollector struct{}

func (dnsCollector) Name() string { return "dns_resolve" }

func (dnsCollector) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	r := net.DefaultResolver
	out := []db.AssetRecord{}
	var errs []string

	// A / AAAA (+ ip records).
	if ips, err := r.LookupIP(ctx, "ip", domain); err != nil {
		errs = append(errs, "ip: "+err.Error())
	} else {
		seen := map[string]bool{}
		for _, ip := range ips {
			s := ip.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			typ := "A"
			if ip.To4() == nil {
				typ = "AAAA"
			}
			out = append(out, recActive("dns", typ+" "+s, "dns_resolve", map[string]any{"type": typ, "value": s}, "live DNS"))
			out = append(out, recActive("ip", s, "dns_resolve", map[string]any{"ip": s, "from": domain}, "live DNS"))
		}
	}

	// NS.
	if nss, err := r.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			h := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
			out = append(out, recActive("dns", "NS "+h, "dns_resolve", map[string]any{"type": "NS", "value": h}, "live DNS"))
		}
	}

	// MX.
	if mxs, err := r.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			h := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
			out = append(out, recActive("dns", fmt.Sprintf("MX %d %s", mx.Pref, h), "dns_resolve",
				map[string]any{"type": "MX", "host": h, "preference": mx.Pref}, "live DNS"))
		}
	}

	// TXT.
	if txts, err := r.LookupTXT(ctx, domain); err == nil {
		sort.Strings(txts)
		for _, t := range txts {
			out = append(out, recActive("dns", "TXT "+clip(t, 120), "dns_resolve", map[string]any{"type": "TXT", "value": t}, "live DNS"))
		}
	}

	// CNAME (only meaningful when it differs from the domain).
	if cname, err := r.LookupCNAME(ctx, domain); err == nil {
		c := strings.ToLower(strings.TrimSuffix(cname, "."))
		if c != "" && c != domain {
			out = append(out, recActive("dns", "CNAME "+c, "dns_resolve", map[string]any{"type": "CNAME", "value": c}, "live DNS"))
		}
	}

	if len(out) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("dns: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
