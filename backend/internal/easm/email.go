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

	// MTA-STS: _mta-sts.<domain> TXT (v=STSv1). Signals SMTP TLS enforcement.
	out = append(out, txtPresence(ctx, r, "mta_sts", "_mta-sts."+domain, "v=stsv1", map[string]string{"id": "id"}))
	// TLS-RPT: _smtp._tls.<domain> TXT (v=TLSRPTv1). SMTP TLS reporting.
	out = append(out, txtPresence(ctx, r, "tls_rpt", "_smtp._tls."+domain, "v=tlsrptv1", map[string]string{"rua": "rua"}))
	// BIMI: default._bimi.<domain> TXT (v=BIMI1). Brand indicator / logo.
	out = append(out, txtPresence(ctx, r, "bimi", "default._bimi."+domain, "v=bimi1", map[string]string{"logo": "l"}))

	// DKIM: selectors are not enumerable, so probe a small set of common ones and
	// record those that publish a key.
	for _, sel := range commonDKIMSelectors {
		if txts, err := r.LookupTXT(ctx, sel+"._domainkey."+domain); err == nil {
			for _, t := range txts {
				lt := strings.ToLower(t)
				if strings.Contains(lt, "v=dkim1") || strings.Contains(lt, "k=rsa") || strings.Contains(lt, "p=") {
					out = append(out, recActive("email", "dkim:"+sel, "dns_txt", map[string]any{"present": true, "selector": sel}, "live DNS TXT"))
					break
				}
			}
		}
	}

	return out, nil
}

// commonDKIMSelectors are selectors used by common mail providers, probed since
// DKIM selectors cannot be enumerated from DNS.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "dkim", "mail",
	"s1", "s2", "mandrill", "mailchimp", "zoho", "protonmail", "fm1",
}

// txtPresence looks up a TXT record and returns a presence record, extracting the
// given tag values (tagKey→tagName in the record) when present.
func txtPresence(ctx context.Context, r *net.Resolver, key, name, prefix string, tags map[string]string) db.AssetRecord {
	if txts, err := r.LookupTXT(ctx, name); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), prefix) {
				data := map[string]any{"present": true, "record": t}
				for outKey, tag := range tags {
					if v := txtTag(t, tag); v != "" {
						data[outKey] = v
					}
				}
				return recActive("email", key, "dns_txt", data, "live DNS TXT")
			}
		}
	}
	return recActive("email", key, "dns_txt", map[string]any{"present": false}, "no "+key+" record")
}

// txtTag extracts a `tag=value` from a semicolon-separated record (case-
// insensitive tag match), e.g. BIMI "l=" or MTA-STS "id=".
func txtTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), strings.ToLower(tag)+"=") {
			return strings.TrimSpace(part[len(tag)+1:])
		}
	}
	return ""
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
