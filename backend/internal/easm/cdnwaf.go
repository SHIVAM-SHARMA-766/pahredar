package easm

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// cdnWAF fingerprints the CDN / WAF / edge in front of a site from its HTTP
// response headers (A16). Knowing the edge matters for scope (a CDN IP is not
// the origin) and for interpreting other findings. method=active: one GET.
type cdnWAF struct{}

func (cdnWAF) Name() string { return "cdn_waf" }

// edgeSig matches a provider by a response header's presence (value "") or a
// substring of its value (case-insensitive). kind is cdn or waf.
type edgeSig struct {
	provider, kind, header, contains string
}

var edgeSigs = []edgeSig{
	{"Cloudflare", "cdn", "cf-ray", ""},
	{"Cloudflare", "cdn", "server", "cloudflare"},
	{"AWS CloudFront", "cdn", "x-amz-cf-id", ""},
	{"AWS CloudFront", "cdn", "via", "cloudfront"},
	{"Akamai", "cdn", "server", "akamaighost"},
	{"Akamai", "cdn", "x-akamai-transformed", ""},
	{"Fastly", "cdn", "x-served-by", "cache-"},
	{"Fastly", "cdn", "x-fastly-request-id", ""},
	{"Vercel", "cdn", "server", "vercel"},
	{"Vercel", "cdn", "x-vercel-id", ""},
	{"Netlify", "cdn", "server", "netlify"},
	{"Google Cloud", "cdn", "via", "google"},
	{"Sucuri", "waf", "server", "sucuri"},
	{"Sucuri", "waf", "x-sucuri-id", ""},
	{"Imperva Incapsula", "waf", "x-iinfo", ""},
	{"Imperva Incapsula", "waf", "x-cdn", "incapsula"},
	{"F5 BIG-IP", "waf", "server", "big-ip"},
	{"Barracuda", "waf", "server", "barracuda"},
	{"Cloudflare", "waf", "cf-mitigated", ""},
}

func (cdnWAF) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	client := wellKnownClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pahredar-easm")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil // unreachable → nothing to record (not a hard error)
	}
	resp.Body.Close()
	return cdnWAFRecords(resp.Header), nil
}

// cdnWAFRecords matches a response's headers against the edge signatures. Pure.
func cdnWAFRecords(h http.Header) []db.AssetRecord {
	found := map[string]edgeSig{} // provider|kind → sig
	for _, s := range edgeSigs {
		v := h.Get(s.header)
		if v == "" && !headerPresent(h, s.header) {
			continue
		}
		if s.contains == "" || strings.Contains(strings.ToLower(v), s.contains) {
			found[s.provider+"|"+s.kind] = s
		}
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []db.AssetRecord{}
	for _, k := range keys {
		s := found[k]
		out = append(out, recActive("cdn_waf", strings.ToLower(s.provider)+":"+s.kind, "http_probe",
			map[string]any{"provider": s.provider, "kind": s.kind, "matched_header": s.header}, "edge fingerprint"))
	}
	return out
}

// headerPresent reports whether a header key exists (even with an empty value).
func headerPresent(h http.Header, key string) bool {
	_, ok := h[http.CanonicalHeaderKey(key)]
	return ok
}
