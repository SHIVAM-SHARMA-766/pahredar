package scan

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
)

// DNSInfo holds the records the scan looked up.
type DNSInfo struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	MX    []string `json:"mx"`
	NS    []string `json:"ns"`
	TXT   []string `json:"txt"`
	CAA   []string `json:"caa"`
	SPF   string   `json:"spf"`
	DMARC string   `json:"dmarc"`
	DKIM  []string `json:"dkim"` // selectors found (e.g. "google", "selector1")
}

// dkimSelectors are common DKIM selector names to probe.
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "dkim", "mail", "s1", "s2", "mandrill", "mailjet", "zoho", "amazonses"}

// checkDNS looks up the common records and flags email- and
// certificate-issuance hardening that is missing.
func (sc *Scanner) checkDNS(ctx context.Context, host string, rep *Report, mu *sync.Mutex) error {
	r := net.DefaultResolver
	info := &DNSInfo{A: []string{}, AAAA: []string{}, MX: []string{}, NS: []string{}, TXT: []string{}, CAA: []string{}}

	if ips, err := r.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				info.A = append(info.A, ip.String())
			} else {
				info.AAAA = append(info.AAAA, ip.String())
			}
		}
	}
	if mx, err := r.LookupMX(ctx, host); err == nil {
		for _, m := range mx {
			info.MX = append(info.MX, strings.TrimSuffix(m.Host, "."))
		}
	}
	if ns, err := r.LookupNS(ctx, host); err == nil {
		for _, n := range ns {
			info.NS = append(info.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if txt, err := r.LookupTXT(ctx, host); err == nil {
		info.TXT = txt
		for _, t := range txt {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				info.SPF = t
			}
		}
	}
	if dmarc, err := r.LookupTXT(ctx, "_dmarc."+host); err == nil {
		for _, t := range dmarc {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				info.DMARC = t
			}
		}
	}
	// DKIM: probe common selectors concurrently; a hit means that selector
	// publishes a key.
	info.DKIM = []string{}
	var dkmu sync.Mutex
	var dkwg sync.WaitGroup
	for _, sel := range dkimSelectors {
		sel := sel
		dkwg.Add(1)
		go func() {
			defer dkwg.Done()
			txts, err := r.LookupTXT(ctx, sel+"._domainkey."+host)
			if err != nil {
				return
			}
			for _, t := range txts {
				lt := strings.ToLower(t)
				if !strings.Contains(lt, "v=dkim1") && !strings.Contains(lt, "k=rsa") && !strings.Contains(lt, "k=ed25519") {
					continue
				}
				// A published, usable selector has a non-empty public key; an
				// empty p= is a revoked/placeholder key (some domains publish
				// a wildcard "v=DKIM1; p=").
				if dkimKey(t) == "" {
					continue
				}
				dkmu.Lock()
				info.DKIM = append(info.DKIM, sel)
				dkmu.Unlock()
				return
			}
		}()
	}
	dkwg.Wait()
	sort.Strings(info.DKIM)

	mu.Lock()
	defer mu.Unlock()
	rep.DNS = info

	// Email hardening matters when the domain sends mail (has MX) or is a
	// bare apex a brand would protect; flag it as low/medium either way.
	sev := SevLow
	if len(info.MX) > 0 {
		sev = SevMedium
	}
	if info.SPF == "" {
		rep.add(sev, "dns", "No SPF record", "Without an SPF record, anyone can send email claiming to be from this domain. Publish a TXT record starting v=spf1.")
	} else if strings.Contains(strings.ToLower(info.SPF), "+all") {
		rep.add(SevHigh, "dns", "SPF allows any sender (+all)", "The SPF record ends in +all, which authorises every host to send as this domain. Use -all or ~all.")
	}
	if info.DMARC == "" {
		rep.add(sev, "dns", "No DMARC record", "Without DMARC, receivers cannot tell how to handle mail that fails SPF/DKIM. Publish _dmarc."+host+" TXT with v=DMARC1.")
	} else if strings.Contains(strings.ToLower(info.DMARC), "p=none") {
		rep.add(SevLow, "dns", "DMARC policy is p=none", "DMARC is in monitor-only mode; spoofed mail is still delivered. Move to p=quarantine or p=reject once reports look clean.")
	} else {
		rep.add(SevGood, "dns", "DMARC enforced", info.DMARC)
	}
	return nil
}

// dkimKey extracts the public-key value (p=) from a DKIM TXT record, trimmed.
func dkimKey(txt string) string {
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "p="); ok {
			return strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(part, "P="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
