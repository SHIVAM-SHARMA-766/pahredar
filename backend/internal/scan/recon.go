package scan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Recon gathers everything discoverable about the target from public sources:
// domain registration (RDAP), the hosting network (reverse DNS, ASN, RDAP),
// and subdomains (Certificate Transparency logs). These query third-party
// public services, not the target, and carry no attack payloads.

// DomainInfo is the registration record from RDAP (modern WHOIS).
type DomainInfo struct {
	Domain        string   `json:"domain"`
	Registrar     string   `json:"registrar,omitempty"`
	RegistrantOrg string   `json:"registrant_org,omitempty"`
	Created       string   `json:"created,omitempty"`
	Updated       string   `json:"updated,omitempty"`
	Expires       string   `json:"expires,omitempty"`
	Statuses      []string `json:"statuses"`
	Nameservers   []string `json:"nameservers"`
	DNSSEC        bool     `json:"dnssec"`
}

// NetInfo describes the IP and the network hosting it.
type NetInfo struct {
	IP       string `json:"ip"`
	PTR      string `json:"ptr,omitempty"`
	ASN      string `json:"asn,omitempty"`
	ASOrg    string `json:"as_org,omitempty"`
	NetName  string `json:"net_name,omitempty"`
	NetRange string `json:"net_range,omitempty"`
	Country  string `json:"country,omitempty"`
	Org      string `json:"org,omitempty"`
}

// PortOut is one TCP port probed by the active scan.
type PortOut struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Open    bool   `json:"open"`
}

const rdapBase = "https://rdap.org"

// getJSON fetches a URL with an RDAP/JSON Accept header into v.
func (sc *Scanner) getJSON(ctx context.Context, url, accept string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", scannerUA)
	req.Header.Set("Accept", accept)
	resp, err := sc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return json.Unmarshal(body, v)
}

// rdapResponse is the subset of an RDAP domain/IP object we read.
type rdapResponse struct {
	LDHName   string   `json:"ldhName"`
	Handle    string   `json:"handle"`
	Name      string   `json:"name"`
	Country   string   `json:"country"`
	StartAddr string   `json:"startAddress"`
	EndAddr   string   `json:"endAddress"`
	Status    []string `json:"status"`
	Events    []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Entities []rdapEntity `json:"entities"`
	CIDR0    []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
}

type rdapEntity struct {
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
}

// vcard pulls a named property (fn, org) out of an RDAP jCard array.
func (e rdapEntity) vcard(prop string) string {
	if len(e.VCardArray) < 2 {
		return ""
	}
	items, ok := e.VCardArray[1].([]any)
	if !ok {
		return ""
	}
	for _, it := range items {
		f, ok := it.([]any)
		if !ok || len(f) < 4 {
			continue
		}
		if name, _ := f[0].(string); strings.EqualFold(name, prop) {
			if s, ok := f[3].(string); ok {
				return s
			}
		}
	}
	return ""
}

func (r rdapResponse) entityName(role string) string {
	for _, e := range r.Entities {
		for _, ro := range e.Roles {
			if strings.EqualFold(ro, role) {
				if org := e.vcard("org"); org != "" {
					return org
				}
				return e.vcard("fn")
			}
		}
	}
	return ""
}

func (r rdapResponse) event(action string) string {
	for _, ev := range r.Events {
		if strings.EqualFold(ev.Action, action) {
			if t, err := time.Parse(time.RFC3339, ev.Date); err == nil {
				return t.UTC().Format("2006-01-02")
			}
			return ev.Date
		}
	}
	return ""
}

// checkDomain looks up the registrable domain's registration via RDAP.
func (sc *Scanner) checkDomain(ctx context.Context, host string, rep *Report, mu *sync.Mutex) error {
	domain := baseDomain(host)
	var r rdapResponse
	if err := sc.getJSON(ctx, rdapBase+"/domain/"+domain, "application/rdap+json", &r); err != nil {
		return nil // registration is best-effort; absence is not an error
	}
	d := &DomainInfo{
		Domain:        domain,
		Registrar:     r.entityName("registrar"),
		RegistrantOrg: r.entityName("registrant"),
		Created:       r.event("registration"),
		Updated:       r.event("last changed"),
		Expires:       r.event("expiration"),
		Statuses:      r.Status,
		DNSSEC:        r.SecureDNS.DelegationSigned,
		Nameservers:   []string{},
	}
	for _, ns := range r.Nameservers {
		d.Nameservers = append(d.Nameservers, strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")))
	}
	if d.Statuses == nil {
		d.Statuses = []string{}
	}
	mu.Lock()
	rep.Domain = d
	mu.Unlock()
	return nil
}

// checkNet resolves the hosting network: reverse DNS, ASN (Team Cymru), and
// the RDAP IP registration.
func (sc *Scanner) checkNet(ctx context.Context, ip string, rep *Report, mu *sync.Mutex) error {
	n := &NetInfo{IP: ip}
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		n.PTR = strings.TrimSuffix(names[0], ".")
	}
	asn, org, country, prefix := cymruASN(ctx, ip)
	if asn != "" {
		n.ASN = "AS" + asn
		n.ASOrg = org
		n.NetRange = prefix
		if country != "" {
			n.Country = country
		}
	}
	var r rdapResponse
	if err := sc.getJSON(ctx, rdapBase+"/ip/"+ip, "application/rdap+json", &r); err == nil {
		n.NetName = r.Name
		if r.Country != "" {
			n.Country = r.Country
		}
		if org := r.entityName("registrant"); org != "" {
			n.Org = org
		}
		if n.NetRange == "" && r.StartAddr != "" {
			n.NetRange = r.StartAddr + " – " + r.EndAddr
		}
	}
	mu.Lock()
	rep.Net = n
	mu.Unlock()
	return nil
}

// cymruASN maps an IPv4 address to its origin ASN via Team Cymru's DNS
// service (free, no key). Returns asn, org, country, prefix.
func cymruASN(ctx context.Context, ipStr string) (asn, org, country, prefix string) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return // IPv6 origin lookup uses a different format; skip
	}
	q := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ip[3], ip[2], ip[1], ip[0])
	txts, err := net.DefaultResolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return
	}
	// "13335 | 104.16.0.0/12 | US | arin | 2010-07-14"
	parts := splitPipe(txts[0])
	if len(parts) >= 3 {
		asn = firstField(parts[0])
		prefix = parts[1]
		country = parts[2]
	}
	if asn != "" {
		if a, err := net.DefaultResolver.LookupTXT(ctx, "AS"+asn+".asn.cymru.com"); err == nil && len(a) > 0 {
			// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
			ap := splitPipe(a[0])
			if len(ap) >= 5 {
				org = strings.TrimSpace(ap[4])
			}
		}
	}
	return
}

func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// checkSubdomains discovers subdomains from Certificate Transparency logs,
// passive public sources. It tries crt.sh first and falls back to Cert
// Spotter (both free, no key); crt.sh is often overloaded.
func (sc *Scanner) checkSubdomains(ctx context.Context, host string, rep *Report, mu *sync.Mutex) error {
	domain := baseDomain(host)
	cctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()

	names := sc.crtSh(cctx, domain)
	if len(names) == 0 {
		names = sc.certSpotter(cctx, domain)
	}

	seen := map[string]bool{}
	out := []string{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
		if name == "" || name == domain || strings.ContainsAny(name, " *") || !strings.HasSuffix(name, "."+domain) {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) > 200 {
		out = out[:200]
	}
	mu.Lock()
	rep.Subdomains = mergeStrings(rep.Subdomains, out)
	mu.Unlock()
	return nil
}

func (sc *Scanner) crtSh(ctx context.Context, domain string) []string {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := sc.getJSON(ctx, "https://crt.sh/?q=%25."+domain+"&output=json", "application/json", &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.Split(r.NameValue, "\n")...)
	}
	return out
}

func (sc *Scanner) certSpotter(ctx context.Context, domain string) []string {
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	url := "https://api.certspotter.com/v1/issuances?domain=" + domain + "&include_subdomains=true&expand=dns_names"
	if err := sc.getJSON(ctx, url, "application/json", &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range append(a, b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// commonPorts are TCP ports the active scan connects to.
var commonPorts = []struct {
	port int
	svc  string
}{
	{21, "ftp"}, {22, "ssh"}, {25, "smtp"}, {53, "dns"}, {80, "http"},
	{110, "pop3"}, {143, "imap"}, {443, "https"}, {445, "smb"}, {3306, "mysql"},
	{3389, "rdp"}, {5432, "postgres"}, {6379, "redis"}, {8080, "http-alt"},
	{8443, "https-alt"}, {9200, "elasticsearch"}, {27017, "mongodb"},
}

// checkPorts connects to a short list of common TCP ports (active scan only)
// and records which accept a connection.
func (sc *Scanner) checkPorts(ctx context.Context, ip string, rep *Report, mu *sync.Mutex) {
	out := make([]PortOut, len(commonPorts))
	var wg sync.WaitGroup
	for i, p := range commonPorts {
		i, p := i, p
		wg.Add(1)
		go func() {
			defer wg.Done()
			open := sc.portOpen(ctx, ip, p.port)
			out[i] = PortOut{Port: p.port, Service: p.svc, Open: open}
			if open {
				mu.Lock()
				rep.add(SevInfo, "ports", fmt.Sprintf("Port %d/tcp open (%s)", p.port, p.svc), "A TCP connection to port "+strconv.Itoa(p.port)+" was accepted. Make sure this service is meant to be reachable from the internet.")
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	// Keep only open ports in the report's list, in order.
	open := []PortOut{}
	for _, p := range out {
		if p.Open {
			open = append(open, p)
		}
	}
	mu.Lock()
	rep.Ports = open
	mu.Unlock()
}

func (sc *Scanner) portOpen(ctx context.Context, ip string, port int) bool {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// FaviconInfo is the site's favicon and its hashes. The mmh3 value matches
// Shodan's http.favicon.hash, so it can be pivoted on to find related hosts.
type FaviconInfo struct {
	URL    string `json:"url"`
	MMH3   string `json:"mmh3"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// checkFavicon fetches /favicon.ico and computes its Shodan-style mmh3 hash.
func (sc *Scanner) checkFavicon(ctx context.Context, base *url.URL, rep *Report, mu *sync.Mutex) {
	u := strings.TrimRight(base.String(), "/") + "/favicon.ico"
	resp, body, err := sc.get(ctx, u)
	if err != nil {
		return
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) == 0 {
		return
	}
	ct := normType(resp)
	if ct != "" && !strings.HasPrefix(ct, "image/") && !strings.Contains(ct, "icon") {
		return // an HTML 200 (SPA shell), not a real icon
	}
	sum := sha256.Sum256(body)
	fav := &FaviconInfo{
		URL:    u,
		MMH3:   strconv.FormatInt(int64(mmh3Hash32(faviconB64(body), 0)), 10),
		SHA256: hex.EncodeToString(sum[:]),
		Size:   len(body),
	}
	mu.Lock()
	rep.Favicon = fav
	mu.Unlock()
}

// faviconB64 base64-encodes data the way Python's base64.encodebytes does (a
// newline every 76 characters and a trailing newline), which is what Shodan
// hashes.
func faviconB64(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// mmh3Hash32 is MurmurHash3 x86_32, returned as a signed int32 (Shodan's
// convention for favicon hashes).
func mmh3Hash32(data []byte, seed uint32) int32 {
	const c1 = 0xcc9e2d51
	const c2 = 0x1b873593
	h := seed
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}
