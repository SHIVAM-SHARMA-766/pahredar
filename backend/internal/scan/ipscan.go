package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// The IP scanner enriches a single IP address from several public databases
// at once and folds them into one view with a combined verdict. It never
// connects to the IP itself — every lookup is a third-party query (DNS
// blocklists, Team Cymru, RDAP, ip-api), so there is no SSRF surface and no
// authorization concern. Key-free sources only in this version; keyed ones
// (AbuseIPDB, Shodan) are added later behind an optional admin key.

// ErrBadIP means the input is not a valid IP address.
var ErrBadIP = errors.New("enter a valid IP address, e.g. 8.8.8.8 or 2001:4860:4860::8888")

// IPReport is the aggregated profile of one IP address.
type IPReport struct {
	IP        string         `json:"ip"`
	Version   int            `json:"version"` // 4 or 6
	Type      string         `json:"type"`    // public, private, loopback, reserved…
	PTR       string         `json:"ptr,omitempty"`
	Net       *NetInfo       `json:"net"`
	Geo       *GeoInfo       `json:"geo"`
	Blocklist *BlocklistScan `json:"blocklist"`
	Flags     []string       `json:"flags"`   // proxy, hosting, mobile…
	Score     int            `json:"score"`   // 0 (clean) – 100 (bad)
	Verdict   string         `json:"verdict"` // clean, suspicious, malicious
	ScannedAt time.Time      `json:"scanned_at"`
	Duration  string         `json:"duration"`
	Errors    []string       `json:"errors"`
}

// GeoInfo is the geolocation and connection profile from ip-api (free, no key).
type GeoInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Zip         string  `json:"zip,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	AS          string  `json:"as,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

// BlocklistScan is the result of checking the IP against many DNS blocklists.
type BlocklistScan struct {
	Checked int            `json:"checked"` // how many lists were queried
	Listed  int            `json:"listed"`  // how many list the IP
	Hits    []BlocklistHit `json:"hits"`    // the lists that flag it
	Lists   []string       `json:"lists"`   // every list queried (for transparency)
}

// BlocklistHit is one DNS blocklist that lists the IP.
type BlocklistHit struct {
	Zone   string   `json:"zone"`
	Codes  []string `json:"codes"`            // the 127.0.0.x return codes
	Reason string   `json:"reason,omitempty"` // the list's TXT explanation
}

// dnsblZones are well-known, free DNS blocklists. Listing is signalled by an
// A record in 127.0.0.0/8; the TXT record (when present) explains why.
var dnsblZones = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"dnsbl.sorbs.net",
	"cbl.abuseat.org",
	"dnsbl-1.uceprotect.net",
	"psbl.surriel.com",
	"bl.mailspike.net",
	"ix.dnsbl.manitu.net",
	"spam.dnsbl.anonmails.de",
	"all.s5h.net",
	"dnsbl.dronebl.org",
	"z.mailspike.net",
	"spamrbl.imp.ch",
}

// ScanIP builds an aggregated profile of ipStr from public databases.
func (sc *Scanner) ScanIP(ctx context.Context, ipStr string) (*IPReport, error) {
	start := time.Now()
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, ErrBadIP
	}
	canon := ip.String()
	rep := &IPReport{IP: canon, Version: ipVersion(ip), Type: ipType(ip), ScannedAt: start.UTC(), Errors: []string{}, Flags: []string{}}

	var mu sync.Mutex
	fail := func(where string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		rep.Errors = append(rep.Errors, where+": "+err.Error())
		mu.Unlock()
	}

	var wg sync.WaitGroup
	// Reverse DNS + Team Cymru ASN + RDAP allocation (reuses the recon helpers).
	wg.Add(1)
	go func() {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		n := &NetInfo{IP: canon}
		if names, err := net.DefaultResolver.LookupAddr(cctx, canon); err == nil && len(names) > 0 {
			n.PTR = strings.TrimSuffix(names[0], ".")
		}
		if asn, org, country, prefix := cymruASN(cctx, canon); asn != "" {
			n.ASN = "AS" + asn
			n.ASOrg = org
			n.NetRange = prefix
			n.Country = country
		}
		var r rdapResponse
		if err := sc.getJSON(cctx, rdapBase+"/ip/"+canon, "application/rdap+json", &r); err == nil {
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
		rep.PTR = n.PTR
		mu.Unlock()
	}()

	// Geolocation + connection flags (ip-api, free, no key).
	wg.Add(1)
	go func() {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		geo, err := sc.geoLookup(cctx, canon)
		if err != nil {
			fail("geo", err)
			return
		}
		mu.Lock()
		rep.Geo = geo
		mu.Unlock()
	}()

	// DNS blocklists (only meaningful for a public address).
	wg.Add(1)
	go func() {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		bl := sc.checkBlocklists(cctx, ip)
		mu.Lock()
		rep.Blocklist = bl
		mu.Unlock()
	}()

	wg.Wait()

	scoreIP(rep)
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	return rep, nil
}

// geoLookup fetches ip-api's free JSON profile (country, ISP, and the
// mobile/proxy/hosting flags).
func (sc *Scanner) geoLookup(ctx context.Context, ip string) (*GeoInfo, error) {
	var out struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Timezone    string  `json:"timezone"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		ASName      string  `json:"asname"`
		Mobile      bool    `json:"mobile"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
	}
	const fields = "status,message,country,countryCode,regionName,city,zip,timezone,lat,lon,isp,org,as,asname,mobile,proxy,hosting"
	if err := sc.getJSON(ctx, "http://ip-api.com/json/"+ip+"?fields="+fields, "application/json", &out); err != nil {
		return nil, err
	}
	if out.Status != "success" {
		msg := out.Message
		if msg == "" {
			msg = "lookup failed"
		}
		return nil, errors.New(msg)
	}
	return &GeoInfo{
		Country: out.Country, CountryCode: out.CountryCode, Region: out.RegionName,
		City: out.City, Zip: out.Zip, Timezone: out.Timezone, Lat: out.Lat, Lon: out.Lon,
		ISP: out.ISP, Org: out.Org, AS: out.AS, ASName: out.ASName,
		Mobile: out.Mobile, Proxy: out.Proxy, Hosting: out.Hosting,
	}, nil
}

// checkBlocklists queries every DNS blocklist in parallel and collects the
// ones that list the IP. IPv6 and non-public addresses are skipped (the free
// lists index public IPv4 only).
func (sc *Scanner) checkBlocklists(ctx context.Context, ip net.IP) *BlocklistScan {
	out := &BlocklistScan{Hits: []BlocklistHit{}, Lists: dnsblZones}
	v4 := ip.To4()
	if v4 == nil || !isPublicIP(ip) {
		return out
	}
	rev := fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, zone := range dnsblZones {
		zone := zone
		wg.Add(1)
		go func() {
			defer wg.Done()
			out.Checked++
			query := rev + "." + zone
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupHost(cctx, query)
			if err != nil || len(addrs) == 0 {
				return // not listed (NXDOMAIN) or lookup failed
			}
			codes := []string{}
			for _, a := range addrs {
				if strings.HasPrefix(a, "127.") {
					codes = append(codes, a)
				}
			}
			if len(codes) == 0 {
				return
			}
			hit := BlocklistHit{Zone: zone, Codes: codes}
			if txts, err := net.DefaultResolver.LookupTXT(cctx, query); err == nil && len(txts) > 0 {
				hit.Reason = clip(txts[0], 200)
			}
			mu.Lock()
			out.Hits = append(out.Hits, hit)
			mu.Unlock()
		}()
	}
	wg.Wait()
	out.Listed = len(out.Hits)
	sort.Slice(out.Hits, func(i, j int) bool { return out.Hits[i].Zone < out.Hits[j].Zone })
	return out
}

// scoreIP folds the signals into a 0–100 score, a verdict, and the flag list.
func scoreIP(rep *IPReport) {
	flags := []string{}
	score := 0
	if rep.Blocklist != nil && rep.Blocklist.Listed > 0 {
		score += rep.Blocklist.Listed * 20
		flags = append(flags, fmt.Sprintf("on %d blocklist(s)", rep.Blocklist.Listed))
	}
	if rep.Geo != nil {
		if rep.Geo.Proxy {
			score += 20
			flags = append(flags, "proxy/VPN/Tor")
		}
		if rep.Geo.Hosting {
			score += 5
			flags = append(flags, "hosting/datacenter")
		}
		if rep.Geo.Mobile {
			flags = append(flags, "mobile network")
		}
	}
	if score > 100 {
		score = 100
	}
	rep.Score = score
	rep.Flags = flags
	switch {
	case score >= 60:
		rep.Verdict = "malicious"
	case score >= 20:
		rep.Verdict = "suspicious"
	default:
		rep.Verdict = "clean"
	}
}

func ipVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func ipType(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsMulticast():
		return "multicast"
	case isPublicIP(ip):
		return "public"
	default:
		return "reserved"
	}
}
