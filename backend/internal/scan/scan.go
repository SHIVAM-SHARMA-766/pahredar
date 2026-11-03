// Package scan runs a non-intrusive external security assessment of a public
// endpoint: DNS, TLS, HTTP security headers, cookies, a technology
// fingerprint matched against Pahredar's CVE data, a small set of commonly
// exposed paths, and related resources (security.txt, certificate subject
// alternative names, linked assets). It only sends the same requests a
// browser or crawler would — no exploit payloads — and only connects to
// public unicast addresses (private, loopback, and internal ranges are
// refused, which also prevents SSRF).
package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity levels, most to least serious.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
	SevGood     = "good" // a positive finding (HSTS present, etc.)
)

var sevWeight = map[string]int{SevCritical: 30, SevHigh: 15, SevMedium: 8, SevLow: 3, SevInfo: 0, SevGood: 0}
var sevRank = map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4, SevGood: 5}

// Finding is one observation about the target.
type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"` // tls, headers, dns, cookies, exposure, tech
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// Report is the full assessment of one endpoint.
type Report struct {
	Target    string      `json:"target"`
	URL       string      `json:"url"`
	Host      string      `json:"host"`
	IP        string      `json:"ip"`
	ScannedAt time.Time   `json:"scanned_at"`
	Duration  string      `json:"duration"`
	Grade     string      `json:"grade"`
	Score     int         `json:"score"`
	Findings  []Finding   `json:"findings"`
	DNS       *DNSInfo    `json:"dns"`
	TLS       *TLSInfo    `json:"tls"`
	HTTP      *HTTPInfo   `json:"http"`
	Headers   []HeaderOut `json:"headers"`
	Cookies   []CookieOut `json:"cookies"`
	Tech      []TechOut   `json:"tech"`
	Paths     []PathOut   `json:"paths"`
	Related   *Related    `json:"related"`
	Errors    []string    `json:"errors"`
}

// TechMatcher looks up a fingerprinted product in Pahredar's CVE data.
type TechMatcher interface {
	MatchTech(ctx context.Context, vendor, product string) (*TechCVEs, error)
}

// Scanner runs scans. It holds a public-only HTTP client and the CVE matcher.
type Scanner struct {
	client  *http.Client
	matcher TechMatcher
}

func NewScanner(m TechMatcher) *Scanner {
	return &Scanner{client: publicClient(10 * time.Second), matcher: m}
}

var (
	// ErrPrivate means the target does not resolve to a public address.
	ErrPrivate = errors.New("the target does not resolve to a public internet address; this scanner only assesses public endpoints")
	// ErrNoResolve means DNS returned no usable address.
	ErrNoResolve = errors.New("could not resolve the target")
	// ErrBadTarget means the input is not a host or URL.
	ErrBadTarget = errors.New("enter a hostname or URL, e.g. example.com or https://example.com")
)

// ParseTarget normalizes user input into a host and a base URL. A bare host
// defaults to https.
func ParseTarget(in string) (host string, base *url.URL, err error) {
	in = strings.TrimSpace(in)
	if in == "" || len(in) > 255 {
		return "", nil, ErrBadTarget
	}
	if !strings.Contains(in, "://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", nil, ErrBadTarget
	}
	// Keep only scheme, host, port; drop any path/query/fragment and userinfo.
	base = &url.URL{Scheme: u.Scheme, Host: u.Host}
	host = u.Hostname()
	// Reject IP literals that are already non-public, and obvious junk.
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return "", nil, ErrPrivate
	}
	return host, base, nil
}

// Scan assesses one target. It is bounded by ctx; callers pass a timeout.
func (sc *Scanner) Scan(ctx context.Context, target string) (*Report, error) {
	start := time.Now()
	host, base, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	// Resolve and require a public address before any connection.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, ErrNoResolve
	}
	var pub net.IP
	for _, ip := range ips {
		if isPublicIP(ip) {
			pub = ip
			break
		}
	}
	if pub == nil {
		return nil, ErrPrivate
	}

	rep := &Report{Target: target, Host: host, URL: base.String(), IP: pub.String(), ScannedAt: start.UTC(), Errors: []string{}, Findings: []Finding{}}

	// Each check appends to rep under its own mutex-guarded slot; run them
	// concurrently so a slow one does not block the rest.
	var mu sync.Mutex
	fail := func(where string, err error) {
		if err != nil {
			mu.Lock()
			rep.Errors = append(rep.Errors, where+": "+err.Error())
			mu.Unlock()
		}
	}
	var wg sync.WaitGroup
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			fail(name, fn(cctx))
		}()
	}

	run("dns", func(c context.Context) error { return sc.checkDNS(c, host, rep, &mu) })
	run("tls", func(c context.Context) error { return sc.checkTLS(c, host, base, rep, &mu) })
	// The HTTP checks (headers, cookies, tech, paths, related) share one
	// fetch of the page, so they run together.
	run("http", func(c context.Context) error { return sc.checkHTTP(c, host, base, rep, &mu) })

	wg.Wait()
	score(rep)
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	nilEmpty(rep)
	return rep, nil
}

// add records a finding (thread-safe via the caller's mutex).
func (rep *Report) add(sev, cat, title, detail string) {
	rep.Findings = append(rep.Findings, Finding{Severity: sev, Category: cat, Title: title, Detail: detail})
}

// score sorts findings by severity and computes the 0–100 score and grade.
func score(rep *Report) {
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		return sevRank[rep.Findings[i].Severity] < sevRank[rep.Findings[j].Severity]
	})
	s := 100
	for _, f := range rep.Findings {
		s -= sevWeight[f.Severity]
	}
	if s < 0 {
		s = 0
	}
	rep.Score = s
	switch {
	case s >= 90:
		rep.Grade = "A"
	case s >= 80:
		rep.Grade = "B"
	case s >= 70:
		rep.Grade = "C"
	case s >= 50:
		rep.Grade = "D"
	default:
		rep.Grade = "F"
	}
}

func nilEmpty(rep *Report) {
	if rep.Headers == nil {
		rep.Headers = []HeaderOut{}
	}
	if rep.Cookies == nil {
		rep.Cookies = []CookieOut{}
	}
	if rep.Tech == nil {
		rep.Tech = []TechOut{}
	}
	if rep.Paths == nil {
		rep.Paths = []PathOut{}
	}
}

// --- public-only networking --------------------------------------------------

func isPublicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && (v4[0] == 0 || (v4[0] == 100 && v4[1]&0xc0 == 64)) {
		return false
	}
	return true
}

func publicClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 6 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialPublic(ctx, d, network, addr)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS10},
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout + 8*time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
				return errors.New("redirect to a non-HTTP URL")
			}
			return nil
		},
	}
}

// dialPublic resolves addr, connects to the first public IP, and refuses the
// rest, so the connection cannot be redirected to an internal address.
func dialPublic(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if isPublicIP(ip) {
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
	}
	return nil, fmt.Errorf("refusing to connect to non-public address %s", host)
}
