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

// Phase is one stage of a scan and its status.
type Phase struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pending, running, done
}

// ActiveProgress is live progress of the Nuclei phase.
type ActiveProgress struct {
	Templates int `json:"templates"`
	Requests  int `json:"requests"`
	Total     int `json:"total"`
	Percent   int `json:"percent"`
	Matched   int `json:"matched"`
}

// Progress is a snapshot of a running scan for the UI. Findings carries every
// finding recorded so far, sorted by severity, so the UI can show results
// stream in as each check completes rather than only at the end.
type Progress struct {
	Phases   []Phase         `json:"phases"`
	Active   *ActiveProgress `json:"active,omitempty"`
	Findings []Finding       `json:"findings"`
}

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
	Active    *ActiveScan `json:"active"`
	Errors    []string    `json:"errors"`
}

// TechMatcher looks up a fingerprinted product in Pahredar's CVE data.
type TechMatcher interface {
	MatchTech(ctx context.Context, vendor, product string) (*TechCVEs, error)
}

// Scanner runs scans. It holds an HTTP client, the CVE matcher, and the
// optional active (Nuclei) runner.
type Scanner struct {
	client       *http.Client
	matcher      TechMatcher
	active       *Nuclei
	allowPrivate bool
}

// NewScanner builds a scanner. allowPrivate lets it reach private/internal
// addresses (for assessing one's own infrastructure); active, when non-nil,
// enables intrusive Nuclei checks.
func NewScanner(m TechMatcher, allowPrivate bool, active *Nuclei) *Scanner {
	sc := &Scanner{matcher: m, active: active, allowPrivate: allowPrivate}
	sc.client = sc.newClient(10 * time.Second)
	return sc
}

// ActiveAvailable reports whether intrusive scanning is configured.
func (sc *Scanner) ActiveAvailable() bool { return sc.active != nil }

// AllowsPrivate reports whether private targets are permitted.
func (sc *Scanner) AllowsPrivate() bool { return sc.allowPrivate }

// ActiveCatalog lists the Nuclei template categories the active scan covers,
// or nil when active scanning is not configured.
func (sc *Scanner) ActiveCatalog() []Category {
	if sc.active == nil {
		return nil
	}
	return sc.active.Catalog()
}

// allowed reports whether sc may connect to ip.
func (sc *Scanner) allowed(ip net.IP) bool { return sc.allowPrivate || isPublicIP(ip) }

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
	return host, base, nil
}

// Scan assesses one target. It is bounded by ctx; callers pass a timeout.
// When active is true and a Nuclei runner is configured, intrusive checks
// run after the passive phase.
func (sc *Scanner) Scan(ctx context.Context, target string, active bool, onProgress func(Progress)) (*Report, error) {
	start := time.Now()
	if onProgress == nil {
		onProgress = func(Progress) {}
	}
	phases := []Phase{{"DNS", "pending"}, {"TLS & certificate", "pending"}, {"HTTP, headers & technology", "pending"}}
	if active && sc.active != nil {
		phases = append(phases, Phase{"Active checks", "pending"})
	}
	var pmu sync.Mutex
	var activeProg *ActiveProgress
	var mu sync.Mutex
	var rep *Report
	emit := func() {
		snap := make([]Phase, len(phases))
		copy(snap, phases)
		var ap *ActiveProgress
		if activeProg != nil {
			c := *activeProg
			ap = &c
		}
		var fsnap []Finding
		if rep != nil {
			mu.Lock()
			fsnap = append(fsnap, rep.Findings...)
			mu.Unlock()
			sortFindings(fsnap)
		}
		onProgress(Progress{Phases: snap, Active: ap, Findings: fsnap})
	}
	setPhase := func(name, status string) {
		pmu.Lock()
		for i := range phases {
			if phases[i].Name == name {
				phases[i].Status = status
			}
		}
		emit()
		pmu.Unlock()
	}
	emit()
	host, base, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	// Resolve and require an allowed address before any connection.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, ErrNoResolve
	}
	var dst net.IP
	for _, ip := range ips {
		if sc.allowed(ip) {
			dst = ip
			break
		}
	}
	if dst == nil {
		return nil, ErrPrivate
	}

	rep = &Report{Target: target, Host: host, URL: base.String(), IP: dst.String(), ScannedAt: start.UTC(), Errors: []string{}, Findings: []Finding{}}

	// Each check appends to rep under its own mutex-guarded slot; run them
	// concurrently so a slow one does not block the rest.
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

	phased := func(name, phase string, fn func(context.Context) error) {
		setPhase(phase, "running")
		run(name, func(c context.Context) error {
			err := fn(c)
			setPhase(phase, "done")
			return err
		})
	}
	phased("dns", "DNS", func(c context.Context) error { return sc.checkDNS(c, host, rep, &mu) })
	phased("tls", "TLS & certificate", func(c context.Context) error { return sc.checkTLS(c, host, base, rep, &mu) })
	// The HTTP checks (headers, cookies, tech, paths, related) share one
	// fetch of the page, so they run together.
	phased("http", "HTTP, headers & technology", func(c context.Context) error { return sc.checkHTTP(c, host, base, rep, &mu) })

	wg.Wait()

	if active && sc.active != nil {
		// Scan the resolved final URL from the passive phase when available.
		targetURL := rep.URL
		if rep.HTTP != nil && rep.HTTP.FinalURL != "" {
			targetURL = rep.HTTP.FinalURL
		}
		setPhase("Active checks", "running")
		onActive := func(ap ActiveProgress) {
			pmu.Lock()
			activeProg = &ap
			emit()
			pmu.Unlock()
		}
		// Each matched template is turned into a finding and streamed to the
		// UI as it arrives (not only at the end).
		onFinding := func(f ActiveFinding) {
			detail := "Verified by Nuclei template " + f.TemplateID + " at " + f.MatchedAt
			if len(f.CVEs) > 0 {
				detail = strings.Join(f.CVEs, ", ") + " — " + detail
			}
			mu.Lock()
			rep.add(nucleiSeverity(f.Severity), "active", f.Name, detail)
			mu.Unlock()
			emit()
		}
		if as, err := sc.active.Run(ctx, targetURL, onActive, onFinding); err != nil {
			rep.Errors = append(rep.Errors, "active: "+err.Error())
		} else {
			rep.Active = as
		}
		setPhase("Active checks", "done")
	}

	score(rep)
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	nilEmpty(rep)
	return rep, nil
}

// add records a finding (thread-safe via the caller's mutex).
func (rep *Report) add(sev, cat, title, detail string) {
	rep.Findings = append(rep.Findings, Finding{Severity: sev, Category: cat, Title: title, Detail: detail})
}

// sortFindings orders findings most-severe first (stable).
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		return sevRank[fs[i].Severity] < sevRank[fs[j].Severity]
	})
}

// score sorts findings by severity and computes the 0–100 score and grade.
func score(rep *Report) {
	sortFindings(rep.Findings)
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

func (sc *Scanner) newClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            sc.dial,
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

// dial resolves addr, connects to the first allowed IP, and refuses the
// rest, so the connection cannot be redirected to a disallowed address.
func (sc *Scanner) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 6 * time.Second}
	for _, ip := range ips {
		if sc.allowed(ip) {
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
	}
	return nil, fmt.Errorf("refusing to connect to non-allowed address %s", host)
}
