package scan

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Pahredar's own active checks. Unlike the Nuclei phase, these are a small,
// transparent set written here: each sends a specific request and records the
// request and response as evidence, so a finding can be trusted without a
// black box. They are safe — no exploitation, no destructive payloads, no
// denial-of-service — and run only on an authorised active scan.

// probeMarker is an off-site host used to detect redirects and reflection. It
// does not resolve to anything; it is only looked for in responses.
const probeMarker = "pahredar-probe.example"

// verify runs the native active checks against base, adding findings (with
// evidence) and calling onFinding after each so results stream to the UI.
func (sc *Scanner) verify(ctx context.Context, host string, base *url.URL, rep *Report, mu *sync.Mutex, onFinding func()) {
	add := func(sev, title, detail string, ev *Evidence) {
		mu.Lock()
		rep.addEv(sev, "verify", title, detail, ev)
		mu.Unlock()
		onFinding()
	}
	nr := sc.newClient(10 * time.Second)
	nr.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	sc.checkCORS(ctx, base, add)
	sc.checkOpenRedirect(ctx, nr, base, add)
	sc.checkMethods(ctx, base, add)
	sc.checkHostHeader(ctx, base, host, add)
	sc.checkReflection(ctx, base, add)
	sc.checkDirListing(ctx, base, add)
}

type addFn func(sev, title, detail string, ev *Evidence)

// checkCORS sends a cross-origin request and reports a policy that trusts an
// arbitrary origin, especially with credentials.
func (sc *Scanner) checkCORS(ctx context.Context, base *url.URL, add addFn) {
	origin := "https://evil." + probeMarker
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if req == nil {
		return
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", scannerUA)
	resp, err := sc.client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	if acao == "" {
		return
	}
	ev := &Evidence{
		Request:  "GET " + path(base) + "\nOrigin: " + origin,
		Response: resp.Status + "\nAccess-Control-Allow-Origin: " + acao + credLine(acac),
	}
	switch {
	case acao == origin && acac:
		add(SevHigh, "CORS trusts any origin with credentials", "The response reflects the request's Origin in Access-Control-Allow-Origin and allows credentials, so any site can read authenticated responses. Allow only known origins.", ev)
	case acao == origin:
		add(SevMedium, "CORS reflects the request Origin", "Access-Control-Allow-Origin echoes whatever Origin is sent, so cross-origin reads are not restricted. Allow only a fixed allow-list.", ev)
	case acao == "*" && acac:
		add(SevMedium, "CORS wildcard with credentials", "Access-Control-Allow-Origin is * together with credentials — an invalid, unsafe combination.", ev)
	}
}

// checkOpenRedirect tries common redirect parameters with an off-site target
// and reports if the server redirects to it.
func (sc *Scanner) checkOpenRedirect(ctx context.Context, nr *http.Client, base *url.URL, add addFn) {
	params := []string{"url", "next", "redirect", "redirect_url", "redirect_uri", "return", "returnUrl", "returnTo", "dest", "destination", "continue", "r"}
	target := "https://" + probeMarker + "/"
	for _, p := range params {
		u := strings.TrimRight(base.String(), "/") + "/?" + p + "=" + url.QueryEscape(target)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if req == nil {
			continue
		}
		req.Header.Set("User-Agent", scannerUA)
		resp, err := nr.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			if lu, err := url.Parse(loc); err == nil && strings.EqualFold(lu.Hostname(), probeMarker) {
				add(SevHigh, "Open redirect via ?"+p, "The "+p+" parameter is used in a redirect without validation, so the site can be used to bounce victims to an attacker URL (phishing, token theft).", &Evidence{
					Request:  "GET /?" + p + "=" + target + "\n(redirects not followed)",
					Response: resp.Status + "\nLocation: " + loc,
				})
				return
			}
		}
	}
}

// checkMethods actively tries methods that should usually be refused.
func (sc *Scanner) checkMethods(ctx context.Context, base *url.URL, add addFn) {
	for _, m := range []string{http.MethodPut, http.MethodDelete, "TRACE", http.MethodPatch} {
		req, _ := http.NewRequestWithContext(ctx, m, base.String(), nil)
		if req == nil {
			continue
		}
		req.Header.Set("User-Agent", scannerUA)
		resp, err := sc.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		ev := &Evidence{Request: m + " " + path(base), Response: resp.Status}
		if m == "TRACE" {
			if resp.StatusCode == 200 && strings.Contains(string(body), "TRACE "+path(base)) {
				ev.Snippet = clip(string(body), 200)
				add(SevLow, "HTTP TRACE enabled and echoing", "TRACE is answered and reflects the request, which can expose headers (Cross-Site Tracing). Disable it.", ev)
			}
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204 {
			add(SevMedium, "HTTP "+m+" accepted", "The server answered "+m+" with "+resp.Status+" instead of refusing it. If writes are not intended, disable this method.", ev)
		}
	}
}

// checkHostHeader sends a spoofed Host header and reports if it is reflected
// into the response (a sign of host-header injection / cache poisoning).
func (sc *Scanner) checkHostHeader(ctx context.Context, base *url.URL, host string, add addFn) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if req == nil {
		return
	}
	req.Host = probeMarker // the connection still goes to the real IP (see dial)
	req.Header.Set("User-Agent", scannerUA)
	resp, err := sc.client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, probeMarker) || strings.Contains(string(body), probeMarker) {
		ev := &Evidence{Request: "GET " + path(base) + "\nHost: " + probeMarker, Response: resp.Status}
		if strings.Contains(loc, probeMarker) {
			ev.Response += "\nLocation: " + loc
		} else {
			ev.Snippet = snippetAround(string(body), probeMarker)
		}
		add(SevMedium, "Host header reflected", "A spoofed Host header is reflected back, which can enable cache poisoning or password-reset poisoning. Validate the Host against an allow-list.", ev)
	}
}

// checkReflection sends a marked value and reports if it comes back unescaped
// in an HTML response (reflected input, a precursor to XSS).
func (sc *Scanner) checkReflection(ctx context.Context, base *url.URL, add addFn) {
	marker := "pahredar9Rx<q>"
	u := strings.TrimRight(base.String(), "/") + "/?pahredar=" + url.QueryEscape(marker)
	resp, body, err := sc.get(ctx, u)
	if err != nil {
		return
	}
	resp.Body.Close()
	if !strings.HasPrefix(normType(resp), "text/html") {
		return
	}
	if strings.Contains(string(body), marker) { // the < > came back raw
		add(SevMedium, "Reflected unescaped input (possible XSS)", "A value sent in the query string is returned in the HTML without encoding the < and > characters, so it may be exploitable for cross-site scripting. Context-encode reflected input.", &Evidence{
			Request:  "GET /?pahredar=" + marker,
			Response: resp.Status + "\nContent-Type: " + resp.Header.Get("Content-Type"),
			Snippet:  snippetAround(string(body), marker),
		})
	}
}

// checkDirListing looks for directory-listing (autoindex) pages.
func (sc *Scanner) checkDirListing(ctx context.Context, base *url.URL, add addFn) {
	for _, p := range []string{"/", "/assets/", "/images/", "/img/", "/static/", "/uploads/", "/files/", "/js/", "/css/", "/backup/"} {
		resp, body, err := sc.get(ctx, strings.TrimRight(base.String(), "/")+p)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 && (strings.Contains(string(body), "<title>Index of ") || strings.Contains(string(body), "Directory listing for ")) {
			add(SevLow, "Directory listing enabled at "+p, "The server returns an automatic file index for "+p+", exposing file names that should not be browsable.", &Evidence{
				Request:  "GET " + p,
				Response: resp.Status + "\nContent-Type: " + resp.Header.Get("Content-Type"),
				Snippet:  snippetAround(string(body), "Index of "),
			})
			return
		}
	}
}

const scannerUA = "pahredar-scanner (+https://github.com/SHIVAM-SHARMA-766/pahredar)"

func path(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return p
}

func credLine(v bool) string {
	if v {
		return "\nAccess-Control-Allow-Credentials: true"
	}
	return ""
}

// snippetAround returns a short window of s centred on the first match of sub.
func snippetAround(s, sub string) string {
	i := strings.Index(s, sub)
	if i < 0 {
		return clip(s, 160)
	}
	start := i - 60
	if start < 0 {
		start = 0
	}
	end := i + len(sub) + 60
	if end > len(s) {
		end = len(s)
	}
	out := s[start:end]
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}
	return strings.TrimSpace(out)
}
