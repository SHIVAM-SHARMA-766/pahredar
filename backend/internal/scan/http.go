package scan

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// HTTPInfo describes the main HTTP response.
type HTTPInfo struct {
	FinalURL      string   `json:"final_url"`
	Status        int      `json:"status"`
	Redirects     []string `json:"redirects"`
	Server        string   `json:"server"`
	PoweredBy     string   `json:"powered_by"`
	HTTPSRedirect bool     `json:"https_redirect"`
	Methods       []string `json:"methods"`
}

// HeaderOut is one security header's state.
type HeaderOut struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

// CookieOut is one Set-Cookie and its flags.
type CookieOut struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

const maxBody = 512 << 10

// checkHTTP fetches the page once and runs the header, cookie, tech, path,
// and related-resource checks from it.
func (sc *Scanner) checkHTTP(ctx context.Context, host string, base *url.URL, rep *Report, mu *sync.Mutex) error {
	resp, body, err := sc.get(ctx, base.String())
	if err != nil {
		// Fall back to the other scheme before giving up.
		alt := *base
		alt.Scheme = otherScheme(base.Scheme)
		resp, body, err = sc.get(ctx, alt.String())
		if err != nil {
			mu.Lock()
			rep.add(SevHigh, "http", "Endpoint did not respond", err.Error())
			mu.Unlock()
			return nil
		}
		base = &alt
	}
	defer resp.Body.Close()

	info := &HTTPInfo{FinalURL: resp.Request.URL.String(), Status: resp.StatusCode, Redirects: []string{}, Methods: []string{}}
	info.Server = resp.Header.Get("Server")
	info.PoweredBy = resp.Header.Get("X-Powered-By")

	// Did http:// redirect to https://?
	if base.Scheme == "http" {
		info.HTTPSRedirect = strings.HasPrefix(resp.Request.URL.String(), "https://")
	} else {
		info.HTTPSRedirect = true
		if up, _, err := sc.get(ctx, "http://"+host); err == nil {
			info.HTTPSRedirect = strings.HasPrefix(up.Request.URL.String(), "https://")
			up.Body.Close()
		}
	}

	// Allowed methods, from OPTIONS.
	if req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, base.String(), nil); req != nil {
		if o, err := sc.client.Do(req); err == nil {
			if a := o.Header.Get("Allow"); a != "" {
				info.Methods = splitList(a)
			}
			o.Body.Close()
		}
	}

	headers, cookies := analyzeHeaders(resp, base.Scheme == "https")
	tech := sc.fingerprint(ctx, resp, body, mu, rep)

	mu.Lock()
	rep.HTTP = info
	rep.Headers = headers
	rep.Cookies = cookies
	rep.Tech = tech
	addHTTPFindings(rep, info, headers, cookies)
	mu.Unlock()

	// Paths and related resources make their own requests.
	sc.checkPaths(ctx, base, rep, mu)
	sc.checkRelated(ctx, host, base, body, rep, mu)
	return nil
}

func (sc *Scanner) get(ctx context.Context, u string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "pahredar-scanner (+https://github.com/SHIVAM-SHARMA-766/pahredar)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp, body, nil
}

// securityHeaders are the response headers the scan grades, in report order.
var securityHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
}

func analyzeHeaders(resp *http.Response, https bool) ([]HeaderOut, []CookieOut) {
	out := make([]HeaderOut, 0, len(securityHeaders))
	for _, h := range securityHeaders {
		v := resp.Header.Get(h)
		out = append(out, HeaderOut{Name: h, Present: v != "", Value: clip(v, 200)})
	}
	cookies := []CookieOut{}
	for _, c := range resp.Cookies() {
		cookies = append(cookies, CookieOut{Name: c.Name, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: sameSite(c.SameSite)})
	}
	return out, cookies
}

func addHTTPFindings(rep *Report, info *HTTPInfo, headers []HeaderOut, cookies []CookieOut) {
	byName := map[string]HeaderOut{}
	for _, h := range headers {
		byName[h.Name] = h
	}
	hsts := byName["Strict-Transport-Security"]
	if !hsts.Present {
		rep.add(SevMedium, "headers", "No HSTS header", "Strict-Transport-Security is missing, so a browser can be downgraded to http on the first visit. Add it with a long max-age.")
	} else if !strings.Contains(strings.ToLower(hsts.Value), "max-age") {
		rep.add(SevLow, "headers", "HSTS without max-age", hsts.Value)
	} else {
		rep.add(SevGood, "headers", "HSTS set", hsts.Value)
	}
	if !byName["Content-Security-Policy"].Present {
		rep.add(SevMedium, "headers", "No Content-Security-Policy", "A CSP limits where scripts and other resources can load from, a key defence against XSS and injection.")
	} else {
		rep.add(SevGood, "headers", "Content-Security-Policy set", "")
	}
	if !byName["X-Frame-Options"].Present && !strings.Contains(strings.ToLower(byName["Content-Security-Policy"].Value), "frame-ancestors") {
		rep.add(SevLow, "headers", "No clickjacking protection", "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed by other sites.")
	}
	if !byName["X-Content-Type-Options"].Present {
		rep.add(SevLow, "headers", "No X-Content-Type-Options", "Add 'X-Content-Type-Options: nosniff' to stop browsers guessing content types.")
	}
	if !byName["Referrer-Policy"].Present {
		rep.add(SevInfo, "headers", "No Referrer-Policy", "Consider a Referrer-Policy to control how much of the URL is sent to other sites.")
	}
	if !byName["Permissions-Policy"].Present {
		rep.add(SevInfo, "headers", "No Permissions-Policy", "A Permissions-Policy can disable powerful browser features (camera, geolocation) the site does not use.")
	}
	if !info.HTTPSRedirect && info.Status > 0 {
		rep.add(SevMedium, "headers", "http is not redirected to https", "Plain-http requests are served instead of redirecting to https.")
	}
	for _, m := range info.Methods {
		if strings.EqualFold(m, "TRACE") {
			rep.add(SevLow, "http", "HTTP TRACE enabled", "TRACE can aid cross-site tracing attacks; disable it.")
		}
	}
	for _, c := range cookies {
		if !c.Secure {
			rep.add(SevLow, "cookies", "Cookie without Secure flag: "+c.Name, "Set the Secure flag so the cookie is only sent over https.")
		}
		if !c.HTTPOnly {
			rep.add(SevLow, "cookies", "Cookie without HttpOnly flag: "+c.Name, "Set HttpOnly so scripts cannot read the cookie (limits XSS theft).")
		}
		if c.SameSite == "none" || c.SameSite == "" {
			rep.add(SevInfo, "cookies", "Cookie without SameSite: "+c.Name, "Set SameSite=Lax or Strict to limit cross-site sending.")
		}
	}
}

func otherScheme(s string) string {
	if s == "https" {
		return "http"
	}
	return "https"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return ""
	}
}
