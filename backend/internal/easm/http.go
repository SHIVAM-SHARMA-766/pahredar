package easm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// httpProbe actively contacts the target's web server: a TLS handshake (A07,
// cert + protocol + cipher) and an HTTPS request (A06, status/server/title/
// redirect) with a security-header read (A13). method=active. Low impact — one
// TLS dial and one HTTP request per host.
type httpProbe struct{}

func (httpProbe) Name() string { return "http_probe" }

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// securityHeaders are the response headers whose presence/value we record (A13).
var securityHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
	"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
}

func (httpProbe) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	out := []db.AssetRecord{}
	out = append(out, tlsRecords(ctx, domain)...)
	out = append(out, httpRecords(ctx, domain)...)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// tlsRecords does a TLS handshake and records the leaf cert + protocol + cipher.
func tlsRecords(ctx context.Context, domain string) []db.AssetRecord {
	d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: domain}, NetDialer: &net.Dialer{Timeout: 10 * time.Second}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	out := []db.AssetRecord{recActive("tls", "tls", "tls_probe", map[string]any{
		"version": tlsVersion(st.Version),
		"cipher":  tls.CipherSuiteName(st.CipherSuite),
		"alpn":    st.NegotiatedProtocol,
	}, "TLS handshake")}
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		expired := time.Now().After(c.NotAfter)
		out = append(out, recActive("cert", "live", "tls_probe", map[string]any{
			"common_name": c.Subject.CommonName,
			"issuer":      c.Issuer.CommonName,
			"not_before":  c.NotBefore.UTC().Format(time.RFC3339),
			"not_after":   c.NotAfter.UTC().Format(time.RFC3339),
			"dns_names":   c.DNSNames,
			"expired":     expired,
			"self_signed": c.Issuer.CommonName == c.Subject.CommonName,
		}, "live certificate"))
	}
	return out
}

// httpRecords fetches https://domain and records the response + security headers.
func httpRecords(ctx context.Context, domain string) []db.AssetRecord {
	redirects := 0
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = len(via)
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "pahredar-easm")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))

	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.TrimSpace(html(string(m[1])))
		title = clip(title, 160)
	}
	out := []db.AssetRecord{recActive("http", "root", "http_probe", map[string]any{
		"status":       resp.StatusCode,
		"server":       resp.Header.Get("Server"),
		"powered_by":   resp.Header.Get("X-Powered-By"),
		"content_type": resp.Header.Get("Content-Type"),
		"title":        title,
		"final_url":    resp.Request.URL.String(),
		"redirects":    redirects,
		"proto":        resp.Proto,
	}, "HTTPS GET")}

	for _, h := range securityHeaders {
		v := resp.Header.Get(h)
		out = append(out, recActive("http_security", strings.ToLower(h), "http_probe",
			map[string]any{"present": v != "", "value": clip(v, 200)}, "response header"))
	}
	return out
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "unknown"
	}
}

// html unescapes the few entities common in <title>.
func html(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "\n", " ")
	return strings.Join(strings.Fields(r.Replace(s)), " ")
}
