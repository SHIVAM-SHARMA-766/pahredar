// Package fetch holds the HTTP plumbing shared by the source packages.
package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

const UserAgent = "pahredar (+https://github.com/SHIVAM-SHARMA-766/pahredar)"

// NewClient returns a client without an overall timeout (downloads can be
// large); callers bound requests with their context.
func NewClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 90 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}}
}

// Get issues a GET and returns the response only for HTTP 200; any other
// status becomes an error carrying the start of the body.
func Get(ctx context.Context, c *http.Client, url string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &StatusError{URL: url, Code: resp.StatusCode, Status: resp.Status, Body: string(bytes.TrimSpace(body))}
	}
	return resp, nil
}

type StatusError struct {
	URL    string
	Code   int
	Status string
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: %s: %s", e.URL, e.Status, e.Body)
}

// PublicOnlyClient fetches URLs that come from untrusted data (CVE
// references, feed items). It only connects to public unicast addresses,
// checked after DNS resolution on every connection including redirects,
// follows at most three redirects, and never uses a proxy.
func PublicOnlyClient(headerTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !IsPublic(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			ResponseHeaderTimeout:  headerTimeout,
			MaxResponseHeaderBytes: 64 << 10,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
				return errors.New("redirect to a non-HTTP URL")
			}
			return nil
		},
	}
}

// IsPublic reports whether ip is a public unicast address: not private,
// loopback, link-local, unspecified, multicast, carrier-grade NAT
// (100.64.0.0/10), or 0.0.0.0/8.
func IsPublic(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && (v4[0] == 0 || (v4[0] == 100 && v4[1]&0xc0 == 64)) {
		return false
	}
	return true
}
