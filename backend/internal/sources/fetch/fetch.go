// Package fetch holds the HTTP plumbing shared by the source packages.
package fetch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
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
