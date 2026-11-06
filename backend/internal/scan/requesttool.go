package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The request tool is a transparent HTTP client: it sends exactly the request
// the user specifies and returns the raw request and response. It reuses the
// scanner's public-only dialer, so it cannot reach disallowed addresses unless
// the server enables private targets.

// RequestSpec is a user-defined HTTP request.
type RequestSpec struct {
	Method          string     `json:"method"`
	URL             string     `json:"url"`
	Headers         []HeaderKV `json:"headers"`
	Body            string     `json:"body"`
	FollowRedirects bool       `json:"follow_redirects"`
}

// RequestResult is the outcome of sending a RequestSpec.
type RequestResult struct {
	Request    string     `json:"request"` // the raw request line + headers (+ body)
	URL        string     `json:"url"`
	Status     int        `json:"status"`
	StatusText string     `json:"status_text"`
	Proto      string     `json:"proto"`
	Headers    []HeaderKV `json:"headers"`
	Body       string     `json:"body"`
	BodySize   int        `json:"body_size"`
	TimeMs     int64      `json:"time_ms"`
	WAF        string     `json:"waf,omitempty"`
	Blocked    bool       `json:"blocked"`
	RemoteIP   string     `json:"remote_ip,omitempty"`
}

var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodDelete: true, http.MethodPatch: true, http.MethodHead: true,
	http.MethodOptions: true,
}

const maxToolBody = 128 << 10

// SendRequest executes one user-defined request and returns raw request and
// response for inspection.
func (sc *Scanner) SendRequest(ctx context.Context, spec RequestSpec) (*RequestResult, error) {
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !allowedMethods[method] {
		return nil, fmt.Errorf("method %q is not allowed", method)
	}
	u, err := url.Parse(strings.TrimSpace(spec.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrBadTarget
	}
	// Resolve and require an allowed address before connecting.
	host := u.Hostname()
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

	var reqBody io.Reader
	if spec.Body != "" {
		if len(spec.Body) > maxToolBody {
			return nil, fmt.Errorf("request body too large (max %d KB)", maxToolBody>>10)
		}
		reqBody = strings.NewReader(spec.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return nil, err
	}
	hasUA := false
	for _, h := range spec.Headers {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "Host") {
			req.Host = h.Value
			continue
		}
		if strings.EqualFold(name, "User-Agent") {
			hasUA = true
		}
		req.Header.Set(name, h.Value)
	}
	if !hasUA {
		req.Header.Set("User-Agent", scannerUA)
	}

	client := sc.newClient(15 * time.Second)
	if !spec.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxToolBody))
	elapsed := time.Since(start)

	waf, blocked := detectWAF(resp, body)

	out := &RequestResult{
		Request:    rawRequest(req, spec.Body),
		URL:        u.String(),
		Status:     resp.StatusCode,
		StatusText: strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprintf("%d", resp.StatusCode))),
		Proto:      resp.Proto,
		Headers:    responseHeaders(resp),
		Body:       string(body),
		BodySize:   len(body),
		TimeMs:     elapsed.Milliseconds(),
		WAF:        waf,
		Blocked:    blocked,
		RemoteIP:   dst.String(),
	}
	return out, nil
}

// rawRequest renders the request line, headers, and body as text.
func rawRequest(req *http.Request, body string) string {
	var b strings.Builder
	path := req.URL.RequestURI()
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", req.Method, path)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(&b, "Host: %s\n", host)
	names := make([]string, 0, len(req.Header))
	for n := range req.Header {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, v := range req.Header[n] {
			fmt.Fprintf(&b, "%s: %s\n", n, v)
		}
	}
	if body != "" {
		b.WriteString("\n")
		b.WriteString(body)
	}
	return b.String()
}

func responseHeaders(resp *http.Response) []HeaderKV {
	out := []HeaderKV{}
	names := make([]string, 0, len(resp.Header))
	for n := range resp.Header {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, v := range resp.Header[n] {
			out = append(out, HeaderKV{Name: n, Value: v})
		}
	}
	return out
}
