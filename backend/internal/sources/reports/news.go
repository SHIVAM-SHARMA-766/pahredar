package reports

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	msrcAPI       = "https://api.msrc.microsoft.com/sug/v2.0/en-US/"
	googleNewsRSS = "https://news.google.com/rss/search"
	hnSearchAPI   = "https://hn.algolia.com/api/v1/search"

	maxPreviews     = 8
	maxNewsItems    = 25
	maxPageBytes    = 1 << 20
	previewTimeout  = 6 * time.Second
	previewParallel = 4
)

// --- Microsoft Security Response Center ------------------------------------

type MSRCReport struct {
	Title             string        `json:"title"`
	ReleaseDate       string        `json:"release_date,omitempty"`
	Severity          string        `json:"severity,omitempty"`
	Impact            string        `json:"impact,omitempty"`
	Exploited         string        `json:"exploited,omitempty"`
	PubliclyDisclosed string        `json:"publicly_disclosed,omitempty"`
	Products          []MSRCProduct `json:"products"`
	URL               string        `json:"url"`
}

type MSRCProduct struct {
	Family         string   `json:"family,omitempty"`
	Product        string   `json:"product"`
	Severity       string   `json:"severity,omitempty"`
	KB             []MSRCKB `json:"kb"`
	ActionRequired bool     `json:"action_required"`
}

type MSRCKB struct {
	Article     string `json:"article"`
	URL         string `json:"url,omitempty"`
	FixedBuild  string `json:"fixed_build,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	Download    string `json:"download,omitempty"`
}

func isMicrosoft(req Request) bool {
	if strings.Contains(strings.ToLower(req.Assigner), "microsoft") {
		return true
	}
	for _, v := range req.Vendors {
		if v == "microsoft" {
			return true
		}
	}
	return false
}

// msrc reads Microsoft's Security Update Guide. Non-Microsoft CVEs are not
// queried at all.
func (c *Client) msrc(ctx context.Context, req Request) (*MSRCReport, error) {
	if !isMicrosoft(req) {
		return nil, ErrNotFound
	}
	filter := url.Values{"$filter": {"cveNumber eq '" + req.CVEID + "'"}}.Encode()
	var vuln struct {
		Value []struct {
			Title             string `json:"cveTitle"`
			ReleaseDate       string `json:"releaseDate"`
			Severity          string `json:"severity"`
			Impact            string `json:"impact"`
			Exploited         string `json:"exploited"`
			PubliclyDisclosed string `json:"publiclyDisclosed"`
		} `json:"value"`
	}
	if err := c.getJSON(ctx, msrcAPI+"vulnerability?"+filter, &vuln); err != nil {
		return nil, err
	}
	if len(vuln.Value) == 0 {
		return nil, ErrNotFound
	}
	v := vuln.Value[0]
	r := &MSRCReport{
		Title: v.Title, ReleaseDate: v.ReleaseDate, Severity: v.Severity, Impact: v.Impact,
		Exploited: v.Exploited, PubliclyDisclosed: v.PubliclyDisclosed, Products: []MSRCProduct{},
		URL: "https://msrc.microsoft.com/update-guide/vulnerability/" + req.CVEID,
	}

	var affected struct {
		Value []struct {
			Family         string `json:"productFamily"`
			Product        string `json:"product"`
			Severity       string `json:"severity"`
			ActionRequired bool   `json:"customerActionRequired"`
			KB             []struct {
				Article      string `json:"articleName"`
				URL          string `json:"articleUrl"`
				FixedBuild   string `json:"fixedBuildNumber"`
				DownloadURL  string `json:"downloadUrl"`
				DownloadName string `json:"downloadName"`
			} `json:"kbArticles"`
		} `json:"value"`
	}
	if err := c.getJSON(ctx, msrcAPI+"affectedProduct?"+filter, &affected); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	index := map[string]int{}
	for _, a := range affected.Value {
		i, ok := index[a.Product]
		if !ok {
			i = len(r.Products)
			index[a.Product] = i
			r.Products = append(r.Products, MSRCProduct{Family: a.Family, Product: a.Product, Severity: a.Severity, KB: []MSRCKB{}, ActionRequired: a.ActionRequired})
		}
		for _, kb := range a.KB {
			r.Products[i].KB = append(r.Products[i].KB, MSRCKB{
				Article: kb.Article, URL: kb.URL, FixedBuild: kb.FixedBuild, DownloadURL: kb.DownloadURL, Download: kb.DownloadName,
			})
		}
	}
	return r, nil
}

// --- Vendor advisory previews ----------------------------------------------

type AdvisoryPreview struct {
	URL         string `json:"url"`
	Host        string `json:"host"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	SiteName    string `json:"site_name,omitempty"`
	Published   string `json:"published,omitempty"`
	// Error is set when the page could not be read; the link is still shown.
	Error string `json:"error,omitempty"`
}

// safeClient fetches pages named by CVE data. Those URLs are untrusted, so
// it only connects to public unicast addresses (checked after DNS
// resolution, on every connection including redirects), follows at most
// three redirects, and never uses a proxy.
func safeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !isPublic(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			ResponseHeaderTimeout:  previewTimeout,
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

func isPublic(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !ip.IsMulticast() && !isSharedOrReserved(ip)
}

// isSharedOrReserved covers ranges Go's helpers miss: carrier-grade NAT
// (100.64.0.0/10) and 0.0.0.0/8.
func isSharedOrReserved(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 0 || (v4[0] == 100 && v4[1]&0xc0 == 64)
	}
	return false
}

var (
	metaTag   = regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	attr      = regexp.MustCompile(`(?is)([a-z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	titleTag  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaceRuns = regexp.MustCompile(`\s+`)
)

func (c *Client) advisoryPreviews(ctx context.Context, urls []string) ([]AdvisoryPreview, error) {
	var picked []string
	seen := map[string]bool{}
	for _, u := range urls {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || seen[u] {
			continue
		}
		seen[u] = true
		picked = append(picked, u)
		if len(picked) == maxPreviews {
			break
		}
	}
	if len(picked) == 0 {
		return nil, ErrNotFound
	}
	out := make([]AdvisoryPreview, len(picked))
	sem := make(chan struct{}, previewParallel)
	var wg sync.WaitGroup
	for i, u := range picked {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = c.preview(ctx, u)
		}()
	}
	wg.Wait()
	return out, nil
}

func (c *Client) preview(ctx context.Context, rawURL string) AdvisoryPreview {
	p, _ := url.Parse(rawURL)
	pv := AdvisoryPreview{URL: rawURL, Host: strings.TrimPrefix(p.Hostname(), "www.")}
	ctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()
	resp, err := fetch.Get(ctx, c.pages, rawURL, http.Header{"Accept": {"text/html,application/xhtml+xml"}})
	if err != nil {
		pv.Error = "page could not be loaded"
		return pv
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "html") {
		pv.Error = "not an HTML page"
		return pv
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes))
	if err != nil {
		pv.Error = "page could not be read"
		return pv
	}
	fillPreview(&pv, string(body))
	return pv
}

// fillPreview reads Open Graph and standard meta tags, falling back to the
// <title>. All values are HTML-unescaped plain text.
func fillPreview(pv *AdvisoryPreview, page string) {
	meta := map[string]string{}
	for _, tag := range metaTag.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, m := range attr.FindAllStringSubmatch(tag, -1) {
			attrs[strings.ToLower(m[1])] = m[2] + m[3]
		}
		key := attrs["property"]
		if key == "" {
			key = attrs["name"]
		}
		if key = strings.ToLower(key); key != "" && attrs["content"] != "" {
			if _, dup := meta[key]; !dup {
				meta[key] = attrs["content"]
			}
		}
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := clean(meta[k]); v != "" {
				return v
			}
		}
		return ""
	}
	pv.Title = first("og:title", "twitter:title")
	if pv.Title == "" {
		if m := titleTag.FindStringSubmatch(page); m != nil {
			pv.Title = clean(m[1])
		}
	}
	pv.Description = truncate(first("og:description", "description", "twitter:description"), 400)
	pv.SiteName = first("og:site_name")
	pv.Published = first("article:published_time", "og:updated_time", "article:modified_time", "date", "dcterms.date")
	pv.Title = truncate(pv.Title, 200)
}

func clean(s string) string {
	return strings.TrimSpace(spaceRuns.ReplaceAllString(html.UnescapeString(s), " "))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// --- News and discussions --------------------------------------------------

type NewsItem struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Source    string `json:"source,omitempty"`
	Published string `json:"published,omitempty"`
	// Discussion-only fields.
	DiscussionURL string `json:"discussion_url,omitempty"`
	Points        int    `json:"points,omitempty"`
	Comments      int    `json:"comments,omitempty"`
}

// news searches Google News for the exact CVE ID. Links go through Google
// News, which redirects to the publisher.
func (c *Client) news(ctx context.Context, cveID string) ([]NewsItem, error) {
	q := url.Values{"q": {`"` + cveID + `"`}, "hl": {"en-US"}, "gl": {"US"}, "ceid": {"US:en"}}
	resp, err := fetch.Get(ctx, c.http, googleNewsRSS+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var feed struct {
		Items []struct {
			Title   string `xml:"title"`
			Link    string `xml:"link"`
			PubDate string `xml:"pubDate"`
			Source  struct {
				Name string `xml:",chardata"`
			} `xml:"source"`
		} `xml:"channel>item"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&feed); err != nil {
		return nil, fmt.Errorf("decode news feed: %w", err)
	}
	var out []NewsItem
	for _, it := range feed.Items {
		title := clean(it.Title)
		// Google appends " - Publisher" to titles.
		if src := clean(it.Source.Name); src != "" {
			title = strings.TrimSuffix(title, " - "+src)
		}
		item := NewsItem{Title: title, URL: it.Link, Source: clean(it.Source.Name)}
		if t, err := time.Parse(time.RFC1123, it.PubDate); err == nil {
			item.Published = t.UTC().Format(time.RFC3339)
		} else if t, err := time.Parse(time.RFC1123Z, it.PubDate); err == nil {
			item.Published = t.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Published > out[j].Published })
	if len(out) > maxNewsItems {
		out = out[:maxNewsItems]
	}
	return out, nil
}

// discussions searches Hacker News stories mentioning the CVE ID.
func (c *Client) discussions(ctx context.Context, cveID string) ([]NewsItem, error) {
	q := url.Values{"query": {`"` + cveID + `"`}, "tags": {"story"}, "hitsPerPage": {"20"}}
	var res struct {
		Hits []struct {
			ObjectID    string `json:"objectID"`
			Title       string `json:"title"`
			URL         string `json:"url"`
			Points      int    `json:"points"`
			NumComments int    `json:"num_comments"`
			CreatedAt   string `json:"created_at"`
		} `json:"hits"`
	}
	if err := c.getJSON(ctx, hnSearchAPI+"?"+q.Encode(), &res); err != nil {
		return nil, err
	}
	var out []NewsItem
	for _, h := range res.Hits {
		hn := "https://news.ycombinator.com/item?id=" + h.ObjectID
		link := h.URL
		if link == "" {
			link = hn
		}
		host := ""
		if p, err := url.Parse(link); err == nil {
			host = strings.TrimPrefix(p.Hostname(), "www.")
		}
		out = append(out, NewsItem{
			Title: clean(h.Title), URL: link, Source: host, Published: h.CreatedAt,
			DiscussionURL: hn, Points: h.Points, Comments: h.NumComments,
		})
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Points > out[j].Points })
	return out, nil
}
