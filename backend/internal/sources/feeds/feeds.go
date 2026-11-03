// Package feeds reads security news, research, vendor PSIRT, and government
// advisory feeds (RSS 2.0, RSS 1.0/RDF, Atom) and extracts the CVE IDs each
// item mentions. News sites rarely put CVE IDs in feed text, so for feeds
// marked FetchPage the article page itself is read once to find them.
package feeds

import (
	"context"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	neturl "net/url"
)

// Kind groups feeds for display and for "before NVD" alerting.
const (
	KindVendor     = "vendor"     // vendor PSIRT advisories
	KindGovernment = "government" // CISA, CERT/CC
	KindResearch   = "research"   // security research blogs
	KindNews       = "news"       // security news sites
)

type Feed struct {
	Key  string
	Name string
	URL  string
	Kind string
	// FetchPage reads each new item's page to find CVE IDs the feed text
	// omits. Only for feeds whose items are articles on the publisher's site.
	FetchPage bool
}

// All is the feed list. Every URL was checked to return a parseable feed
// when added; a feed that starts failing shows up in the sync run's errors.
var All = []Feed{
	// Vendor PSIRTs: advisories often land here before NVD analysis.
	{Key: "cisco-psirt", Name: "Cisco PSIRT", URL: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", Kind: KindVendor},
	{Key: "paloalto-psirt", Name: "Palo Alto Networks", URL: "https://security.paloaltonetworks.com/rss.xml", Kind: KindVendor},
	{Key: "fortinet-psirt", Name: "Fortinet PSIRT", URL: "https://filestore.fortinet.com/fortiguard/rss/ir.xml", Kind: KindVendor},
	{Key: "ivanti", Name: "Ivanti", URL: "https://www.ivanti.com/blog/topics/security-advisory/rss", Kind: KindVendor, FetchPage: true},
	{Key: "ubuntu-usn", Name: "Ubuntu USN", URL: "https://ubuntu.com/security/notices/rss.xml", Kind: KindVendor},
	{Key: "debian-dsa", Name: "Debian DSA", URL: "https://www.debian.org/security/dsa-long", Kind: KindVendor},
	{Key: "zdi-advisories", Name: "Zero Day Initiative", URL: "https://www.zerodayinitiative.com/rss/published/", Kind: KindVendor},
	// Government.
	{Key: "cisa", Name: "CISA advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml", Kind: KindGovernment},
	{Key: "cisa-ics", Name: "CISA ICS advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", Kind: KindGovernment},
	{Key: "certcc", Name: "CERT/CC", URL: "https://www.kb.cert.org/vulfeed/", Kind: KindGovernment},
	// Research.
	{Key: "talos", Name: "Cisco Talos", URL: "https://blog.talosintelligence.com/rss/", Kind: KindResearch},
	{Key: "unit42", Name: "Unit 42", URL: "https://unit42.paloaltonetworks.com/feed/", Kind: KindResearch, FetchPage: true},
	{Key: "tenable", Name: "Tenable", URL: "https://www.tenable.com/blog/feed", Kind: KindResearch},
	{Key: "projectzero", Name: "Google Project Zero", URL: "https://googleprojectzero.blogspot.com/feeds/posts/default", Kind: KindResearch},
	{Key: "watchtowr", Name: "watchTowr Labs", URL: "https://labs.watchtowr.com/rss/", Kind: KindResearch},
	{Key: "horizon3", Name: "Horizon3.ai", URL: "https://www.horizon3.ai/feed/", Kind: KindResearch, FetchPage: true},
	{Key: "checkpoint", Name: "Check Point Research", URL: "https://research.checkpoint.com/feed/", Kind: KindResearch},
	{Key: "zdi-blog", Name: "ZDI blog", URL: "https://www.zerodayinitiative.com/blog?format=rss", Kind: KindResearch},
	{Key: "rapid7", Name: "Rapid7", URL: "https://www.rapid7.com/blog/rss/", Kind: KindResearch, FetchPage: true},
	// News.
	{Key: "thehackernews", Name: "The Hacker News", URL: "https://feeds.feedburner.com/TheHackersNews", Kind: KindNews, FetchPage: true},
	{Key: "bleepingcomputer", Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/", Kind: KindNews, FetchPage: true},
	{Key: "securityweek", Name: "SecurityWeek", URL: "https://www.securityweek.com/feed/", Kind: KindNews, FetchPage: true},
	{Key: "therecord", Name: "The Record", URL: "https://therecord.media/feed", Kind: KindNews, FetchPage: true},
	{Key: "helpnetsecurity", Name: "Help Net Security", URL: "https://www.helpnetsecurity.com/feed/", Kind: KindNews, FetchPage: true},
	{Key: "darkreading", Name: "Dark Reading", URL: "https://www.darkreading.com/rss.xml", Kind: KindNews, FetchPage: true},
	{Key: "krebs", Name: "Krebs on Security", URL: "https://krebsonsecurity.com/feed/", Kind: KindNews},
}

// ByKey returns the feed with key k.
func ByKey(k string) (Feed, bool) {
	i := slices.IndexFunc(All, func(f Feed) bool { return f.Key == k })
	if i < 0 {
		return Feed{}, false
	}
	return All[i], true
}

type Item struct {
	URL       string
	Title     string
	Summary   string
	Published *time.Time
	CVEIDs    []string
	// HasBody is true when the feed carried the full article text, so its
	// CVE IDs are complete without reading the page.
	HasBody bool
}

var (
	cvePattern = regexp.MustCompile(`(?i)\bCVE-(\d{4})-(\d{4,7})\b`)
	tagPattern = regexp.MustCompile(`(?s)<[^>]*>`)
	spaces     = regexp.MustCompile(`\s+`)
)

// ExtractCVEs returns the distinct CVE IDs in text, upper-cased, in order of
// first appearance.
func ExtractCVEs(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cvePattern.FindAllStringSubmatch(text, -1) {
		id := "CVE-" + m[1] + "-" + m[2]
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// plain strips tags and entities and collapses whitespace.
func plain(s string) string {
	return strings.TrimSpace(spaces.ReplaceAllString(html.UnescapeString(tagPattern.ReplaceAllString(s, " ")), " "))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// rawItem covers RSS 2.0, RSS 1.0 (RDF), and Atom fields in one struct;
// encoding/xml matches on local names, so namespaced variants land here too.
type rawItem struct {
	Title string `xml:"title"`
	Link  []struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
		Text string `xml:",chardata"`
	} `xml:"link"`
	GUID        string `xml:"guid"`
	Description string `xml:"description"`
	Summary     string `xml:"summary"`
	Content     []struct {
		Text string `xml:",chardata"`
	} `xml:"content"` // atom:content and content:encoded
	Encoded   string `xml:"encoded"`
	PubDate   string `xml:"pubDate"`
	Published string `xml:"published"`
	Updated   string `xml:"updated"`
	Date      string `xml:"date"` // dc:date (RSS 1.0)
}

func (r rawItem) link() string {
	for _, l := range r.Link {
		if l.Href != "" && (l.Rel == "" || l.Rel == "alternate") {
			return strings.TrimSpace(l.Href)
		}
	}
	for _, l := range r.Link {
		if t := strings.TrimSpace(l.Text); t != "" {
			return t
		}
	}
	if strings.HasPrefix(r.GUID, "http") {
		return strings.TrimSpace(r.GUID)
	}
	return ""
}

// dateLayouts covers RFC 822/1123 variants (two-digit years as CISA uses,
// a bare "Z" zone as Ivanti uses), RFC 3339, and Cisco's SQL-style stamps.
var dateLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC822Z, time.RFC822,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 02 Jan 06 15:04:05 -0700",
	"Mon, 02 Jan 2006 15:04:05 Z", "2006-01-02 15:04:05.0", "2006-01-02 15:04:05", "2006-01-02",
}

func parseDate(vals ...string) *time.Time {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		for _, l := range dateLayouts {
			if t, err := time.Parse(l, v); err == nil {
				u := t.UTC()
				return &u
			}
		}
	}
	return nil
}

// Parse reads any of the supported feed formats. The decoder is lenient
// (non-strict, HTML entities) because several publishers emit slightly
// broken XML. HTML auto-closing is deliberately off: it treats <link> as a
// void element, which breaks RSS.
func Parse(r io.Reader) ([]Item, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	var out []Item
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(out) > 0 {
				break // keep what parsed before a broken tail
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || (se.Name.Local != "item" && se.Name.Local != "entry") {
			continue
		}
		var ri rawItem
		if err := dec.DecodeElement(&ri, &se); err != nil {
			continue
		}
		link := ri.link()
		title := plain(ri.Title)
		if link == "" || title == "" {
			continue
		}
		body := ri.Encoded
		for _, c := range ri.Content {
			body += " " + c.Text
		}
		desc := ri.Description
		if desc == "" {
			desc = ri.Summary
		}
		summary := plain(desc)
		if summary == "" {
			summary = plain(body)
		}
		out = append(out, Item{
			URL:       link,
			Title:     truncate(title, 300),
			Summary:   truncate(summary, 600),
			Published: parseDate(ri.PubDate, ri.Published, ri.Updated, ri.Date),
			CVEIDs:    ExtractCVEs(title + " " + desc + " " + body),
			HasBody:   len(plain(body)) > 1500,
		})
	}
	return out, nil
}

// Fetch downloads and parses one feed.
func Fetch(ctx context.Context, c *http.Client, f Feed) ([]Item, error) {
	resp, err := fetch.Get(ctx, c, f.URL, http.Header{"Accept": {"application/rss+xml, application/atom+xml, application/xml, text/xml"}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	items, err := Parse(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", f.Key, err)
	}
	return items, nil
}

// PageCVEs reads an article page (at most 2 MB) and returns the CVE IDs in
// its article text (see ArticleText). c must be a fetch.PublicOnlyClient:
// item links come from third parties.
func PageCVEs(ctx context.Context, c *http.Client, url string) ([]string, error) {
	resp, err := fetch.Get(ctx, c, url, http.Header{"Accept": {"text/html,application/xhtml+xml"}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	text, err := ArticleText(io.LimitReader(resp.Body, 2<<20), resp.Request.URL.Hostname())
	if err != nil {
		return nil, err
	}
	return ExtractCVEs(text), nil
}

// skipTags never hold the article itself.
var skipTags = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Noscript: true, atom.Template: true, atom.Svg: true,
	atom.Nav: true, atom.Aside: true, atom.Header: true, atom.Footer: true, atom.Form: true, atom.Iframe: true,
}

// noiseToken matches one class or id token of page furniture: sidebars,
// related or popular posts, post navigation, comments. News sites list
// other stories there, and their CVE IDs used to be attributed to every
// article on the site. Whole hyphen/underscore-separated words only, so
// "single-post" or Blogger's "widget Blog" (the post itself) do not match.
var noiseToken = regexp.MustCompile(`(?i)(^|[-_])(sidebar|related|popular|trending|recent-posts|post-nav|navigation|breadcrumbs?|comments?|share|sharing|social|newsletter|subscribe|footer|menu|dont-miss|read-next|more-stories|main-secondary|promo|advert|banner|tags-wrapper)([-_]|$)`)

// ArticleText returns the text of a page's article: the largest <article>
// when it holds a good share of the page, else <main>, else <body>,
// without page furniture. Link targets count only for links to other sites
// (vendor advisories, NVD): links to the page's own site are mostly other
// stories.
func ArticleText(r io.Reader, host string) (string, error) {
	doc, err := nethtml.Parse(r)
	if err != nil {
		return "", err
	}
	var articles []*nethtml.Node
	var main, body *nethtml.Node
	var find func(*nethtml.Node)
	find = func(n *nethtml.Node) {
		if n.Type == nethtml.ElementNode {
			if skipTags[n.DataAtom] || isNoise(n) {
				return
			}
			switch n.DataAtom {
			case atom.Article:
				articles = append(articles, n)
			case atom.Main:
				if main == nil {
					main = n
				}
			case atom.Body:
				body = n
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			find(c)
		}
	}
	find(doc)
	outer := body
	if main != nil {
		outer = main
	}
	if outer == nil {
		outer = doc
	}
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	textOf := func(n *nethtml.Node) string { return textOf(n, host) }
	outerText := textOf(outer)
	// An <article> is the story only if it holds a good share of the page;
	// otherwise the <article> elements are teasers for other stories and the
	// story itself sits in a plain <div>.
	best := ""
	for _, a := range articles {
		if t := textOf(a); len(t) > len(best) {
			best = t
		}
	}
	if len(best)*10 >= len(outerText)*4 {
		return best, nil
	}
	return outerText, nil
}

func isNoise(n *nethtml.Node) bool {
	switch n.DataAtom {
	case atom.Html, atom.Body, atom.Main, atom.Article:
		return false
	}
	for _, a := range n.Attr {
		switch a.Key {
		case "role":
			if a.Val == "complementary" || a.Val == "navigation" {
				return true
			}
		case "class", "id":
			for _, tok := range strings.Fields(a.Val) {
				if noiseToken.MatchString(tok) {
					return true
				}
			}
		}
	}
	return false
}

func textOf(n *nethtml.Node, host string) string {
	var b strings.Builder
	var walk func(*nethtml.Node)
	walk = func(n *nethtml.Node) {
		switch n.Type {
		case nethtml.TextNode:
			b.WriteString(n.Data)
			b.WriteByte(' ')
			return
		case nethtml.ElementNode:
			if skipTags[n.DataAtom] || isNoise(n) {
				return
			}
			// A link to another site (an advisory, NVD) names its CVE even
			// when the link text does not ("the router bug").
			if n.DataAtom == atom.A {
				for _, a := range n.Attr {
					if a.Key == "href" && externalLink(a.Val, host) {
						b.WriteString(a.Val)
						b.WriteByte(' ')
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// externalLink reports whether href is absolute and on a host other than
// the page's (subdomains of a different name count as other sites, so
// forums.ivanti.com is external to www.ivanti.com).
func externalLink(href, host string) bool {
	u, err := neturl.Parse(strings.TrimSpace(href))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.") != host
}
