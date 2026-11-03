package feeds

import (
	neturl "net/url"
	"strings"
	"testing"
)

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("Fixes cve-2024-3400 and CVE-2024-3400, plus CVE-2021-44228; not CVE-24-1 or XCVE-2020-1234X")
	if strings.Join(got, ",") != "CVE-2024-3400,CVE-2021-44228" {
		t.Fatalf("got %v", got)
	}
}

func TestParseFormats(t *testing.T) {
	rss := `<rss><channel>
		<item><title>Ivanti &amp; CVE-2026-1111</title><link>https://a.example/1</link><pubDate>Tue, 13 Oct 2026 14:33:02 Z</pubDate>
		<description><![CDATA[<p>Fixes <b>CVE-2026-2222</b></p>]]></description></item>
		<item><title>Cisco</title><link>https://a.example/2</link><pubDate>2026-10-30 21:52:08.0</pubDate></item>
		<item><title>no link</title></item>
	</channel></rss>`
	items, err := Parse(strings.NewReader(rss))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Title != "Ivanti & CVE-2026-1111" || strings.Join(items[0].CVEIDs, ",") != "CVE-2026-1111,CVE-2026-2222" {
		t.Fatalf("rss items = %+v", items)
	}
	if items[0].Summary != "Fixes CVE-2026-2222" || items[0].Published == nil || items[1].Published == nil {
		t.Fatalf("summary/dates = %+v", items)
	}

	atom := `<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>PZ</title>
		<link rel="replies" href="https://x/comments"/><link rel="alternate" href="https://x/post"/>
		<published>2026-10-01T10:00:00Z</published><content type="html">CVE-2026-3333</content></entry></feed>`
	items, err = Parse(strings.NewReader(atom))
	if err != nil || len(items) != 1 || items[0].URL != "https://x/post" || items[0].CVEIDs[0] != "CVE-2026-3333" {
		t.Fatalf("atom = %+v, %v", items, err)
	}

	rdf := `<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
		<item><title>DSA-1 x</title><link>https://debian/1</link><dc:date>2026-10-31</dc:date><description>CVE-2026-4444</description></item></rdf:RDF>`
	items, err = Parse(strings.NewReader(rdf))
	if err != nil || len(items) != 1 || items[0].Published == nil || items[0].CVEIDs[0] != "CVE-2026-4444" {
		t.Fatalf("rdf = %+v, %v", items, err)
	}
}

func TestArticleText(t *testing.T) {
	page := `<html><body>
		<header><a href="/x">CVE-2020-0001 in the menu</a></header>
		<div class="col main-secondary"><ul><li><a href="/ivanti-cve-2026-111357/">Ivanti CVE-2026-111357 exploited</a></li></ul></div>
		<main>
			<article class="teaser"><p>short</p></article>
			<article><h1>Botnet disrupted</h1><p>Attackers used CVE-2026-1234 and <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-9999">the router bug</a>, see <a href="/2026/ivanti-cve-2026-7777/">earlier</a> and <a href="https://www.news.example/cve-2026-6666">this</a>.</p>
				<div class="be__post-nav"><a>Next: CVE-2026-5555 write-up</a></div></article>
		</main>
		<aside><p>Don't miss: CVE-2026-118527</p></aside>
		<footer>CVE-2020-0002</footer>
	</body></html>`
	text, err := ArticleText(strings.NewReader(page), "www.news.example")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ExtractCVEs(text), ","); got != "CVE-2026-1234,CVE-2026-9999" {
		t.Fatalf("CVEs = %s; text = %q", got, text)
	}
	noArticle, _ := ArticleText(strings.NewReader(`<html><body class="single-post has-sidebar"><main><div class="widget Blog"><p>Fixes CVE-2026-4242</p></div></main><nav>CVE-2026-1</nav></body></html>`), "news.example")
	if got := strings.Join(ExtractCVEs(noArticle), ","); got != "CVE-2026-4242" {
		t.Fatalf("main fallback CVEs = %s", got)
	}
}

func TestArticleTextTeasers(t *testing.T) {
	// The story is outside <article>; the <article> elements are teasers.
	page := `<html><body><main>
		<div class="article-wrap"><h1>October Security Update</h1><p>` + strings.Repeat("Ivanti fixed issues in Connect Secure. ", 20) + `See the <a href="https://forums.ivanti.com/s/article/Security-Advisory-CVE-2026-104935">advisory</a>.</p></div>
		<article><a href="/a">Teaser about another update</a></article>
		<article><a href="/b">Another teaser</a></article>
	</main></body></html>`
	text, _ := ArticleText(strings.NewReader(page), "www.ivanti.com")
	if got := strings.Join(ExtractCVEs(text), ","); got != "CVE-2026-104935" {
		t.Fatalf("CVEs = %s", got)
	}
}

func TestParseGitHub(t *testing.T) {
	items, err := parseGitHub(strings.NewReader(`[
		{"ghsa_id":"GHSA-w8hw-w9fx-j79w","cve_id":"CVE-2026-109618","html_url":"https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w","summary":"RCE via OOM corruption","description":"Fixed in 8.4.9","severity":"critical","published_at":"2026-10-21T10:00:00Z","identifiers":[{"type":"GHSA","value":"GHSA-w8hw-w9fx-j79w"}]},
		{"ghsa_id":"GHSA-p3m5-59mp-jv5r","cve_id":null,"html_url":"https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r","summary":"Denial of Service","description":"No CVE yet","severity":"high","published_at":"2026-10-14T00:00:00Z","identifiers":[]}
	]`))
	if err != nil || len(items) != 2 {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
	if items[0].Title != "CVE-2026-109618: RCE via OOM corruption" || strings.Join(items[0].CVEIDs, ",") != "CVE-2026-109618" || items[0].Published == nil {
		t.Fatalf("first = %+v", items[0])
	}
	if items[1].Title != "Denial of Service" || len(items[1].CVEIDs) != 0 || !strings.HasPrefix(items[1].Summary, "High severity.") {
		t.Fatalf("second = %+v", items[1])
	}
}

func TestParseCERTIn(t *testing.T) {
	page := `<table><tr><td class=contentTD><li><a href="/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0534"><span class="verblue2">CERT-In Vulnerability Note CIVN-2026-0534</span></a></li></td></tr>
		<tr><td class=contentTD ><span class="DateContent"> &nbsp;&nbsp;(November  02, 2026) </span></td></tr>
		<tr><td class=contentTD><DIV style="height:30px; overflow: hidden"><span style="padding-left:15px">Denial of Service Vulnerability in Cisco products</span></DIV></td></tr></table>`
	base, _ := neturl.Parse("https://www.cert-in.org.in/s2cMainServlet?pageid=VLNLIST02")
	items, err := parseCERTIn(strings.NewReader(page), base)
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
	it := items[0]
	if it.URL != "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0534" || it.Title != "CIVN-2026-0534: Denial of Service Vulnerability in Cisco products" || it.Published == nil || it.Published.Format("2006-01-02") != "2026-11-02" {
		t.Fatalf("item = %+v", it)
	}
	if _, err := parseCERTIn(strings.NewReader("<html>redesigned</html>"), base); err == nil {
		t.Fatal("want an error when the layout changes")
	}
}
