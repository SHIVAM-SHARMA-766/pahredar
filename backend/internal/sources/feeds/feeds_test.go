package feeds

import (
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
