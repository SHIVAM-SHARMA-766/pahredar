package easm

import "testing"

func TestParseRobots(t *testing.T) {
	body := "User-agent: *\nDisallow: /admin\nDisallow: /api/private\nDisallow:\nDisallow: /\nSitemap: https://x.com/sitemap.xml\n"
	dis, sm := parseRobots(body)
	if len(dis) != 2 || dis[0] != "/admin" || dis[1] != "/api/private" {
		t.Errorf("disallows = %v", dis)
	}
	if len(sm) != 1 || sm[0] != "https://x.com/sitemap.xml" {
		t.Errorf("sitemaps = %v", sm)
	}
}

func TestParseSitemap(t *testing.T) {
	body := `<urlset><url><loc>https://x.com/a</loc></url><url><loc> https://x.com/b </loc></url><url><loc>https://x.com/a</loc></url></urlset>`
	locs := parseSitemap(body)
	if len(locs) != 2 || locs[0] != "https://x.com/a" || locs[1] != "https://x.com/b" {
		t.Errorf("locs = %v", locs)
	}
}

func TestNormalizeURLKey(t *testing.T) {
	cases := []struct{ domain, item, want string }{
		{"x.com", "/admin", "x.com/admin"},
		{"x.com", "https://x.com/login", "x.com/login"},
		{"x.com", "https://api.x.com/v1", "api.x.com/v1"},
		{"x.com", "https://evil.com/p", ""}, // off-scope
		{"x.com", "", ""},
	}
	for _, c := range cases {
		if got := normalizeURLKey(c.domain, c.item); got != c.want {
			t.Errorf("normalizeURLKey(%q,%q) = %q, want %q", c.domain, c.item, got, c.want)
		}
	}
}

func TestURLRecordsCapAndScope(t *testing.T) {
	recs := urlRecords("x.com", []string{"/a", "/a", "https://evil.com/x", "/b"}, "test")
	if len(recs) != 2 { // /a (deduped) + /b; evil.com dropped
		t.Fatalf("want 2 url records, got %d", len(recs))
	}
}
