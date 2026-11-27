package easm

import "testing"

func TestSameSiteScripts(t *testing.T) {
	html := `<html>
	<script src="/assets/app.js"></script>
	<script src="https://x.com/vendor.js"></script>
	<script src="https://cdn.jsdelivr.net/lib.js"></script>
	<script src="./rel.js"></script>
	<script src="//x.com/proto.js"></script>
	<script src="data:text/javascript,alert(1)"></script>
	</html>`
	got := sameSiteScripts("x.com", html)
	want := map[string]bool{"x.com/assets/app.js": true, "x.com/vendor.js": true, "x.com/rel.js": true, "x.com/proto.js": true}
	if len(got) != len(want) {
		t.Fatalf("scripts = %v, want %d entries", got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected script %q (off-site CDN or data: must be dropped)", g)
		}
	}
}

func TestExtractAPIPaths(t *testing.T) {
	text := `fetch("/api/users"); const u = '/v1/orders/42'; x = "/graphql"; nope = "/static/img.png"; a="/api/users";`
	got := extractAPIPaths(text)
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}
	for _, p := range []string{"/api/users", "/v1/orders/42", "/graphql"} {
		if !set[p] {
			t.Errorf("missing API path %q in %v", p, got)
		}
	}
	if set["/static/img.png"] {
		t.Error("/static path must not match")
	}
	if len(got) != 3 {
		t.Errorf("want 3 unique paths, got %d (%v)", len(got), got)
	}
}

func TestLooksLikeSourceMap(t *testing.T) {
	if !looksLikeSourceMap(`{"version":3,"sources":["a.ts"],"mappings":"AAAA"}`) {
		t.Error("valid source map not detected")
	}
	if looksLikeSourceMap(`<!doctype html><title>Not found</title>`) {
		t.Error("HTML error page wrongly detected as source map")
	}
}
