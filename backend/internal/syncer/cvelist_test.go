package syncer

import "testing"

func TestListCursorRoundTrip(t *testing.T) {
	for _, s := range []string{"2026-10-28 0700Z", "2026-10-27 eod", "2026-10-28 0000Z"} {
		c, err := parseListCursor(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if c.String() != s {
			t.Fatalf("round trip %q -> %q", s, c.String())
		}
	}
	for _, bad := range []string{"", "2026-10-28", "28-10-2026 0700Z"} {
		if _, err := parseListCursor(bad); err == nil {
			t.Errorf("parseListCursor(%q) succeeded", bad)
		}
	}
}
