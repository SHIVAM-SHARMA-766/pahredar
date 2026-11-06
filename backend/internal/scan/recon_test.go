package scan

import "testing"

func TestDkimKey(t *testing.T) {
	cases := map[string]string{
		"v=DKIM1; p=":                "", // revoked/placeholder (example.com wildcard)
		"v=DKIM1; k=rsa; p=MIGfMA0=": "MIGfMA0=",
		"v=DKIM1;p=ABC;t=s":          "ABC",
		"k=rsa":                      "",
	}
	for in, want := range cases {
		if got := dkimKey(in); got != want {
			t.Errorf("dkimKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRdapVcardAndEvents(t *testing.T) {
	r := rdapResponse{
		Entities: []rdapEntity{{
			Roles: []string{"registrar"},
			VCardArray: []any{"vcard", []any{
				[]any{"version", map[string]any{}, "text", "4.0"},
				[]any{"fn", map[string]any{}, "text", "MarkMonitor Inc."},
			}},
		}},
		Events: []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		}{{Action: "expiration", Date: "2028-10-09T00:00:00Z"}},
	}
	if got := r.entityName("registrar"); got != "MarkMonitor Inc." {
		t.Errorf("registrar = %q", got)
	}
	if got := r.event("expiration"); got != "2028-10-09" {
		t.Errorf("expiration = %q", got)
	}
}

func TestSplitPipe(t *testing.T) {
	p := splitPipe("13335 | 104.16.0.0/12 | US | arin | 2010-07-14")
	if len(p) != 5 || p[0] != "13335" || p[2] != "US" {
		t.Fatalf("splitPipe = %#v", p)
	}
	if firstField("13335 104.16.0.0/12") != "13335" {
		t.Errorf("firstField wrong")
	}
}

func TestMMH3Hash32(t *testing.T) {
	cases := map[string]int32{
		"":                    0,
		"hello":               613153351,
		"The quick brown fox": 1621279277,
		"pahredar":            1819315621,
	}
	for in, want := range cases {
		if got := mmh3Hash32([]byte(in), 0); got != want {
			t.Errorf("mmh3Hash32(%q) = %d, want %d", in, got, want)
		}
	}
}
