package easm

import "testing"

func TestTxtTag(t *testing.T) {
	cases := []struct{ record, tag, want string }{
		{"v=STSv1; id=20260101T000000;", "id", "20260101T000000"},
		{"v=BIMI1; l=https://x/logo.svg; a=", "l", "https://x/logo.svg"},
		{"v=TLSRPTv1; rua=mailto:a@b.com", "rua", "mailto:a@b.com"},
		{"v=STSv1;", "id", ""},
		{"v=DKIM1; k=rsa; p=ABC", "k", "rsa"},
	}
	for _, c := range cases {
		if got := txtTag(c.record, c.tag); got != c.want {
			t.Errorf("txtTag(%q, %q) = %q, want %q", c.record, c.tag, got, c.want)
		}
	}
}

func TestDmarcPolicy(t *testing.T) {
	if got := dmarcPolicy("v=DMARC1; p=reject; rua=mailto:x"); got != "reject" {
		t.Errorf("dmarcPolicy = %q, want reject", got)
	}
	if got := dmarcPolicy("v=DMARC1; sp=none"); got != "" {
		t.Errorf("dmarcPolicy (no p=) = %q, want empty", got)
	}
}
