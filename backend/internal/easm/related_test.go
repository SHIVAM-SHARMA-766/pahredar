package easm

import "testing"

func TestRelatedRegistrable(t *testing.T) {
	ourReg := "example.com"
	cases := map[string]string{
		"sibling.org":     "sibling.org", // different org → related
		"www.sibling.org": "sibling.org", // subdomain → its registrable
		"*.other.co.uk":   "other.co.uk", // wildcard + multi-level TLD
		"api.example.com": "",            // our own domain → not related
		"example.com":     "",            // exactly ours
		"localhost":       "",            // not a registrable domain
		"":                "",            // empty
	}
	for san, want := range cases {
		if got := relatedRegistrable(ourReg, san); got != want {
			t.Errorf("relatedRegistrable(%q, %q) = %q, want %q", ourReg, san, got, want)
		}
	}
}
