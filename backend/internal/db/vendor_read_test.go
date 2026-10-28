package db

import "testing"

func TestPrettyLabel(t *testing.T) {
	for in, want := range map[string]string{
		"debian":              "Debian",
		"windows server 2016": "Windows Server 2016",
		"IBM":                 "IBM",
		"qEngine CMS":         "qEngine CMS",
		"":                    "",
	} {
		if got := PrettyLabel(in); got != want {
			t.Errorf("PrettyLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
