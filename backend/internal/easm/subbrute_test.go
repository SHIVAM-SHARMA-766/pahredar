package easm

import (
	"strings"
	"testing"
)

func TestCommonSubdomainsSane(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range commonSubdomains {
		if s == "" || strings.ContainsAny(s, ". ") {
			t.Errorf("bad label %q (must be a bare label)", s)
		}
		if seen[s] {
			t.Errorf("duplicate label %q", s)
		}
		seen[s] = true
	}
	if len(commonSubdomains) < 40 {
		t.Errorf("wordlist unexpectedly small: %d", len(commonSubdomains))
	}
}

func TestDedupStrings(t *testing.T) {
	got := dedupStrings([]string{"b", "a", "b", "a", "c"})
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("dedupStrings = %v", got)
	}
}
