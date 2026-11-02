package reports

import (
	"encoding/json"
	"testing"
)

func TestOSVNormalize(t *testing.T) {
	var r osvRecord
	if err := json.Unmarshal([]byte(`{
		"id": "GHSA-jfh8-c2jp-5v3q", "summary": " Remote code injection in Log4j ",
		"affected": [
			{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
			 "ranges": [{"events": [{"introduced": "0"}, {"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]},
			{"package": {}, "ranges": []}
		]}`), &r); err != nil {
		t.Fatal(err)
	}
	a := r.normalize()
	if a.Summary != "Remote code injection in Log4j" || len(a.Affected) != 1 || a.References == nil {
		t.Fatalf("got %+v", a)
	}
	af := a.Affected[0]
	if len(af.Introduced) != 1 || af.Introduced[0] != "2.13.0" || len(af.Fixed) != 1 || af.Fixed[0] != "2.15.0" {
		t.Fatalf("ranges = %+v", af)
	}
	if a.URL != "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q" {
		t.Fatalf("url = %s", a.URL)
	}
}

func TestTextOf(t *testing.T) {
	for in, want := range map[string]string{
		`"plain"`: "plain",
		`{"value": " set the flag ", "lang": "en"}`: "set the flag",
		`null`: "",
	} {
		if got := textOf(json.RawMessage(in)); got != want {
			t.Errorf("textOf(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestAliasPattern(t *testing.T) {
	for alias, want := range map[string]bool{"GHSA-jfh8-c2jp-5v3q": true, "PYSEC-2021-123": true, "CVE-2021-44228": false, "../etc": false} {
		if aliasPattern.MatchString(alias) != want {
			t.Errorf("%s: want %v", alias, want)
		}
	}
}
