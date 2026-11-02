package reports

import (
	"encoding/json"
	"net"
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

func TestFillPreview(t *testing.T) {
	var pv AdvisoryPreview
	fillPreview(&pv, `<html><head><title>Fallback</title>
		<meta property="og:title" content="Cisco &amp; Friends Advisory">
		<meta name='description' content='  Multiple   flaws fixed. '>
		<meta property="article:published_time" content="2024-02-01T10:00:00Z">
		<meta property="og:site_name" content="Cisco"></head></html>`)
	if pv.Title != "Cisco & Friends Advisory" || pv.Description != "Multiple flaws fixed." || pv.Published != "2024-02-01T10:00:00Z" || pv.SiteName != "Cisco" {
		t.Fatalf("got %+v", pv)
	}
	var bare AdvisoryPreview
	fillPreview(&bare, `<title> Only a title </title>`)
	if bare.Title != "Only a title" {
		t.Fatalf("title fallback = %q", bare.Title)
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fc00::1": false,
	} {
		if got := isPublic(net.ParseIP(ip)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestIsMicrosoft(t *testing.T) {
	if !isMicrosoft(Request{Assigner: "microsoft"}) || !isMicrosoft(Request{Vendors: []string{"apache", "microsoft"}}) || isMicrosoft(Request{Assigner: "apache"}) {
		t.Fatal("isMicrosoft wrong")
	}
}
