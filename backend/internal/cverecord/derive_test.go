package cverecord

import (
	"os"
	"testing"
)

func mustParse(t *testing.T, path string) *Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestDeriveCNAv4(t *testing.T) {
	rec := mustParse(t, "testdata/CVE-2014-125136.json")
	d := Derive(rec, nil)

	if rec.Metadata.ID != "CVE-2014-125136" || rec.Metadata.State != "PUBLISHED" {
		t.Fatalf("metadata = %+v", rec.Metadata)
	}
	if d.V4 == nil || d.V4.Score != 8.2 || d.V4.Provider != ProviderCNA {
		t.Fatalf("V4 = %+v", d.V4)
	}
	if d.Severity != "HIGH" || d.SeveritySource != "cna:cvss4.0" {
		t.Fatalf("severity = %s from %s", d.Severity, d.SeveritySource)
	}
	if len(d.CWEs) != 1 || d.CWEs[0] != "CWE-530" {
		t.Fatalf("CWEs = %v", d.CWEs)
	}
	if len(d.Affected) != 3 || d.Affected[0].Vendor != "c97net" || d.Affected[0].Product != "qengine cms" {
		t.Fatalf("affected = %+v", d.Affected)
	}
	if d.Description == "" || len(d.References) == 0 {
		t.Fatal("missing description or references")
	}
}

func TestDeriveFallsBackToADP(t *testing.T) {
	rec := mustParse(t, "testdata/CVE-2025-60475.json")
	d := Derive(rec, nil)

	if d.V3 == nil || d.V3.Provider != ProviderADP || d.V3.Score != 5.5 {
		t.Fatalf("V3 = %+v", d.V3)
	}
	if d.Severity != "MEDIUM" || d.SeveritySource != "adp:cvss3.1" {
		t.Fatalf("severity = %s from %s", d.Severity, d.SeveritySource)
	}
	if s := CISASSVC(rec); s == nil || s.Exploitation != "poc" || s.Automatable != "no" {
		t.Fatalf("SSVC = %+v", s)
	}
	// The CVE Program container's reference is merged in.
	found := false
	for _, r := range d.References {
		if r.URL == "http://www.openwall.com/lists/oss-security/2026/10/28/2" {
			found = true
		}
	}
	if !found {
		t.Fatal("ADP reference not merged")
	}
}

func TestNVDOutranksADPButNotCNA(t *testing.T) {
	nvd, err := ParseNVD([]byte(`{
		"id": "CVE-2025-60475",
		"metrics": {"cvssMetricV31": [
			{"source": "other@example.com", "type": "Secondary", "cvssData": {"baseScore": 6.1, "vectorString": "CVSS:3.1/x", "baseSeverity": "MEDIUM"}},
			{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/y", "baseSeverity": "CRITICAL"}}
		]},
		"weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	d := Derive(mustParse(t, "testdata/CVE-2025-60475.json"), nvd)
	if d.V3.Provider != ProviderNVD || d.V3.Score != 9.8 || d.SeveritySource != "nvd:cvss3.1" {
		t.Fatalf("V3 = %+v, source %s", d.V3, d.SeveritySource)
	}
	if len(d.CWEs) != 2 || d.CWEs[0] != "CWE-119" || d.CWEs[1] != "CWE-787" {
		t.Fatalf("CWEs = %v", d.CWEs)
	}

	d = Derive(mustParse(t, "testdata/CVE-2014-125136.json"), nvd)
	if d.SeveritySource != "cna:cvss4.0" {
		t.Fatalf("CNA v4 should win, got %s", d.SeveritySource)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, raw := range []string{
		`{"cveMetadata": {"cveId": "not-a-cve", "state": "PUBLISHED"}}`,
		`{"cveMetadata": {"cveId": "CVE-2024-1234", "state": "RESERVED"}}`,
		`{`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("Parse(%s) succeeded", raw)
		}
	}
}

func TestParseStripsNUL(t *testing.T) {
	rec, err := Parse([]byte(`{"cveMetadata": {"cveId": "cve-2024-1234", "state": "published"},
		"containers": {"cna": {"descriptions": [{"lang": "en", "value": "a\u0000b"}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Metadata.ID != "CVE-2024-1234" {
		t.Fatalf("ID = %s", rec.Metadata.ID)
	}
	if d := Derive(rec, nil); d.Description != "ab" {
		t.Fatalf("description = %q", d.Description)
	}
}

func TestCPEVendorProduct(t *testing.T) {
	cases := []struct {
		cpe, vendor, product string
		ok                   bool
	}{
		{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "apache", "log4j", true},
		{`cpe:2.3:a:acme\:corp:big\\tool:*:*:*:*:*:*:*:*`, "acme:corp", `big\tool`, true},
		{"cpe:2.3:o:*:linux:*:*:*:*:*:*:*:*", "", "", false},
		{"cpe:2.3:a:vendor", "", "", false},
		{"cpe:/a:apache:log4j", "", "", false},
	}
	for _, c := range cases {
		v, p, ok := cpeVendorProduct(c.cpe)
		if ok != c.ok || v != c.vendor || p != c.product {
			t.Errorf("%s: got (%q, %q, %v)", c.cpe, v, p, ok)
		}
	}
}

func TestDeriveNVDAffectedAndExploitRef(t *testing.T) {
	nvd, err := ParseNVD([]byte(`{
		"id": "CVE-2025-60475",
		"configurations": [{"nodes": [{"cpeMatch": [
			{"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"},
			{"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:3.0:*:*:*:*:*:*:*"},
			{"vulnerable": false, "criteria": "cpe:2.3:o:acme:os:-:*:*:*:*:*:*:*"}
		]}]}],
		"references": [{"url": "https://example.com/poc", "tags": ["Exploit", "Third Party Advisory"]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := Derive(mustParse(t, "testdata/CVE-2025-60475.json"), nvd)
	var nvdRows []AffectedRow
	for _, a := range d.Affected {
		if a.Source == ProviderNVD {
			nvdRows = append(nvdRows, a)
		}
	}
	if len(nvdRows) != 1 || nvdRows[0].Vendor != "acme" || nvdRows[0].Product != "widget" || len(nvdRows[0].CPEs) != 2 {
		t.Fatalf("nvd affected = %+v", nvdRows)
	}
	if !d.ExploitRef {
		t.Fatal("ExploitRef not set from NVD Exploit tag")
	}
	if Derive(mustParse(t, "testdata/CVE-2025-60475.json"), nil).ExploitRef {
		t.Fatal("ExploitRef set without an exploit tag")
	}
	if !Derive(mustParse(t, "testdata/CVE-2014-125136.json"), nil).ExploitRef {
		t.Fatal("ExploitRef not set from CNA exploit tag")
	}
}
