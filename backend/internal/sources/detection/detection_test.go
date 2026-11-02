package detection

import (
	"slices"
	"strings"
	"testing"
)

func TestParseSigma(t *testing.T) {
	body := `title: Sudo Baron Samedit Exploitation
id: b9748c98-9ea7-4fdb-80b6-29bed6ba71d2
status: test
description: |
    Mentions CVE-2019-0001 in prose only.
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2021.3156
    - cve.2021-44228
logsource:
    product: linux
    service: auditd
detection:
    selection:
        exe: '/usr/bin/sudoedit'
    condition: selection
level: high
`
	r, ok := parseSigma("rules/linux/lnx_cve_2023_1234_x.yml", body)
	if !ok {
		t.Fatal("rule skipped")
	}
	if want := []string{"CVE-2021-3156", "CVE-2021-44228", "CVE-2023-1234"}; !slices.Equal(r.CVEIDs, want) {
		t.Errorf("cves = %v, want %v", r.CVEIDs, want)
	}
	if r.RuleID != "b9748c98-9ea7-4fdb-80b6-29bed6ba71d2" || r.Meta["level"] != "high" || r.Meta["status"] != "test" {
		t.Errorf("fields = %q %v", r.RuleID, r.Meta)
	}
	if ls := r.Meta["logsource"].(map[string]string); ls["product"] != "linux" || ls["service"] != "auditd" {
		t.Errorf("logsource = %v", ls)
	}
	if at := r.Meta["attack"].([]string); !slices.Equal(at, []string{"T1068"}) {
		t.Errorf("attack = %v", at)
	}

	if _, ok := parseSigma("rules/x.yml", "title: No CVE here\nstatus: test\n"); ok {
		t.Error("rule without a CVE kept")
	}
	if _, ok := parseSigma("rules/x.yml", "title: Old CVE-2020-1111\nstatus: deprecated\n"); ok {
		t.Error("deprecated rule kept")
	}
}

func TestParseSuricata(t *testing.T) {
	in := `# comment line
alert http any any -> any any (msg:"ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)"; content:"${jndi"; reference:cve,2021-44228; reference:cve,CVE-2021-45046; classtype:attempted-admin; sid:2034647; rev:3; metadata:created_at 2021_12_10, signature_severity Major, updated_at 2021_12_13;)
#alert tcp any any -> any 53 (msg:"ET DOS old"; reference:cve,2009-0696; classtype:attempted-dos; sid:2009701; rev:2;)
alert tcp any any -> any any (msg:"no cve"; sid:1; rev:1;)
`
	rules, err := parseSuricata(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	r := rules[0]
	if r.RuleID != "2034647" || !strings.HasPrefix(r.Title, "ET EXPLOIT Apache Log4j") || r.Meta["enabled"] != true ||
		r.Meta["classtype"] != "attempted-admin" || r.Meta["signature_severity"] != "Major" {
		t.Errorf("rule = %+v", r)
	}
	if !slices.Equal(r.CVEIDs, []string{"CVE-2021-44228", "CVE-2021-45046"}) {
		t.Errorf("cves = %v", r.CVEIDs)
	}
	if rules[1].Meta["enabled"] != false || strings.HasPrefix(rules[1].Body, "#") {
		t.Errorf("disabled rule = %+v", rules[1])
	}
}

func TestParseNmap(t *testing.T) {
	in := `Entry { filename = "http-vuln-cve2017-5638.nse", categories = { "exploit", "vuln", } }
Entry { filename = "smb-vuln-ms17-010.nse", categories = { "safe", "vuln", } }
`
	rules, err := parseNmap(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].RuleID != "http-vuln-cve2017-5638" || !slices.Equal(rules[0].CVEIDs, []string{"CVE-2017-5638"}) {
		t.Fatalf("rules = %+v", rules)
	}
}
