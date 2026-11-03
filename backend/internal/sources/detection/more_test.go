package detection

import (
	"strings"
	"testing"
)

func TestParseSplunk(t *testing.T) {
	body := `name: Log4Shell JNDI Payload Injection Attempt
id: c184f12e-5c90-11ec-bf1f-497c9a704a72
type: Anomaly
status: production
description: Detects CVE-2021-44228 attempts.
data_source:
  - Splunk Stream HTTP
search: '| from datamodel Web | search "${jndi:"'
tags:
  cve:
    - CVE-2021-44228
    - CVE-2021-45046
  mitre_attack_id:
    - T1190
`
	r, ok := parseSplunk("detections/web/log4shell.yml", []byte(body))
	if !ok || r.RuleID != "c184f12e-5c90-11ec-bf1f-497c9a704a72" || strings.Join(r.CVEIDs, ",") != "CVE-2021-44228,CVE-2021-45046" || !strings.Contains(r.Body, "jndi") {
		t.Fatalf("rule = %+v", r)
	}
	if _, ok := parseSplunk("x.yml", []byte(strings.Replace(body, "status: production", "status: deprecated", 1))); ok {
		t.Fatal("deprecated detection kept")
	}
}

func TestParseElastic(t *testing.T) {
	body := `[metadata]
maturity = "production"

[rule]
rule_id = "a1b2"
name = "Potential curl CVE-2023-38545 Exploitation"
description = "Heap overflow."
language = "eql"
type = "eql"
severity = "high"
risk_score = 73
index = ["logs-endpoint.events.process*"]
query = '''
process where process.name == "curl"
'''

[[rule.threat]]
[[rule.threat.technique]]
id = "T1203"
`
	r, ok := parseElastic("rules/linux/curl.toml", []byte(body))
	if !ok || r.RuleID != "a1b2" || strings.Join(r.CVEIDs, ",") != "CVE-2023-38545" || r.Meta["language"] != "eql" || !strings.Contains(r.Body, "curl") {
		t.Fatalf("rule = %+v", r)
	}
	if _, ok := parseElastic("x.toml", []byte(strings.Replace(body, `"production"`, `"deprecated"`, 1))); ok {
		t.Fatal("deprecated rule kept")
	}
}

func TestParseSnort(t *testing.T) {
	rules, err := parseSnort(strings.NewReader(`alert tcp any any -> any 445 ( msg:"OS-WINDOWS SMB EternalBlue"; reference:cve,2017-0144; classtype:attempted-admin; sid:41978; rev:5; )
# alert tcp any any -> any 80 ( msg:"SERVER-WEB old"; reference:cve,2014-6271; sid:31975; rev:2; )
alert tcp any any -> any 80 ( msg:"no cve"; sid:1; )
`))
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %+v, err = %v", rules, err)
	}
	if rules[0].RuleID != "41978" || rules[0].Meta["enabled"] != true || rules[1].Meta["enabled"] != false || rules[1].CVEIDs[0] != "CVE-2014-6271" {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestParseYARA(t *testing.T) {
	text := `rule APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT {
   meta:
      description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868"
      score = 75
   strings:
      $h = { 4D 5A }
   condition:
      $h
}

private rule Helper { condition: true }

rule MAL_Other { meta: description = "No CVE here" condition: true }
`
	rules := parseYARA("yara/apt.yar", text)
	if len(rules) != 1 || rules[0].CVEIDs[0] != "CVE-2023-2868" || !strings.Contains(rules[0].Body, "4D 5A") || strings.Contains(rules[0].Body, "Helper") {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestParseYARADependencies(t *testing.T) {
	text := `import "pe"
import "math"

private rule IsPE { condition: uint16(0) == 0x5A4D and pe.number_of_sections > 0 }

rule Exploit_CVE_2024_1234 {
   meta:
      description = "Exploit for CVE-2024-1234"
   condition:
      IsPE and filesize < 1MB
}
`
	rules := parseYARA("yara/x.yar", text)
	if len(rules) != 1 {
		t.Fatalf("rules = %+v", rules)
	}
	m := rules[0].Meta
	if imp, _ := m["imports"].([]string); len(imp) != 1 || imp[0] != "pe" {
		t.Fatalf("imports = %v", m["imports"])
	}
	if req, _ := m["requires"].([]string); len(req) != 1 || !strings.Contains(req[0], "private rule IsPE") {
		t.Fatalf("requires = %v", m["requires"])
	}
}

func TestYARARequiresOrder(t *testing.T) {
	blocks := map[string]string{
		"Main":  "rule Main { condition: B }",
		"B":     "private rule B { condition: A }",
		"A":     "private rule A { condition: true }",
		"Other": "rule Other { condition: true }",
	}
	got := yaraRequires("Main", blocks)
	if len(got) != 2 || !strings.Contains(got[0], "rule A") || !strings.Contains(got[1], "rule B") {
		t.Fatalf("order = %q", got)
	}
}
