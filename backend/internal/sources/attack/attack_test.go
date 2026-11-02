package attack

import (
	"strings"
	"testing"
)

func TestParseCAPEC(t *testing.T) {
	in := `'ID,Name,Abstraction,Status,Description,Likelihood Of Attack,Typical Severity,Execution Flow,Prerequisites,Indicators,Mitigations,Related Weaknesses,Taxonomy Mappings
1,Accessing Functionality,Standard,Draft,Desc,High,High,"::STEP:1:PHASE:Explore:DESCRIPTION:[Survey] The attacker surveys: carefully:TECHNIQUE:Spidering::STEP:2:PHASE:Exploit:DESCRIPTION:Access it::","::Pre one::Pre two::",,"::Mit one::","::276::285::","TAXONOMY NAME:ATTACK:ENTRY ID:1574.010:ENTRY NAME:Hijack Execution Flow: Services File Permissions Weakness::TAXONOMY NAME:ATTACK:ENTRY ID:1548:ENTRY NAME:Abuse Elevation Control Mechanism::"
2,Old,Meta,Deprecated,,,,,,,,,
`
	ps, err := parseCAPEC(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("got %d patterns, want 1", len(ps))
	}
	p := ps[0]
	if p.ID != "CAPEC-1" || p.Likelihood != "High" || len(p.Prerequisites) != 2 || len(p.Mitigations) != 1 {
		t.Errorf("pattern = %+v", p)
	}
	if strings.Join(p.CWEs, ",") != "CWE-276,CWE-285" {
		t.Errorf("cwes = %v", p.CWEs)
	}
	if len(p.Attack) != 2 || p.Attack[0].ID != "T1574.010" || p.Attack[0].Name != "Hijack Execution Flow: Services File Permissions Weakness" || p.Attack[1].ID != "T1548" {
		t.Errorf("attack = %+v", p.Attack)
	}
	if len(p.ExecutionFlow) != 2 || p.ExecutionFlow[0] != "Explore: [Survey] The attacker surveys: carefully" {
		t.Errorf("flow = %q", p.ExecutionFlow)
	}
}
