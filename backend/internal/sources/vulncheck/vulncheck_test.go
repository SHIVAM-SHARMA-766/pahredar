package vulncheck

import "testing"

func TestEntries(t *testing.T) {
	var r record
	r.CVE = []string{"cve-2023-46604", "not-a-cve"}
	r.Ransomware = "Known"
	r.DateAdded = "2023-11-02T00:00:00Z"
	r.Reported = append(r.Reported, struct {
		URL       string `json:"url"`
		DateAdded string `json:"date_added"`
	}{"https://example.com/a", "2023-11-02T00:00:00Z"})
	r.XDB = append(r.XDB, struct {
		ID        string `json:"xdb_id"`
		URL       string `json:"xdb_url"`
		Type      string `json:"exploit_type"`
		CloneURL  string `json:"clone_ssh_url"`
		DateAdded string `json:"date_added"`
	}{"1e13", "https://vulncheck.com/xdb/1e13", "initial-access", "git@github.com:trganda/ActiveMQ-RCE.git", "2023-10-26T03:25:05Z"})
	es := entries(r)
	if len(es) != 1 || es[0].CVEID != "CVE-2023-46604" || !es[0].Ransomware || es[0].DateAdded == nil {
		t.Fatalf("entries = %+v", es)
	}
	if es[0].Reported[0].DateAdded != "2023-11-02" || es[0].XDB[0].Repo != "https://github.com/trganda/ActiveMQ-RCE" {
		t.Fatalf("details = %+v %+v", es[0].Reported, es[0].XDB)
	}
}
