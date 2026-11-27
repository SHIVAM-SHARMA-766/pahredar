package easm

import (
	"encoding/json"
	"testing"
)

func TestGithubRecords(t *testing.T) {
	body := `{"items":[
	  {"path":"config/prod.yml","repository":{"full_name":"acme/app","html_url":"https://github.com/acme/app"}},
	  {"path":"README.md","repository":{"full_name":"acme/app","html_url":"https://github.com/acme/app"}},
	  {"path":"deploy.sh","repository":{"full_name":"other/infra","html_url":"https://github.com/other/infra"}},
	  {"path":"x","repository":{"full_name":""}}
	]}`
	var parsed struct {
		Items []ghItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	recs := githubRecords(parsed.Items)
	if len(recs) != 2 {
		t.Fatalf("want 2 repo records, got %d (%+v)", len(recs), recs)
	}
	// acme/app sorts before other/infra.
	if recs[0].Key != "acme/app" || recs[1].Key != "other/infra" {
		t.Errorf("keys = %q,%q", recs[0].Key, recs[1].Key)
	}
	var d struct {
		Repo    string   `json:"repo"`
		Paths   []string `json:"paths"`
		Matches int      `json:"matches"`
	}
	_ = json.Unmarshal(recs[0].Data, &d)
	if d.Matches != 2 || len(d.Paths) != 2 {
		t.Errorf("acme/app agg = %+v, want 2 paths", d)
	}
	if recs[0].Category != "repo_ref" || recs[0].Source != "github" || recs[0].Method != "passive" {
		t.Errorf("record shape wrong: %+v", recs[0])
	}
}
