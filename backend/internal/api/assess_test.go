package api

import (
	"testing"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

func TestAssess(t *testing.T) {
	high := &cverecord.Metric{Score: 8.1}
	low := &cverecord.Metric{Score: 4.0}
	cases := []struct {
		name     string
		d        db.CVEDetail
		best     *cverecord.Metric
		ssvc     *cverecord.SSVC
		exploit  string
		priority string
	}{
		{"kev", db.CVEDetail{State: "PUBLISHED", KEV: &db.KEVOut{DateAdded: time.Now()}}, low, nil, "active", "P1"},
		{"ssvc active", db.CVEDetail{State: "PUBLISHED"}, low, &cverecord.SSVC{Exploitation: "active"}, "active", "P1"},
		{"high epss", db.CVEDetail{State: "PUBLISHED", EPSS: &db.EPSSOut{Score: 0.2}}, low, nil, "none", "P2"},
		{"poc and high cvss", db.CVEDetail{State: "PUBLISHED", Exploits: []db.ExploitOut{{Source: "github"}}}, high, nil, "poc", "P2"},
		{"poc low cvss", db.CVEDetail{State: "PUBLISHED", ExploitRef: true}, low, nil, "poc", "P3"},
		{"high cvss only", db.CVEDetail{State: "PUBLISHED"}, high, nil, "none", "P3"},
		{"nothing", db.CVEDetail{State: "PUBLISHED"}, low, nil, "none", "P4"},
		{"rejected", db.CVEDetail{State: "REJECTED", KEV: &db.KEVOut{}}, high, nil, "none", ""},
	}
	for _, c := range cases {
		a := assess(&c.d, c.best, c.ssvc)
		if a.Exploitation != c.exploit || a.Priority != c.priority || len(a.Reasons) == 0 {
			t.Errorf("%s: got %+v", c.name, a)
		}
	}
}
