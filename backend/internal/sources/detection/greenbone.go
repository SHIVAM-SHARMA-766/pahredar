package detection

import (
	"context"
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/greenbone"
)

// SourceGreenbone holds the Greenbone Community Feed's vulnerability tests
// (see package greenbone). They run only inside a Greenbone scanner, so the
// rule body is the test's summary and solution, not the NASL script.
const SourceGreenbone = "greenbone"

func init() {
	Fetchers[SourceGreenbone] = Greenbone
}

func Greenbone(ctx context.Context, c *http.Client) ([]Rule, error) {
	tests, err := greenbone.Fetch(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, len(tests))
	for i, t := range tests {
		body := t.Summary
		if t.Solution != "" {
			body += "\n\nSolution: " + t.Solution
		}
		meta := map[string]any{"family": t.Family, "check": t.Check, "license": "GPL-2.0", "file": t.Path}
		for k, v := range map[string]string{"qod_type": t.QoDType, "solution_type": t.SolutionType, "cvss_vector": t.CVSSVector, "modified": t.Modified} {
			if v != "" {
				meta[k] = v
			}
		}
		out[i] = Rule{RuleID: t.OID, Title: t.Name, Body: body, Meta: meta, CVEIDs: t.CVEIDs}
	}
	return out, nil
}
