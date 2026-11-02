// Package debian reads the Debian Security Tracker's full JSON export
// (security-tracker.debian.org/tracker/data/json, ~90 MB): for each source
// package and CVE, the status, fixed version, and urgency per Debian
// release. It is decoded one package at a time to keep memory flat.
package debian

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const trackerURL = "https://security-tracker.debian.org/tracker/data/json"

// Status is one (CVE, source package, release) row.
type Status struct {
	CVEID        string
	Package      string
	Release      string
	Status       string // resolved, open, undetermined
	FixedVersion string // "0" means the release was never affected
	Urgency      string
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func Fetch(ctx context.Context, c *http.Client) ([]Status, error) {
	resp, err := fetch.Get(ctx, c, trackerURL, http.Header{"Accept": {"application/json"}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("debian tracker: expected an object (%v)", err)
	}
	var out []Status
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		pkg, _ := t.(string)
		var cves map[string]struct {
			Releases map[string]struct {
				Status       string `json:"status"`
				FixedVersion string `json:"fixed_version"`
				Urgency      string `json:"urgency"`
			} `json:"releases"`
		}
		if err := dec.Decode(&cves); err != nil {
			return nil, fmt.Errorf("debian tracker: package %q: %w", pkg, err)
		}
		for id, v := range cves {
			if !cvePattern.MatchString(id) {
				continue
			}
			for rel, s := range v.Releases {
				out = append(out, Status{CVEID: id, Package: pkg, Release: rel, Status: s.Status, FixedVersion: s.FixedVersion, Urgency: s.Urgency})
			}
		}
	}
	return out, nil
}
