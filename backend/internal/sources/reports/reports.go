// Package reports fetches in-depth, per-CVE write-ups from free third-party
// APIs and normalizes them:
//
//   - OSV.dev (api.osv.dev): the CVE record and its advisory aliases (GitHub
//     Security Advisories, PyPA, Go, RustSec, …) with package-level affected
//     and fixed versions and long-form details.
//   - Red Hat Security Data API: Red Hat's statement, mitigation, Bugzilla
//     summary, and fix status per product.
//   - Ubuntu CVE tracker: priority, notes, and fix status per release.
//
// Coverage is best for open-source and Linux software; closed-source vendor
// products are usually absent. Fetches happen on demand (see the API's
// /cves/{id}/reports) and are cached by the caller.
package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const (
	SourceOSV    = "osv"
	SourceRedHat = "redhat"
	SourceUbuntu = "ubuntu"

	osvURL    = "https://api.osv.dev/v1/vulns/"
	redHatURL = "https://access.redhat.com/hydra/rest/securitydata/cve/"
	ubuntuURL = "https://ubuntu.com/security/cves/"

	// maxAliases bounds the advisory records fetched per CVE from OSV.
	maxAliases = 4
	maxBody    = 8 << 20
)

// Sources lists every report source in display order.
var Sources = []string{SourceOSV, SourceRedHat, SourceUbuntu}

// ErrNotFound means the source has no record for the CVE.
var ErrNotFound = errors.New("no record")

// Advisory IDs OSV may list as aliases. CVE aliases are skipped (they are
// the record already fetched).
var aliasPattern = regexp.MustCompile(`^(GHSA|PYSEC|GO|RUSTSEC|OSV|GSD|MAL|BIT|DSA|DLA|USN|RHSA|ALSA|RLSA)-[A-Za-z0-9.:_-]+$`)

type Ref struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

// OSVAdvisory is one OSV record.
type OSVAdvisory struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary,omitempty"`
	Details    string        `json:"details,omitempty"`
	Published  string        `json:"published,omitempty"`
	Modified   string        `json:"modified,omitempty"`
	Affected   []OSVAffected `json:"affected"`
	References []Ref         `json:"references"`
	URL        string        `json:"url"`
}

type OSVAffected struct {
	Ecosystem    string   `json:"ecosystem"`
	Package      string   `json:"package"`
	Introduced   []string `json:"introduced"`
	Fixed        []string `json:"fixed"`
	LastAffected []string `json:"last_affected"`
}

type RedHatReport struct {
	ThreatSeverity string          `json:"threat_severity,omitempty"`
	PublicDate     string          `json:"public_date,omitempty"`
	Statement      string          `json:"statement,omitempty"`
	Mitigation     string          `json:"mitigation,omitempty"`
	Summary        string          `json:"summary,omitempty"`
	BugzillaURL    string          `json:"bugzilla_url,omitempty"`
	Details        []string        `json:"details"`
	CVSS3Score     string          `json:"cvss3_score,omitempty"`
	CVSS3Vector    string          `json:"cvss3_vector,omitempty"`
	CWE            string          `json:"cwe,omitempty"`
	FixedIn        []RedHatRelease `json:"fixed_in"`
	States         []RedHatState   `json:"states"`
	URL            string          `json:"url"`
}

type RedHatRelease struct {
	Product     string `json:"product"`
	Package     string `json:"package,omitempty"`
	Advisory    string `json:"advisory,omitempty"`
	ReleaseDate string `json:"release_date,omitempty"`
}

type RedHatState struct {
	Product  string `json:"product"`
	Package  string `json:"package"`
	FixState string `json:"fix_state"`
}

type UbuntuReport struct {
	Priority          string          `json:"priority,omitempty"`
	Description       string          `json:"description,omitempty"`
	UbuntuDescription string          `json:"ubuntu_description,omitempty"`
	Mitigation        string          `json:"mitigation,omitempty"`
	Notes             []UbuntuNote    `json:"notes"`
	Packages          []UbuntuPackage `json:"packages"`
	URL               string          `json:"url"`
}

type UbuntuNote struct {
	Author string `json:"author"`
	Note   string `json:"note"`
}

type UbuntuPackage struct {
	Name     string         `json:"name"`
	Statuses []UbuntuStatus `json:"statuses"`
}

type UbuntuStatus struct {
	Release     string `json:"release"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
}

type Client struct {
	http *http.Client
}

func New(c *http.Client) *Client {
	return &Client{http: c}
}

// Fetch returns the normalized report for one source, or ErrNotFound.
func (c *Client) Fetch(ctx context.Context, source, cveID string) (any, error) {
	switch source {
	case SourceOSV:
		return c.osv(ctx, cveID)
	case SourceRedHat:
		return c.redHat(ctx, cveID)
	case SourceUbuntu:
		return c.ubuntu(ctx, cveID)
	}
	return nil, fmt.Errorf("unknown report source %q", source)
}

func (c *Client) getJSON(ctx context.Context, url string, v any) error {
	resp, err := fetch.Get(ctx, c.http, url, http.Header{"Accept": {"application/json"}})
	if err != nil {
		var se *fetch.StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return ErrNotFound
		}
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

type osvRecord struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []Ref `json:"references"`
}

func (r osvRecord) normalize() OSVAdvisory {
	a := OSVAdvisory{
		ID: r.ID, Summary: strings.TrimSpace(r.Summary), Details: strings.TrimSpace(r.Details),
		Published: r.Published, Modified: r.Modified, References: r.References,
		Affected: []OSVAffected{}, URL: "https://osv.dev/vulnerability/" + r.ID,
	}
	if a.References == nil {
		a.References = []Ref{}
	}
	for _, af := range r.Affected {
		if af.Package.Name == "" {
			continue
		}
		out := OSVAffected{Ecosystem: af.Package.Ecosystem, Package: af.Package.Name, Introduced: []string{}, Fixed: []string{}, LastAffected: []string{}}
		for _, rg := range af.Ranges {
			for _, ev := range rg.Events {
				if v := ev["introduced"]; v != "" && v != "0" {
					out.Introduced = append(out.Introduced, v)
				}
				if v := ev["fixed"]; v != "" {
					out.Fixed = append(out.Fixed, v)
				}
				if v := ev["last_affected"]; v != "" {
					out.LastAffected = append(out.LastAffected, v)
				}
			}
		}
		a.Affected = append(a.Affected, out)
	}
	return a
}

// osv fetches the CVE's OSV record and its advisory aliases. The CVE record
// itself is kept only when it adds package data; otherwise it mirrors the
// CVE List, which Pahredar already shows.
func (c *Client) osv(ctx context.Context, cveID string) ([]OSVAdvisory, error) {
	var root osvRecord
	if err := c.getJSON(ctx, osvURL+cveID, &root); err != nil {
		return nil, err
	}
	var out []OSVAdvisory
	if n := root.normalize(); len(n.Affected) > 0 {
		out = append(out, n)
	}
	fetched := 0
	for _, alias := range root.Aliases {
		if fetched == maxAliases || !aliasPattern.MatchString(alias) {
			continue
		}
		fetched++
		var rec osvRecord
		if err := c.getJSON(ctx, osvURL+alias, &rec); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("osv alias %s: %w", alias, err)
		}
		out = append(out, rec.normalize())
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (c *Client) redHat(ctx context.Context, cveID string) (*RedHatReport, error) {
	var raw struct {
		ThreatSeverity string          `json:"threat_severity"`
		PublicDate     string          `json:"public_date"`
		Statement      string          `json:"statement"`
		Mitigation     json.RawMessage `json:"mitigation"`
		Bugzilla       struct {
			Description string `json:"description"`
			URL         string `json:"url"`
		} `json:"bugzilla"`
		Details []string `json:"details"`
		CVSS3   struct {
			Score  string `json:"cvss3_base_score"`
			Vector string `json:"cvss3_scoring_vector"`
		} `json:"cvss3"`
		CWE             string `json:"cwe"`
		AffectedRelease []struct {
			Product     string `json:"product_name"`
			Package     string `json:"package"`
			Advisory    string `json:"advisory"`
			ReleaseDate string `json:"release_date"`
		} `json:"affected_release"`
		PackageState []struct {
			Product  string `json:"product_name"`
			Package  string `json:"package_name"`
			FixState string `json:"fix_state"`
		} `json:"package_state"`
	}
	if err := c.getJSON(ctx, redHatURL+cveID+".json", &raw); err != nil {
		return nil, err
	}
	r := &RedHatReport{
		ThreatSeverity: raw.ThreatSeverity, PublicDate: raw.PublicDate, Statement: strings.TrimSpace(raw.Statement),
		Mitigation: textOf(raw.Mitigation), Summary: raw.Bugzilla.Description, BugzillaURL: raw.Bugzilla.URL,
		Details: raw.Details, CVSS3Score: raw.CVSS3.Score, CVSS3Vector: raw.CVSS3.Vector, CWE: raw.CWE,
		FixedIn: []RedHatRelease{}, States: []RedHatState{},
		URL: "https://access.redhat.com/security/cve/" + strings.ToLower(cveID),
	}
	if r.Details == nil {
		r.Details = []string{}
	}
	for _, a := range raw.AffectedRelease {
		r.FixedIn = append(r.FixedIn, RedHatRelease{Product: a.Product, Package: a.Package, Advisory: a.Advisory, ReleaseDate: a.ReleaseDate})
	}
	for _, p := range raw.PackageState {
		r.States = append(r.States, RedHatState{Product: p.Product, Package: p.Package, FixState: p.FixState})
	}
	return r, nil
}

// textOf reads a field Red Hat publishes either as a string or as
// {"value": "...", "lang": "..."}.
func textOf(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return strings.TrimSpace(obj.Value)
	}
	return ""
}

func (c *Client) ubuntu(ctx context.Context, cveID string) (*UbuntuReport, error) {
	var raw struct {
		Priority          string `json:"priority"`
		Description       string `json:"description"`
		UbuntuDescription string `json:"ubuntu_description"`
		Mitigation        string `json:"mitigation"`
		Notes             []struct {
			Author string `json:"author"`
			Note   string `json:"note"`
		} `json:"notes"`
		Packages []struct {
			Name     string `json:"name"`
			Statuses []struct {
				Release     string `json:"release_codename"`
				Status      string `json:"status"`
				Description string `json:"description"`
			} `json:"statuses"`
		} `json:"packages"`
	}
	if err := c.getJSON(ctx, ubuntuURL+cveID+".json", &raw); err != nil {
		return nil, err
	}
	r := &UbuntuReport{
		Priority: raw.Priority, Description: strings.TrimSpace(raw.Description),
		UbuntuDescription: strings.TrimSpace(raw.UbuntuDescription), Mitigation: strings.TrimSpace(raw.Mitigation),
		Notes: []UbuntuNote{}, Packages: []UbuntuPackage{}, URL: "https://ubuntu.com/security/" + cveID,
	}
	for _, n := range raw.Notes {
		if strings.TrimSpace(n.Note) != "" {
			r.Notes = append(r.Notes, UbuntuNote{Author: n.Author, Note: strings.TrimSpace(n.Note)})
		}
	}
	for _, p := range raw.Packages {
		pkg := UbuntuPackage{Name: p.Name, Statuses: []UbuntuStatus{}}
		for _, s := range p.Statuses {
			pkg.Statuses = append(pkg.Statuses, UbuntuStatus{Release: s.Release, Status: s.Status, Description: s.Description})
		}
		r.Packages = append(r.Packages, pkg)
	}
	return r, nil
}
