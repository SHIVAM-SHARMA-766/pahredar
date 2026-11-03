// Package greenbone reads the Greenbone Community Feed's vulnerability tests
// (NVTs, NASL scripts run by OpenVAS / Greenbone Community Edition) and keeps
// each test's metadata: OID, name, family, how it checks (remote or
// authenticated), summary, solution, and the CVEs it detects. The scripts
// themselves are not kept (GPL-2.0; they only run inside a Greenbone
// scanner).
//
// The feed is published as a container image on Greenbone's registry; its
// largest layer is a tarball of var/lib/openvas/<feed version>/vt-data/nasl
// for several feed versions in order. The layer is streamed, never written
// to disk, and only the newest feed version is kept. (The same data is on
// an rsync server, but the backend image has no rsync and that server
// blocks concurrent syncs.)
package greenbone

import (
	"archive/tar"
	"compress/gzip"
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
	registry   = "https://registry.community.greenbone.net"
	repository = "community/vulnerability-tests"
	tokenURL   = registry + "/service/token?service=harbor-registry&scope=repository:" + repository + ":pull"
	// maxScript skips oversized files (a few include large data tables).
	maxScript = 1 << 20
)

// Test is one NVT and the CVEs it checks for.
type Test struct {
	OID          string
	Name         string
	Family       string
	Check        string // remote or authenticated
	QoDType      string
	SolutionType string
	Summary      string
	Solution     string
	CVSSVector   string
	Modified     string
	Path         string
	CVEIDs       []string
}

// Fetch streams the newest feed version's NASL scripts from the registry.
func Fetch(ctx context.Context, c *http.Client) ([]Test, error) {
	var tok struct {
		Token string `json:"token"`
	}
	if err := getJSON(ctx, c, tokenURL, nil, &tok); err != nil {
		return nil, fmt.Errorf("registry token: %w", err)
	}
	auth := http.Header{"Authorization": {"Bearer " + tok.Token}}
	accept := "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
	var index struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		Layers []layer `json:"layers"`
	}
	h := auth.Clone()
	h.Set("Accept", accept)
	if err := getJSON(ctx, c, registry+"/v2/"+repository+"/manifests/latest", h, &index); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	layers := index.Layers
	if len(index.Manifests) > 0 {
		// The data is the same for every architecture; take the first.
		var m struct {
			Layers []layer `json:"layers"`
		}
		if err := getJSON(ctx, c, registry+"/v2/"+repository+"/manifests/"+index.Manifests[0].Digest, h, &m); err != nil {
			return nil, fmt.Errorf("image manifest: %w", err)
		}
		layers = m.Layers
	}
	if len(layers) == 0 {
		return nil, errors.New("feed image has no layers")
	}
	largest := layers[0]
	for _, l := range layers {
		if l.Size > largest.Size {
			largest = l
		}
	}
	resp, err := fetch.Get(ctx, c, registry+"/v2/"+repository+"/blobs/"+largest.Digest, auth)
	if err != nil {
		return nil, fmt.Errorf("feed layer: %w", err)
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseLayer(gz)
}

type layer struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func getJSON(ctx context.Context, c *http.Client, url string, h http.Header, v any) error {
	resp, err := fetch.Get(ctx, c, url, h)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// naslPath matches var/lib/openvas/<version>/vt-data/nasl/<path>.nasl.
var naslPath = regexp.MustCompile(`^var/lib/openvas/([0-9.]+)/vt-data/nasl/(.+\.nasl)$`)

// ParseLayer reads the feed tarball. Feed versions come one after another;
// when a newer one starts, what was read from the older one is dropped, so
// memory holds one version at a time.
func ParseLayer(r io.Reader) ([]Test, error) {
	tr := tar.NewReader(r)
	version := ""
	var out []Test
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		m := naslPath.FindStringSubmatch(strings.TrimPrefix(h.Name, "./"))
		if m == nil || h.Typeflag != tar.TypeReg || h.Size > maxScript {
			continue
		}
		if m[1] != version {
			if version != "" && !newerVersion(m[1], version) {
				continue // an older version after a newer one: ignore it
			}
			version, out = m[1], nil
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if t, ok := Parse(m[2], string(body)); ok {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no vulnerability tests naming a CVE found; the feed layout may have changed")
	}
	return out, nil
}

// newerVersion compares dotted feed versions ("25.0" > "24.10").
func newerVersion(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			fmt.Sscan(pa[i], &x)
		}
		if i < len(pb) {
			fmt.Sscan(pb[i], &y)
		}
		if x != y {
			return x > y
		}
	}
	return false
}

var (
	reOID    = regexp.MustCompile(`script_oid\("([0-9.]+)"\)`)
	reName   = regexp.MustCompile(`script_name\("([^"]*)"\)`)
	reFamily = regexp.MustCompile(`script_family\("([^"]*)"\)`)
	reCVE    = regexp.MustCompile(`script_cve_id\(([^)]*)\)`)
	reCVEID  = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	reTag    = regexp.MustCompile(`script_tag\(\s*name\s*:\s*"(\w+)"\s*,\s*value\s*:\s*("([^"]*)"|\w+)\s*\)`)
	spaces   = regexp.MustCompile(`\s+`)
)

// authenticatedQoD are the quality-of-detection types that read the target
// from the inside (package lists, registry, file versions): they need
// credentials. The rest probe the service over the network.
var authenticatedQoD = map[string]bool{
	"package": true, "package_unreliable": true, "registry": true,
	"executable_version": true, "executable_version_unreliable": true,
	"executable_version_unreliable_gl": true, "general_note": false,
}

// Parse reads one NASL script's description block. Deprecated tests and
// tests naming no CVE are skipped.
func Parse(path, s string) (Test, bool) {
	oid := reOID.FindStringSubmatch(s)
	if oid == nil {
		return Test{}, false
	}
	var cves []string
	seen := map[string]bool{}
	for _, m := range reCVE.FindAllStringSubmatch(s, -1) {
		for _, id := range reCVEID.FindAllString(m[1], -1) {
			if !seen[id] {
				seen[id] = true
				cves = append(cves, id)
			}
		}
	}
	if len(cves) == 0 {
		return Test{}, false
	}
	tags := map[string]string{}
	for _, m := range reTag.FindAllStringSubmatch(s, -1) {
		v := m[3]
		if !strings.HasPrefix(m[2], `"`) {
			v = m[2] // a bare value such as TRUE
		}
		if _, ok := tags[m[1]]; !ok {
			tags[m[1]] = v
		}
	}
	if strings.EqualFold(tags["deprecated"], "TRUE") {
		return Test{}, false
	}
	t := Test{
		OID: oid[1], Path: path, CVEIDs: cves,
		QoDType: tags["qod_type"], SolutionType: tags["solution_type"], CVSSVector: tags["cvss_base_vector"],
		Summary: clip(tags["summary"], 600), Solution: clip(tags["solution"], 600), Modified: firstField(tags["last_modification"]),
	}
	if m := reName.FindStringSubmatch(s); m != nil {
		t.Name = strings.TrimSpace(m[1])
	}
	if m := reFamily.FindStringSubmatch(s); m != nil {
		t.Family = m[1]
	}
	t.Check = "remote"
	if authenticatedQoD[t.QoDType] || strings.Contains(t.Family, "Local Security Checks") || strings.HasPrefix(t.Family, "Windows : Microsoft Bulletins") {
		t.Check = "authenticated"
	}
	return t, true
}

func clip(s string, n int) string {
	s = strings.TrimSpace(spaces.ReplaceAllString(s, " "))
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// firstField keeps the date of "2026-10-30 05:05:34 +0000 (Fri, 30 Oct 2026)".
func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}
