package easm

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Manifest upload (S5 "Later"): instead of POSTing a pre-built component list,
// an operator uploads a raw manifest file (package-lock.json / package.json /
// go.mod) and the server parses it into the dependency inventory. Mirrors the
// loader script's parsing, server-side so the UI can do it directly.

const maxManifestBytes = 8 << 20 // 8 MiB — lockfiles can be large.

// ingestManifest parses an uploaded manifest and stores its dependencies.
func (s *Service) ingestManifest(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Kind    string `json:"kind"`    // package-lock | package-json | go-mod
		Content string `json:"content"` // the raw file text
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxManifestBytes)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	comps, err := parseManifest(body.Kind, body.Content)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(comps) == 0 {
		platform.WriteError(w, http.StatusUnprocessableEntity, "no dependencies found in the manifest")
		return
	}
	n := s.upsertDependencies(r.Context(), a, comps)
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ingested": n, "parsed": len(comps)})
}

// parseManifest dispatches on the manifest kind.
func parseManifest(kind, content string) ([]depInput, error) {
	switch kind {
	case "package-lock":
		return parsePackageLock([]byte(content))
	case "package-json":
		return parsePackageJSON([]byte(content))
	case "go-mod":
		return parseGoMod(content), nil
	default:
		return nil, errUnknownKind
	}
}

var errUnknownKind = &manifestError{"kind must be package-lock, package-json, or go-mod"}

type manifestError struct{ msg string }

func (e *manifestError) Error() string { return e.msg }

// --- npm: package-lock.json ---------------------------------------------------

type lockPkg struct {
	Version string `json:"version"`
	Link    bool   `json:"link"`
}

// parsePackageLock reads the resolved npm graph. Lockfile v2/v3 use the
// `packages` map (full transitive tree); v1 uses `dependencies`. Workspace-local
// packages (link:true) and versionless entries are skipped.
func parsePackageLock(data []byte) ([]depInput, error) {
	var lf struct {
		Packages     map[string]lockPkg `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, &manifestError{"not valid package-lock.json"}
	}
	seen := map[string]string{}
	for path, info := range lf.Packages {
		if !strings.HasPrefix(path, "node_modules/") || info.Link || info.Version == "" {
			continue // root/workspace package, a symlink, or no resolved version
		}
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		seen[name] = info.Version
	}
	// v1 fallback: the flat top-level dependencies map.
	if len(seen) == 0 {
		for name, info := range lf.Dependencies {
			if info.Version != "" {
				seen[name] = info.Version
			}
		}
	}
	return npmComps(seen), nil
}

// --- npm: package.json (direct deps only) ------------------------------------

var npmRangeRe = regexp.MustCompile(`^[\^~>=<\s]*v?(\d+\.\d+\.\d+)`)

// parsePackageJSON reads the direct dependencies + devDependencies, resolving a
// semver range to its base version.
func parsePackageJSON(data []byte) ([]depInput, error) {
	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, &manifestError{"not valid package.json"}
	}
	seen := map[string]string{}
	for _, sect := range []map[string]string{pj.Dependencies, pj.DevDependencies} {
		for name, raw := range sect {
			if v := cleanNpmVersion(raw); v != "" {
				seen[name] = v
			}
		}
	}
	return npmComps(seen), nil
}

// cleanNpmVersion resolves a package.json version range to a concrete version,
// or "" for non-registry refs (workspace:/link:/file:/*/latest/git).
func cleanNpmVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" || raw == "latest" ||
		strings.HasPrefix(raw, "workspace:") || strings.HasPrefix(raw, "link:") ||
		strings.HasPrefix(raw, "file:") || strings.Contains(raw, "://") {
		return ""
	}
	if m := npmRangeRe.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	return ""
}

// npmComps turns a name→version map into a sorted component list.
func npmComps(seen map[string]string) []depInput {
	out := make([]depInput, 0, len(seen))
	for name, ver := range seen {
		out = append(out, depInput{Ecosystem: "npm", Name: name, Version: ver})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- Go: go.mod ---------------------------------------------------------------

// goReqRe matches a require line, block form ("\tmodule/path v1.2.3") or
// single-line form ("require module/path v1.2.3"), direct or // indirect.
var goReqRe = regexp.MustCompile(`(?m)^\s*(?:require\s+)?([\w.~/-]+\.[\w.~/-]+)\s+v(\d+\.\d+\.\d+[\w.+-]*)`)

// parseGoMod reads every require (direct + indirect). The module's own path and
// replace targets without a version are naturally excluded (no version match).
func parseGoMod(content string) []depInput {
	seen := map[string]string{}
	for _, m := range goReqRe.FindAllStringSubmatch(content, -1) {
		name, ver := m[1], m[2]
		if name == "module" || name == "go" || name == "toolchain" {
			continue
		}
		seen[name] = ver // OSV wants the Go version without the "v" prefix
	}
	out := make([]depInput, 0, len(seen))
	for name, ver := range seen {
		out = append(out, depInput{Ecosystem: "Go", Name: name, Version: ver})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
