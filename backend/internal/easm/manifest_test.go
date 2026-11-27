package easm

import "testing"

func depMap(comps []depInput) map[string]depInput {
	m := map[string]depInput{}
	for _, c := range comps {
		m[c.Name] = c
	}
	return m
}

func TestParsePackageLockV3(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/@scope/pkg": {"version": "2.3.4"},
	    "node_modules/a/node_modules/nested": {"version": "0.1.0"},
	    "node_modules/@local/core": {"link": true, "resolved": "packages/core"},
	    "node_modules/noversion": {}
	  }
	}`)
	comps, err := parsePackageLock(data)
	if err != nil {
		t.Fatal(err)
	}
	m := depMap(comps)
	if m["lodash"].Version != "4.17.21" || m["lodash"].Ecosystem != "npm" {
		t.Errorf("lodash = %+v", m["lodash"])
	}
	if m["@scope/pkg"].Version != "2.3.4" {
		t.Errorf("scoped = %+v", m["@scope/pkg"])
	}
	if m["nested"].Version != "0.1.0" {
		t.Errorf("nested = %+v", m["nested"])
	}
	if _, ok := m["@local/core"]; ok {
		t.Error("workspace link package must be skipped")
	}
	if _, ok := m["noversion"]; ok {
		t.Error("versionless package must be skipped")
	}
	if _, ok := m["root"]; ok {
		t.Error("root package must be skipped")
	}
	if len(comps) != 3 {
		t.Errorf("want 3 comps, got %d (%+v)", len(comps), comps)
	}
}

func TestParsePackageLockV1(t *testing.T) {
	data := []byte(`{"lockfileVersion": 1, "dependencies": {"express": {"version": "4.18.2"}}}`)
	comps, err := parsePackageLock(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 || comps[0].Name != "express" || comps[0].Version != "4.18.2" {
		t.Errorf("v1 fallback = %+v", comps)
	}
}

func TestParsePackageJSON(t *testing.T) {
	data := []byte(`{
	  "dependencies": {"react": "^19.0.0", "left-pad": "1.3.0"},
	  "devDependencies": {"vite": "~5.2.1", "local": "workspace:*", "fromgit": "git+https://x/y.git", "any": "*"}
	}`)
	comps, err := parsePackageJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	m := depMap(comps)
	if m["react"].Version != "19.0.0" || m["left-pad"].Version != "1.3.0" || m["vite"].Version != "5.2.1" {
		t.Errorf("versions = %+v", m)
	}
	for _, skip := range []string{"local", "fromgit", "any"} {
		if _, ok := m[skip]; ok {
			t.Errorf("non-registry ref %q must be skipped", skip)
		}
	}
	if len(comps) != 3 {
		t.Errorf("want 3, got %d (%+v)", len(comps), comps)
	}
}

func TestParseGoMod(t *testing.T) {
	content := `module github.com/me/project

go 1.26

require (
	github.com/jackc/pgx/v5 v5.7.1
	golang.org/x/crypto v0.59.0 // indirect
)

require github.com/stretchr/testify v1.9.0
`
	comps := parseGoMod(content)
	m := depMap(comps)
	if m["github.com/jackc/pgx/v5"].Version != "5.7.1" || m["github.com/jackc/pgx/v5"].Ecosystem != "Go" {
		t.Errorf("pgx = %+v", m["github.com/jackc/pgx/v5"])
	}
	if m["golang.org/x/crypto"].Version != "0.59.0" { // indirect, v stripped
		t.Errorf("crypto = %+v", m["golang.org/x/crypto"])
	}
	if m["github.com/stretchr/testify"].Version != "1.9.0" { // single-line require
		t.Errorf("testify = %+v", m["github.com/stretchr/testify"])
	}
	if _, ok := m["module"]; ok {
		t.Error("module line must not be a dependency")
	}
	if len(comps) != 3 {
		t.Errorf("want 3, got %d (%+v)", len(comps), comps)
	}
}

func TestParseManifestUnknownKind(t *testing.T) {
	if _, err := parseManifest("requirements-txt", "x"); err == nil {
		t.Error("want error for unknown kind")
	}
}
