package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

const (
	relatedPerGroup   = 8
	relatedMaxURLs    = 6
	relatedWindowDays = 30
)

type relatedGroup struct {
	// Kind is "advisory" (cites the same vendor advisory or patch) or
	// "product" (same product, published within relatedWindowDays).
	Kind    string          `json:"kind"`
	Label   string          `json:"label"`
	URL     string          `json:"url,omitempty"`
	Vendor  string          `json:"vendor,omitempty"`
	Product string          `json:"product,omitempty"`
	Total   int             `json:"total"`
	Items   []db.CVESummary `json:"items"`
}

// relatedCVEs finds the CVEs that "came with" this one: those citing the
// same vendor advisory or patch (typically fixed in the same release), and
// those for the same product published around the same time.
func (s *Server) relatedCVEs(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	d, err := s.store.GetCVE(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CVE not found")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}

	var groups []relatedGroup
	seen := map[string]bool{id: true}
	addGroup := func(g relatedGroup, ids []string) error {
		var fresh []string
		for _, x := range ids {
			if !seen[x] {
				fresh = append(fresh, x)
			}
		}
		if len(fresh) == 0 {
			return nil
		}
		items, _, err := s.store.ListCVEs(r.Context(), db.ListCVEParams{IDs: fresh, Sort: "cvss", Desc: true, Limit: len(fresh)})
		if err != nil {
			return err
		}
		for _, it := range items {
			seen[it.ID] = true
		}
		g.Items = items
		groups = append(groups, g)
		return nil
	}

	urls := advisoryURLs(d.Refs)
	if len(urls) > relatedMaxURLs {
		urls = urls[:relatedMaxURLs]
	}
	for _, u := range urls {
		ids, total, err := s.store.CVEsCitingURL(r.Context(), u, id, relatedPerGroup)
		if err != nil {
			internalError(w, r, err)
			return
		}
		label := u
		if p, err := url.Parse(u); err == nil {
			label = strings.TrimPrefix(p.Hostname(), "www.") + p.EscapedPath()
		}
		if err := addGroup(relatedGroup{Kind: "advisory", Label: label, URL: u, Total: total}, ids); err != nil {
			internalError(w, r, err)
			return
		}
	}

	// The product: the CNA's first affected product, else NVD's.
	var target *db.AffectedOut
	for i := range d.Affected {
		a := &d.Affected[i]
		if a.Vendor == "" {
			continue
		}
		if target == nil || (target.Source == "nvd" && a.Source != "nvd") {
			target = a
		}
	}
	if target != nil && d.DatePublished != nil {
		ids, total, err := s.store.CVEsForProductNear(r.Context(), target.Vendor, target.Product, *d.DatePublished, relatedWindowDays, id, relatedPerGroup)
		if err != nil {
			internalError(w, r, err)
			return
		}
		label := db.PrettyLabel(target.ProductLabel)
		if err := addGroup(relatedGroup{Kind: "product", Label: label, Vendor: target.Vendor, Product: target.Product, Total: total}, ids); err != nil {
			internalError(w, r, err)
			return
		}
	}
	if groups == nil {
		groups = []relatedGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}
