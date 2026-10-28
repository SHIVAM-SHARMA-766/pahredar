package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

const maxVendorPageSize = 100

func (s *Server) listVendors(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := intParam(r.URL.Query(), "page_size", 25)
	if err != nil || limit < 1 || limit > maxVendorPageSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("page_size must be between 1 and %d", maxVendorPageSize))
		return
	}
	vendors, err := s.store.ListVendors(r.Context(), q, limit)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if vendors == nil {
		vendors = []db.VendorSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": vendors})
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := intParam(r.URL.Query(), "page_size", 25)
	if err != nil || limit < 1 || limit > maxVendorPageSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("page_size must be between 1 and %d", maxVendorPageSize))
		return
	}
	products, err := s.store.ListProducts(r.Context(), q, limit)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if products == nil {
		products = []db.ProductSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": products})
}

func (s *Server) getVendor(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetVendor(r.Context(), cverecord.CanonicalVendor(r.PathValue("vendor")))
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "vendor not found")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	if d.Years == nil {
		d.Years = []db.YearCount{}
	}
	if d.Products == nil {
		d.Products = []db.ProductSummary{}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) getProduct(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetProduct(r.Context(), cverecord.CanonicalVendor(r.PathValue("vendor")), cverecord.CanonicalProduct(r.PathValue("product")))
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "product not found")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	if d.Years == nil {
		d.Years = []db.YearCount{}
	}
	writeJSON(w, http.StatusOK, d)
}
