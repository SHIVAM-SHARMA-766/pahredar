package intel

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

const maxVendorPageSize = 100

func (s *Service) listVendors(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := intParam(r.URL.Query(), "page_size", 25)
	if err != nil || limit < 1 || limit > maxVendorPageSize {
		platform.WriteError(w, http.StatusBadRequest, fmt.Sprintf("page_size must be between 1 and %d", maxVendorPageSize))
		return
	}
	vendors, err := s.Store.ListVendors(r.Context(), q, limit)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if vendors == nil {
		vendors = []db.VendorSummary{}
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": vendors})
}

func (s *Service) listProducts(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := intParam(r.URL.Query(), "page_size", 25)
	if err != nil || limit < 1 || limit > maxVendorPageSize {
		platform.WriteError(w, http.StatusBadRequest, fmt.Sprintf("page_size must be between 1 and %d", maxVendorPageSize))
		return
	}
	products, err := s.Store.ListProducts(r.Context(), q, limit)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if products == nil {
		products = []db.ProductSummary{}
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": products})
}

func (s *Service) getVendor(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.GetVendor(r.Context(), cverecord.CanonicalVendor(r.PathValue("vendor")))
	if errors.Is(err, db.ErrNotFound) {
		platform.WriteError(w, http.StatusNotFound, "vendor not found")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if d.Years == nil {
		d.Years = []db.YearCount{}
	}
	if d.Products == nil {
		d.Products = []db.ProductSummary{}
	}
	platform.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) getProduct(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.GetProduct(r.Context(), cverecord.CanonicalVendor(r.PathValue("vendor")), cverecord.CanonicalProduct(r.PathValue("product")))
	if errors.Is(err, db.ErrNotFound) {
		platform.WriteError(w, http.StatusNotFound, "product not found")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if d.Years == nil {
		d.Years = []db.YearCount{}
	}
	platform.WriteJSON(w, http.StatusOK, d)
}
