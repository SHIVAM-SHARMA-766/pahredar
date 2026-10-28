package db

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// RefreshStats recomputes the vendor/product materialized views. CONCURRENTLY
// keeps them readable during the ~15 s refresh.
func (s *Store) RefreshStats(ctx context.Context) error {
	for _, view := range []string{"product_stats", "vendor_stats", "vendor_year_stats"} {
		if _, err := s.pool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY "+view); err != nil {
			return err
		}
	}
	return nil
}

// SeverityCounts is shared by vendor and product summaries.
type SeverityCounts struct {
	CVEs            int        `json:"cves"`
	Critical        int        `json:"critical"`
	High            int        `json:"high"`
	Medium          int        `json:"medium"`
	Low             int        `json:"low"`
	KEV             int        `json:"kev"`
	LatestPublished *time.Time `json:"latest_published"`
}

// Vendor and Product are canonical keys (used in URLs and filters); Label is
// the display spelling.
type VendorSummary struct {
	Vendor   string `json:"vendor"`
	Label    string `json:"label"`
	Products int    `json:"products"`
	SeverityCounts
}

type ProductSummary struct {
	Vendor      string `json:"vendor"`
	VendorLabel string `json:"vendor_label"`
	Product     string `json:"product"`
	Label       string `json:"label"`
	SeverityCounts
}

type YearCount struct {
	Year int `json:"year"`
	CVEs int `json:"cves"`
}

// ListVendors returns vendors by CVE count, optionally filtered by a
// case-insensitive substring; an exact match sorts first.
func (s *Store) ListVendors(ctx context.Context, q string, limit int) ([]VendorSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT vendor, label, products, cves, critical, high, medium, low, kev, latest_published
		FROM vendor_stats
		WHERE $1 = '' OR vendor ILIKE '%' || $1 || '%'
		ORDER BY (vendor = lower($1)) DESC, cves DESC, vendor
		LIMIT $2`, q, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanVendor)
}

func scanVendor(row pgx.CollectableRow) (VendorSummary, error) {
	var v VendorSummary
	err := row.Scan(&v.Vendor, &v.Label, &v.Products, &v.CVEs, &v.Critical, &v.High, &v.Medium, &v.Low, &v.KEV, &v.LatestPublished)
	v.Label = PrettyLabel(v.Label)
	return v, err
}

func scanProduct(row pgx.CollectableRow) (ProductSummary, error) {
	var p ProductSummary
	err := row.Scan(&p.Vendor, &p.VendorLabel, &p.Product, &p.Label, &p.CVEs, &p.Critical, &p.High, &p.Medium, &p.Low, &p.KEV, &p.LatestPublished)
	p.VendorLabel, p.Label = PrettyLabel(p.VendorLabel), PrettyLabel(p.Label)
	return p, err
}

const productCols = `p.vendor, v.label, p.product, p.label, p.cves, p.critical, p.high, p.medium, p.low, p.kev, p.latest_published`

// ListProducts returns products across all vendors by CVE count, optionally
// filtered by a case-insensitive substring of the product name.
func (s *Store) ListProducts(ctx context.Context, q string, limit int) ([]ProductSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+productCols+`
		FROM product_stats p JOIN vendor_stats v USING (vendor)
		WHERE $1 = '' OR p.product ILIKE '%' || $1 || '%'
		ORDER BY (p.product = lower($1)) DESC, p.cves DESC, p.vendor, p.product
		LIMIT $2`, q, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanProduct)
}

type VendorDetail struct {
	VendorSummary
	Years    []YearCount      `json:"years"`
	Products []ProductSummary `json:"top_products"`
}

// maxVendorProducts bounds the product list on a vendor page.
const maxVendorProducts = 200

func (s *Store) GetVendor(ctx context.Context, vendor string) (*VendorDetail, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT vendor, label, products, cves, critical, high, medium, low, kev, latest_published
		FROM vendor_stats WHERE vendor = $1`, vendor)
	if err != nil {
		return nil, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, scanVendor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := &VendorDetail{VendorSummary: v}

	rows, err = s.pool.Query(ctx, `SELECT year, cves FROM vendor_year_stats WHERE vendor = $1 ORDER BY year`, vendor)
	if err != nil {
		return nil, err
	}
	if d.Years, err = pgx.CollectRows(rows, pgx.RowToStructByPos[YearCount]); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT `+productCols+`
		FROM product_stats p JOIN vendor_stats v USING (vendor)
		WHERE p.vendor = $1 ORDER BY p.cves DESC, p.product LIMIT $2`, vendor, maxVendorProducts)
	if err != nil {
		return nil, err
	}
	if d.Products, err = pgx.CollectRows(rows, scanProduct); err != nil {
		return nil, err
	}
	return d, nil
}

type ProductDetail struct {
	ProductSummary
	Years []YearCount `json:"years"`
}

func (s *Store) GetProduct(ctx context.Context, vendor, product string) (*ProductDetail, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+productCols+`
		FROM product_stats p JOIN vendor_stats v USING (vendor)
		WHERE p.vendor = $1 AND p.product = $2`, vendor, product)
	if err != nil {
		return nil, err
	}
	p, err := pgx.CollectExactlyOneRow(rows, scanProduct)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := &ProductDetail{ProductSummary: p}
	// Per-product years are computed live: a single product is small enough.
	rows, err = s.pool.Query(ctx, `
		SELECT extract(year FROM c.date_published)::int, count(*)::int
		FROM cve c
		WHERE c.state = 'PUBLISHED' AND c.date_published IS NOT NULL
		  AND EXISTS (SELECT 1 FROM cve_affected a WHERE a.cve_id = c.id AND a.vendor = $1 AND a.product = $2)
		GROUP BY 1 ORDER BY 1`, vendor, product)
	if err != nil {
		return nil, err
	}
	if d.Years, err = pgx.CollectRows(rows, pgx.RowToStructByPos[YearCount]); err != nil {
		return nil, err
	}
	return d, nil
}

// PrettyLabel title-cases a label that has no capital letters at all, which
// is what NVD CPE names look like ("debian", "windows server 2016"). Labels a
// CNA wrote with its own capitalisation ("IBM", "qEngine CMS") are kept.
func PrettyLabel(s string) string {
	if s != strings.ToLower(s) {
		return s
	}
	words := strings.Fields(s)
	for i, w := range words {
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		words[i] = string(r)
	}
	return strings.Join(words, " ")
}
