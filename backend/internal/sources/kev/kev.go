// Package kev downloads the CISA Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

const feedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type Catalog struct {
	Version         string  `json:"catalogVersion"`
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

type Entry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	ForensicTriage             string `json:"forensicTriage"`
	Notes                      string `json:"notes"`
}

// ParseDate parses a catalog date (YYYY-MM-DD); empty yields nil.
func ParseDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func Fetch(ctx context.Context, c *http.Client) (Catalog, error) {
	resp, err := fetch.Get(ctx, c, feedURL, nil)
	if err != nil {
		return Catalog{}, err
	}
	defer resp.Body.Close()
	var cat Catalog
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		return Catalog{}, fmt.Errorf("decode KEV catalog: %w", err)
	}
	for i := range cat.Vulnerabilities {
		cat.Vulnerabilities[i].CVEID = strings.ToUpper(strings.TrimSpace(cat.Vulnerabilities[i].CVEID))
	}
	return cat, nil
}
