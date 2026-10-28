package syncer

import (
	"encoding/json"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// buildRow derives a complete cve row from whichever raw records exist.
// rec or nvd may be nil, but not both.
func buildRow(rec *cverecord.Record, nvd *cverecord.NVD) (db.CVERow, error) {
	d := cverecord.Derive(rec, nvd)
	refs, err := json.Marshal(d.References)
	if err != nil {
		return db.CVERow{}, err
	}
	row := db.CVERow{
		CWEIDs:         d.CWEs,
		Title:          strPtr(d.Title),
		Description:    strPtr(d.Description),
		Severity:       d.Severity,
		SeveritySource: strPtr(d.SeveritySource),
		Refs:           refs,
		ExploitRef:     d.ExploitRef,
		SearchText:     d.SearchText,
	}
	if rec != nil {
		m := rec.Metadata
		row.ID = m.ID
		row.State = m.State
		row.Assigner = strPtr(m.AssignerShortName)
		row.DateReserved = m.DateReserved.Ptr()
		row.DatePublished = m.DatePublished.Ptr()
		row.DateUpdated = m.DateUpdated.Ptr()
		row.RawCvelist = rec.Raw
	}
	if nvd != nil {
		row.RawNVD = nvd.Raw
		row.NVDStatus = strPtr(nvd.VulnStatus)
		row.NVDLastModified = nvd.LastModified.Ptr()
		if rec == nil {
			row.ID = nvd.ID
			row.State = "PUBLISHED"
			if nvd.VulnStatus == "Rejected" {
				row.State = "REJECTED"
			}
			row.DatePublished = nvd.Published.Ptr()
			row.DateUpdated = nvd.LastModified.Ptr()
		}
	}
	row.CVSSv4Score, row.CVSSv4Vector = metricCols(d.V4)
	row.CVSSv3Score, row.CVSSv3Vector = metricCols(d.V3)
	row.CVSSv2Score, row.CVSSv2Vector = metricCols(d.V2)
	for _, a := range d.Affected {
		row.Affected = append(row.Affected, db.AffectedRow{
			Source: a.Source, Vendor: a.Vendor, Product: a.Product, VendorLabel: a.VendorLabel, ProductLabel: a.ProductLabel,
			CPEs: a.CPEs, Versions: a.Versions,
		})
	}
	return row, nil
}

func metricCols(m *cverecord.Metric) (*float64, *string) {
	if m == nil {
		return nil, nil
	}
	score := m.Score
	return &score, strPtr(m.Vector)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
