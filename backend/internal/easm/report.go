package easm

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Summary is a derived attack-surface report for an asset (spec R02–R08
// condensed): registration, counts, subdomains, IPs, certs, email posture. It
// is a view over asset_record, not stored.
type Summary struct {
	AssetID      int64           `json:"asset_id"`
	Registration json.RawMessage `json:"registration,omitempty"`
	Counts       map[string]int  `json:"counts"`
	Subdomains   []string        `json:"subdomains"`
	IPs          []ipSummary     `json:"ips"`
	Certs        certSummary     `json:"certs"`
	Email        emailSummary    `json:"email"`
	LastRun      *db.ScanRun     `json:"last_run,omitempty"`
}

type ipSummary struct {
	IP      string `json:"ip"`
	Org     string `json:"org,omitempty"`
	Network string `json:"network,omitempty"`
	Country string `json:"country,omitempty"`
}
type certSummary struct {
	Count           int    `json:"count"`
	SoonestNotAfter string `json:"soonest_not_after,omitempty"`
}
type emailSummary struct {
	SPF    *bool  `json:"spf,omitempty"`
	DMARC  *bool  `json:"dmarc,omitempty"`
	Policy string `json:"dmarc_policy,omitempty"`
}

// summary builds the report for an asset from its records.
func (s *Service) summary(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	records, err := s.Store.ListRecords(r.Context(), a.ID, "")
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	out := buildSummary(a.ID, records)
	if runs, err := s.Store.ListScanRuns(r.Context(), a.ID, 1); err == nil && len(runs) > 0 {
		out.LastRun = &runs[0]
	}
	platform.WriteJSON(w, http.StatusOK, out)
}

func buildSummary(assetID int64, records []db.AssetRecord) Summary {
	sum := Summary{AssetID: assetID, Counts: map[string]int{}, Subdomains: []string{}, IPs: []ipSummary{}}
	ipByKey := map[string]*ipSummary{}

	for _, rec := range records {
		sum.Counts[rec.Category]++
		switch rec.Category {
		case "whois":
			if rec.Key == "registration" {
				sum.Registration = rec.Data
			}
		case "subdomain":
			sum.Subdomains = append(sum.Subdomains, rec.Key)
		case "ip":
			ip := ipByKey[rec.Key]
			if ip == nil {
				ip = &ipSummary{IP: rec.Key}
				ipByKey[rec.Key] = ip
			}
			var d struct {
				Org, Network, Country string
			}
			if json.Unmarshal(rec.Data, &d) == nil {
				if d.Org != "" {
					ip.Org = d.Org
				}
				if d.Network != "" {
					ip.Network = d.Network
				}
				if d.Country != "" {
					ip.Country = d.Country
				}
			}
		case "cert":
			sum.Certs.Count++
			var d struct {
				NotAfter string `json:"not_after"`
			}
			if json.Unmarshal(rec.Data, &d) == nil && d.NotAfter != "" {
				if sum.Certs.SoonestNotAfter == "" || d.NotAfter < sum.Certs.SoonestNotAfter {
					sum.Certs.SoonestNotAfter = d.NotAfter
				}
			}
		case "email":
			var d struct {
				Present bool   `json:"present"`
				Policy  string `json:"policy"`
			}
			_ = json.Unmarshal(rec.Data, &d)
			p := d.Present
			if rec.Key == "spf" {
				sum.Email.SPF = &p
			} else if rec.Key == "dmarc" {
				sum.Email.DMARC = &p
				sum.Email.Policy = d.Policy
			}
		}
	}
	sort.Strings(sum.Subdomains)
	for _, ip := range ipByKey {
		sum.IPs = append(sum.IPs, *ip)
	}
	sort.Slice(sum.IPs, func(i, j int) bool { return sum.IPs[i].IP < sum.IPs[j].IP })
	return sum
}

// promote turns a discovered hostname into a tracked asset under the parent's
// client (an explicit operator decision — discovered assets are not auto-created).
func (s *Service) promote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ParentAssetID int64  `json:"parent_asset_id"`
		Value         string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.ParentAssetID == 0 || body.Value == "" {
		platform.WriteError(w, http.StatusBadRequest, `body must be {"parent_asset_id": <id>, "value": "sub.example.com"}`)
		return
	}
	parent, ok := s.accessibleAsset(w, r, body.ParentAssetID)
	if !ok {
		return
	}
	if parent.ClientID == nil {
		platform.WriteError(w, http.StatusBadRequest, "parent asset has no client to inherit")
		return
	}
	id, err := s.Store.CreateAsset(r.Context(), *parent.ClientID, "domain", body.Value, "discovered via EASM", nil)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("easm promoted asset", "value", body.Value, "client_id", *parent.ClientID)
	platform.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}
