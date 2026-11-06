package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/feeds"
)

// label fills in each article's feed name and kind from the feed list.
func label(articles []db.ArticleOut) []db.ArticleOut {
	if articles == nil {
		return []db.ArticleOut{}
	}
	for i := range articles {
		if f, ok := feeds.ByKey(articles[i].Feed); ok {
			articles[i].FeedName, articles[i].FeedKind = f.Name, f.Kind
		} else {
			articles[i].FeedName = articles[i].Feed
		}
	}
	return articles
}

func boundedInt(r *http.Request, name string, def, lo, hi int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return min(max(v, lo), hi)
}

// cveArticles lists feed articles mentioning a CVE. It works for IDs not yet
// in the CVE List, since vendor advisories often name a CVE first.
func (s *Server) cveArticles(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	out, err := s.Store.ArticlesForCVE(r.Context(), id, boundedInt(r, "limit", 50, 1, 200))
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": label(out)})
}

type trendingItem struct {
	db.Trending
	// CVE is nil when the ID is not in the CVE List yet.
	CVE *db.CVESummary `json:"cve"`
}

// trending ranks CVEs by how many distinct feeds mentioned them in the last
// `days` days (default 7), with each CVE's summary when it is published.
func (s *Server) trending(w http.ResponseWriter, r *http.Request) {
	days := boundedInt(r, "days", 7, 1, 90)
	rows, err := s.Store.TrendingCVEs(r.Context(), time.Now().AddDate(0, 0, -days), boundedInt(r, "limit", 10, 1, 50))
	if err != nil {
		internalError(w, r, err)
		return
	}
	ids := make([]string, len(rows))
	for i, t := range rows {
		ids[i] = t.CVEID
	}
	byID := map[string]db.CVESummary{}
	if len(ids) > 0 {
		summaries, _, err := s.Store.ListCVEs(r.Context(), db.ListCVEParams{IDs: ids, Sort: "published", Desc: true, Limit: len(ids)})
		if err != nil {
			internalError(w, r, err)
			return
		}
		for _, c := range summaries {
			byID[c.ID] = c
		}
	}
	out := make([]trendingItem, len(rows))
	for i, t := range rows {
		out[i] = trendingItem{Trending: t}
		if c, ok := byID[t.CVEID]; ok {
			out[i].CVE = &c
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days, "items": out})
}

// latestAdvisories lists the newest vendor PSIRT and government advisories
// that name CVEs.
func (s *Server) latestAdvisories(w http.ResponseWriter, r *http.Request) {
	var keys []string
	for _, f := range feeds.All {
		if f.Kind == feeds.KindVendor || f.Kind == feeds.KindGovernment {
			keys = append(keys, f.Key)
		}
	}
	out, err := s.Store.LatestArticles(r.Context(), keys, boundedInt(r, "limit", 12, 1, 100))
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": label(out)})
}

type feedInfo struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	URL  string `json:"url"`
	db.FeedStat
}

// feedList returns every configured feed with how many articles it has
// contributed.
func (s *Server) feedList(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Store.FeedStats(r.Context())
	if err != nil {
		internalError(w, r, err)
		return
	}
	byFeed := map[string]db.FeedStat{}
	for _, st := range stats {
		byFeed[st.Feed] = st
	}
	out := make([]feedInfo, len(feeds.All))
	for i, f := range feeds.All {
		st := byFeed[f.Key]
		st.Feed = f.Key
		out[i] = feedInfo{Key: f.Key, Name: f.Name, Kind: f.Kind, URL: f.URL, FeedStat: st}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// cveDetection lists the Sigma, Suricata, and Nmap rules naming a CVE. Scan
// commands built from exploit modules and affected packages are assembled
// by the frontend from data it already has.
func (s *Server) cveDetection(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	out, err := s.Store.DetectionForCVE(r.Context(), id, 500)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if out == nil {
		out = []db.DetectionOut{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

// cveAttack places a CVE in an attack: CTID's ATT&CK mappings (KEV CVEs)
// and the CAPEC attack patterns related to its CWEs.
func (s *Server) cveAttack(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	d, err := s.Store.GetCVE(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CVE not found")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	mappings, err := s.Store.AttackMappings(r.Context(), id)
	if err != nil {
		internalError(w, r, err)
		return
	}
	patterns, err := s.Store.CAPECForCWEs(r.Context(), d.CWEIDs, 8)
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mappings": orEmpty(mappings), "capec": orEmpty(patterns)})
}
