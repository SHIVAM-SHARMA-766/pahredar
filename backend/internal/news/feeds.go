package news

import (
	"net/http"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
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

// cveArticles lists feed articles mentioning a CVE. It works for IDs not yet
// in the CVE List, since vendor advisories often name a CVE first.
func (s *Service) cveArticles(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		platform.WriteError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	out, err := s.Store.ArticlesForCVE(r.Context(), id, platform.BoundedInt(r, "limit", 50, 1, 200))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": label(out)})
}

type trendingItem struct {
	db.Trending
	// CVE is nil when the ID is not in the CVE List yet.
	CVE *db.CVESummary `json:"cve"`
}

// trending ranks CVEs by how many distinct feeds mentioned them in the last
// `days` days (default 7), with each CVE's summary when it is published.
func (s *Service) trending(w http.ResponseWriter, r *http.Request) {
	days := platform.BoundedInt(r, "days", 7, 1, 90)
	rows, err := s.Store.TrendingCVEs(r.Context(), time.Now().AddDate(0, 0, -days), platform.BoundedInt(r, "limit", 10, 1, 50))
	if err != nil {
		platform.InternalError(w, r, err)
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
			platform.InternalError(w, r, err)
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
	platform.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "items": out})
}

// latestAdvisories lists the newest vendor PSIRT and government advisories
// that name CVEs.
func (s *Service) latestAdvisories(w http.ResponseWriter, r *http.Request) {
	var keys []string
	for _, f := range feeds.All {
		if f.Kind == feeds.KindVendor || f.Kind == feeds.KindGovernment {
			keys = append(keys, f.Key)
		}
	}
	out, err := s.Store.LatestArticles(r.Context(), keys, platform.BoundedInt(r, "limit", 12, 1, 100))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": label(out)})
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
func (s *Service) feedList(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Store.FeedStats(r.Context())
	if err != nil {
		platform.InternalError(w, r, err)
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
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
