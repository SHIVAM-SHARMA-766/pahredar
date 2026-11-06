package news

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/feeds"
)

// news lists feed articles for the news page. Parameters: kind (vendor,
// government, research, news), feed (one feed key), q (substring of title
// or summary), days (window; 0 = everything stored, default 7), cves=1
// (only articles naming a CVE), bookmarked=1, sort (top, newest), page,
// limit. Alongside the
// articles it returns a badge (severity, score, KEV, exploited) for each
// CVE they name.
func (s *Service) news(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := db.NewsParams{
		Query:       strings.TrimSpace(q.Get("q")),
		WithCVEOnly: q.Get("cves") == "1",
		Top:         q.Get("sort") == "top",
		Bookmarked:  q.Get("bookmarked") == "1",
		Limit:       platform.BoundedInt(r, "limit", 30, 1, 100),
	}
	if len(p.Query) > 200 {
		platform.WriteError(w, http.StatusBadRequest, "q is limited to 200 characters")
		return
	}
	p.Offset = (platform.BoundedInt(r, "page", 1, 1, 1000) - 1) * p.Limit
	if days := platform.BoundedInt(r, "days", 7, 0, 3650); days > 0 {
		p.Since = time.Now().AddDate(0, 0, -days)
	}
	kind, feed := q.Get("kind"), q.Get("feed")
	switch {
	case feed != "":
		if _, ok := feeds.ByKey(feed); !ok {
			platform.WriteError(w, http.StatusBadRequest, "unknown feed")
			return
		}
		p.Feeds = []string{feed}
	case kind != "":
		if !slices.Contains([]string{feeds.KindVendor, feeds.KindGovernment, feeds.KindResearch, feeds.KindNews}, kind) {
			platform.WriteError(w, http.StatusBadRequest, "kind must be one of vendor, government, research, news")
			return
		}
		p.Feeds = []string{}
		for _, f := range feeds.All {
			if f.Kind == kind {
				p.Feeds = append(p.Feeds, f.Key)
			}
		}
	}
	items, total, err := s.Store.NewsArticles(r.Context(), p)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	var ids []string
	for i := range items {
		if f, ok := feeds.ByKey(items[i].Feed); ok {
			items[i].FeedName, items[i].FeedKind = f.Name, f.Kind
		} else {
			items[i].FeedName = items[i].Feed
		}
		ids = append(ids, items[i].CVEIDs...)
	}
	badges := map[string]db.CVEBadge{}
	if len(ids) > 0 {
		if badges, err = s.Store.CVEBadges(r.Context(), ids); err != nil {
			platform.InternalError(w, r, err)
			return
		}
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "cves": badges})
}

// setBookmark bookmarks (or un-bookmarks) a feed article so it is kept past
// its retention and listed under bookmarked=1. Body: {"url": "…",
// "bookmarked": true}.
func (s *Service) setBookmark(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL        string `json:"url"`
		Bookmarked bool   `json:"bookmarked"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil || body.URL == "" {
		platform.WriteError(w, http.StatusBadRequest, `body must be {"url": "…", "bookmarked": true|false}`)
		return
	}
	found, err := s.Store.SetBookmark(r.Context(), body.URL, body.Bookmarked)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if !found {
		platform.WriteError(w, http.StatusNotFound, "no article with that URL")
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"url": body.URL, "bookmarked": body.Bookmarked})
}
