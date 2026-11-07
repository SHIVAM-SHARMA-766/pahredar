// Package news is the Security News service: feeds, the news stream,
// advisories, bookmarks, and trending CVEs. It reads CVE data from the
// intelligence service's tables (read-only) for trending badges.
package news

import (
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Service holds the news service over the shared platform.
type Service struct {
	*platform.Platform
}

// New builds the news service.
func New(p *platform.Platform) *Service { return &Service{Platform: p} }

func (s *Service) Name() string { return "news" }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/stats/trending", s.trending)
	mux.HandleFunc("GET /api/v1/feeds", s.feedList)
	mux.HandleFunc("GET /api/v1/feeds/advisories", s.latestAdvisories)
	mux.HandleFunc("GET /api/v1/news", s.news)
	mux.HandleFunc("PUT /api/v1/news/bookmark", platform.Guard(platform.RoleOperator, s.setBookmark))
	mux.HandleFunc("GET /api/v1/cves/{id}/articles", s.cveArticles)
}
