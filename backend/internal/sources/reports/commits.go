package reports

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

const (
	githubAPI = "https://api.github.com/repos/"
	// maxCommits bounds the commits fetched per CVE, maxFiles the files
	// kept per commit, and maxPatch each file's diff.
	maxCommits = 5
	maxFiles   = 40
	maxPatch   = 12 << 10
)

// commitPattern matches github.com/{owner}/{repo}/commit/{sha}, also inside
// pull-request URLs (/pull/{n}/commits/{sha}).
var commitPattern = regexp.MustCompile(`^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/(?:commit|pull/\d+/commits)/([0-9a-fA-F]{7,40})\b`)

// CommitURLs returns the distinct GitHub commit URLs among urls, in order.
func CommitURLs(urls []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range urls {
		m := commitPattern.FindStringSubmatch(u)
		if m == nil {
			continue
		}
		key := strings.ToLower(m[1] + "/" + m[2] + "@" + m[3])
		if !seen[key] {
			seen[key] = true
			out = append(out, u)
		}
	}
	return out
}

type Commit struct {
	Repo      string       `json:"repo"`
	SHA       string       `json:"sha"`
	URL       string       `json:"url"`
	Message   string       `json:"message"`
	Author    string       `json:"author,omitempty"`
	Date      string       `json:"date,omitempty"`
	Additions int          `json:"additions"`
	Deletions int          `json:"deletions"`
	Files     []CommitFile `json:"files"`
	// MoreFiles counts files left out beyond maxFiles.
	MoreFiles int `json:"more_files,omitempty"`
}

type CommitFile struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Patch     string `json:"patch,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type commitResponse struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	Stats struct {
		Additions int `json:"additions"`
		Deletions int `json:"deletions"`
	} `json:"stats"`
	Files []struct {
		Filename  string `json:"filename"`
		Status    string `json:"status"`
		Additions int    `json:"additions"`
		Deletions int    `json:"deletions"`
		Patch     string `json:"patch"`
	} `json:"files"`
}

// commits fetches each referenced GitHub commit. A commit that is gone
// (deleted repo, rewritten history) is skipped; the source is "not found"
// only if none could be read.
func (c *Client) commits(ctx context.Context, urls []string) ([]Commit, error) {
	if len(urls) == 0 {
		return nil, ErrNotFound
	}
	if len(urls) > maxCommits {
		urls = urls[:maxCommits]
	}
	var out []Commit
	var lastErr error
	for _, u := range urls {
		m := commitPattern.FindStringSubmatch(u)
		if m == nil {
			continue
		}
		var r commitResponse
		err := c.getGitHub(ctx, githubAPI+m[1]+"/"+m[2]+"/commits/"+m[3], &r)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}
		cm := Commit{
			Repo: m[1] + "/" + m[2], SHA: r.SHA, URL: r.HTMLURL, Message: clip(r.Commit.Message, 4000),
			Author: r.Commit.Author.Name, Date: r.Commit.Author.Date,
			Additions: r.Stats.Additions, Deletions: r.Stats.Deletions, Files: []CommitFile{},
		}
		for i, f := range r.Files {
			if i >= maxFiles {
				cm.MoreFiles = len(r.Files) - maxFiles
				break
			}
			cf := CommitFile{Name: f.Filename, Status: f.Status, Additions: f.Additions, Deletions: f.Deletions, Patch: f.Patch}
			if len(cf.Patch) > maxPatch {
				cf.Patch, cf.Truncated = cf.Patch[:maxPatch], true
			}
			cm.Files = append(cm.Files, cf)
		}
		out = append(out, cm)
	}
	if len(out) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrNotFound
	}
	return out, nil
}

func (c *Client) getGitHub(ctx context.Context, url string, v any) error {
	if c.githubToken == "" {
		return c.getJSON(ctx, url, v)
	}
	return c.getJSONWithHeader(ctx, url, http.Header{"Authorization": {"Bearer " + c.githubToken}}, v)
}
