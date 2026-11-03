package reports

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
)

// Threat intelligence and social sources: AlienVault OTX pulses, abuse.ch
// ThreatFox IOCs, and Bluesky posts need a free signup key and return
// ErrNotConfigured without one; Mastodon hashtag timelines are public.

const (
	otxURL       = "https://otx.alienvault.com/api/v1/indicators/cve/"
	threatFoxURL = "https://threatfox-api.abuse.ch/api/v1/"
	blueskyPDS   = "https://bsky.social/xrpc/"

	// focusedMaxCVEs: an OTX pulse naming more CVEs than this is a bulk
	// list (daily KEV digests, scanner feeds); its adversaries and malware
	// are not attributed to the CVE.
	focusedMaxCVEs = 10
	maxPulses      = 25
	maxIOCs        = 500
	maxPosts       = 25
	// blueskySession is how long an access token is reused (they last ~2h).
	blueskySession = 90 * time.Minute
)

// ErrNotConfigured means the source needs a key that is not set.
var ErrNotConfigured = errors.New("source not configured")

// --- AlienVault OTX ----------------------------------------------------------

type OTXReport struct {
	// PulseCount is OTX's total; Pulses holds the focused ones, newest first.
	PulseCount  int         `json:"pulse_count"`
	BulkPulses  int         `json:"bulk_pulses"`
	Pulses      []OTXPulse  `json:"pulses"`
	Adversaries []string    `json:"adversaries"`
	Malware     []string    `json:"malware"`
	Industries  []string    `json:"industries"`
	Countries   []string    `json:"countries"`
	Techniques  []Technique `json:"techniques"`
	URL         string      `json:"url"`
}

type OTXPulse struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Created    string   `json:"created"`
	Modified   string   `json:"modified"`
	Author     string   `json:"author"`
	Adversary  string   `json:"adversary,omitempty"`
	Malware    []string `json:"malware"`
	Industries []string `json:"industries"`
	Countries  []string `json:"countries"`
	Techniques []string `json:"techniques"`
	Tags       []string `json:"tags"`
	Indicators int      `json:"indicators"`
	References []string `json:"references"`
}

type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) otx(ctx context.Context, cveID string) (*OTXReport, error) {
	if c.keys.OTX == "" {
		return nil, ErrNotConfigured
	}
	var raw struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				ID       string   `json:"id"`
				Name     string   `json:"name"`
				Created  string   `json:"created"`
				Modified string   `json:"modified"`
				Tags     []string `json:"tags"`
				Author   struct {
					Username string `json:"username"`
				} `json:"author"`
				Adversary string `json:"adversary"`
				Malware   []struct {
					DisplayName string `json:"display_name"`
				} `json:"malware_families"`
				Industries []string `json:"industries"`
				Countries  []string `json:"targeted_countries"`
				AttackIDs  []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"attack_ids"`
				IndicatorCount int            `json:"indicator_count"`
				TypeCounts     map[string]int `json:"indicator_type_counts"`
				References     []string       `json:"references"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := c.getJSONWithHeader(ctx, otxURL+cveID+"/general", http.Header{"X-OTX-API-KEY": {c.keys.OTX}}, &raw); err != nil {
		return nil, err
	}
	if raw.PulseInfo.Count == 0 {
		return nil, ErrNotFound
	}
	r := &OTXReport{PulseCount: raw.PulseInfo.Count, Pulses: []OTXPulse{}, URL: "https://otx.alienvault.com/indicator/cve/" + cveID}
	adv, mal, ind, cty := newSet(), newSet(), newSet(), newSet()
	tech := map[string]Technique{}
	for _, p := range raw.PulseInfo.Pulses {
		if p.TypeCounts["CVE"] > focusedMaxCVEs {
			r.BulkPulses++
			continue
		}
		out := OTXPulse{
			ID: p.ID, Name: strings.TrimSpace(p.Name), URL: "https://otx.alienvault.com/pulse/" + p.ID,
			Created: p.Created, Modified: p.Modified, Author: p.Author.Username, Adversary: strings.TrimSpace(p.Adversary),
			Malware: []string{}, Industries: orNone(p.Industries), Countries: orNone(p.Countries), Techniques: []string{},
			Tags: orNone(p.Tags), Indicators: p.IndicatorCount, References: orNone(p.References),
		}
		// Some pulses list several actors in one comma-separated field.
		adv.add(strings.Split(out.Adversary, ",")...)
		for _, m := range p.Malware {
			out.Malware = append(out.Malware, m.DisplayName)
			mal.add(m.DisplayName)
		}
		for _, a := range p.AttackIDs {
			out.Techniques = append(out.Techniques, a.ID)
			tech[a.ID] = Technique{ID: a.ID, Name: a.Name}
		}
		ind.add(p.Industries...)
		cty.add(p.Countries...)
		r.Pulses = append(r.Pulses, out)
	}
	slices.SortStableFunc(r.Pulses, func(a, b OTXPulse) int { return cmp.Compare(b.Modified, a.Modified) })
	// Cloned pulses repeat a report under the same name; keep the newest.
	names := newSet()
	r.Pulses = slices.DeleteFunc(r.Pulses, func(p OTXPulse) bool {
		n := len(names.list)
		names.add(p.Name)
		return len(names.list) == n
	})
	if len(r.Pulses) > maxPulses {
		r.Pulses = r.Pulses[:maxPulses]
	}
	r.Adversaries, r.Malware, r.Industries, r.Countries = adv.list, mal.list, ind.list, cty.list
	r.Techniques = []Technique{}
	for _, t := range tech {
		r.Techniques = append(r.Techniques, t)
	}
	slices.SortFunc(r.Techniques, func(a, b Technique) int { return cmp.Compare(a.ID, b.ID) })
	return r, nil
}

// set keeps first-seen order and drops blanks and case-insensitive repeats.
type set struct {
	seen map[string]bool
	list []string
}

func newSet() *set { return &set{seen: map[string]bool{}, list: []string{}} }

func (s *set) add(vals ...string) {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if k := strings.ToLower(v); v != "" && !s.seen[k] {
			s.seen[k] = true
			s.list = append(s.list, v)
		}
	}
}

func orNone(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// --- abuse.ch ThreatFox ------------------------------------------------------

type ThreatFoxReport struct {
	IOCs    []ThreatFoxIOC     `json:"iocs"`
	Malware []ThreatFoxMalware `json:"malware"`
	URL     string             `json:"url"`
}

type ThreatFoxIOC struct {
	IOC        string   `json:"ioc"`
	Type       string   `json:"type"`
	ThreatType string   `json:"threat_type"`
	Malware    string   `json:"malware"`
	Confidence int      `json:"confidence"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen,omitempty"`
	Reporter   string   `json:"reporter,omitempty"`
	Reference  string   `json:"reference,omitempty"`
	Tags       []string `json:"tags"`
	URL        string   `json:"url"`
}

type ThreatFoxMalware struct {
	Name     string `json:"name"`
	Malpedia string `json:"malpedia,omitempty"`
	IOCs     int    `json:"iocs"`
}

// threatFox lists IOCs whose reporters tagged them with the CVE ID. Tags
// are free-form, so coverage is mostly recent, widely exploited CVEs.
func (c *Client) threatFox(ctx context.Context, cveID string) (*ThreatFoxReport, error) {
	if c.keys.AbuseCH == "" {
		return nil, ErrNotConfigured
	}
	body, _ := json.Marshal(map[string]any{"query": "taginfo", "tag": cveID, "limit": maxIOCs})
	var raw struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := c.postJSON(ctx, threatFoxURL, http.Header{"Auth-Key": {c.keys.AbuseCH}}, body, &raw); err != nil {
		return nil, err
	}
	switch raw.Status {
	case "ok":
	case "no_result":
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("threatfox: %s", raw.Status)
	}
	var items []struct {
		ID         string   `json:"id"`
		IOC        string   `json:"ioc"`
		ThreatType string   `json:"threat_type"`
		IOCType    string   `json:"ioc_type"`
		Malware    string   `json:"malware_printable"`
		Malpedia   string   `json:"malware_malpedia"`
		Confidence int      `json:"confidence_level"`
		FirstSeen  string   `json:"first_seen"`
		LastSeen   *string  `json:"last_seen"`
		Reporter   string   `json:"reporter"`
		Reference  *string  `json:"reference"`
		Tags       []string `json:"tags"`
	}
	if err := json.Unmarshal(raw.Data, &items); err != nil {
		return nil, fmt.Errorf("threatfox: %w", err)
	}
	r := &ThreatFoxReport{IOCs: []ThreatFoxIOC{}, Malware: []ThreatFoxMalware{}, URL: "https://threatfox.abuse.ch/browse/tag/" + cveID + "/"}
	byName := map[string]int{}
	for _, it := range items {
		ioc := ThreatFoxIOC{
			IOC: it.IOC, Type: it.IOCType, ThreatType: it.ThreatType, Malware: it.Malware, Confidence: it.Confidence,
			FirstSeen: it.FirstSeen, Reporter: it.Reporter, Tags: orNone(it.Tags), URL: "https://threatfox.abuse.ch/ioc/" + it.ID + "/",
		}
		if it.LastSeen != nil {
			ioc.LastSeen = *it.LastSeen
		}
		if it.Reference != nil {
			ioc.Reference = *it.Reference
		}
		r.IOCs = append(r.IOCs, ioc)
		if it.Malware == "" {
			continue
		}
		i, ok := byName[it.Malware]
		if !ok {
			i = len(r.Malware)
			byName[it.Malware] = i
			r.Malware = append(r.Malware, ThreatFoxMalware{Name: it.Malware, Malpedia: it.Malpedia})
		}
		r.Malware[i].IOCs++
	}
	if len(r.IOCs) == 0 {
		return nil, ErrNotFound
	}
	slices.SortStableFunc(r.Malware, func(a, b ThreatFoxMalware) int { return cmp.Compare(b.IOCs, a.IOCs) })
	return r, nil
}

// --- Bluesky ----------------------------------------------------------------

// blueskyAuth holds the app-password session shared by all requests.
type blueskyAuth struct {
	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

func (c *Client) blueskyToken(ctx context.Context, renew bool) (string, error) {
	a := &c.bsky
	a.mu.Lock()
	defer a.mu.Unlock()
	if !renew && a.token != "" && time.Since(a.issuedAt) < blueskySession {
		return a.token, nil
	}
	body, _ := json.Marshal(map[string]string{"identifier": c.keys.BlueskyHandle, "password": c.keys.BlueskyPassword})
	var s struct {
		AccessJwt string `json:"accessJwt"`
	}
	if err := c.postJSON(ctx, blueskyPDS+"com.atproto.server.createSession", nil, body, &s); err != nil {
		return "", fmt.Errorf("bluesky login: %w", err)
	}
	a.token, a.issuedAt = s.AccessJwt, time.Now()
	return a.token, nil
}

// bluesky searches posts mentioning the CVE ID, most engaged first. Search
// needs a logged-in session; an app password is enough.
func (c *Client) bluesky(ctx context.Context, cveID string) ([]NewsItem, error) {
	if c.keys.BlueskyHandle == "" || c.keys.BlueskyPassword == "" {
		return nil, ErrNotConfigured
	}
	q := url.Values{"q": {cveID}, "sort": {"top"}, "limit": {fmt.Sprint(maxPosts)}}
	var res struct {
		Posts []struct {
			URI    string `json:"uri"`
			Author struct {
				Handle      string `json:"handle"`
				DisplayName string `json:"displayName"`
			} `json:"author"`
			Record struct {
				Text      string `json:"text"`
				CreatedAt string `json:"createdAt"`
				Embed     struct {
					External struct {
						URI   string `json:"uri"`
						Title string `json:"title"`
					} `json:"external"`
				} `json:"embed"`
			} `json:"record"`
			LikeCount   int `json:"likeCount"`
			RepostCount int `json:"repostCount"`
			ReplyCount  int `json:"replyCount"`
		} `json:"posts"`
	}
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var token string
		if token, err = c.blueskyToken(ctx, attempt > 0); err != nil {
			return nil, err
		}
		err = c.getJSONWithHeader(ctx, blueskyPDS+"app.bsky.feed.searchPosts?"+q.Encode(), http.Header{"Authorization": {"Bearer " + token}}, &res)
		var se *fetch.StatusError
		// An expired session is a 400 ExpiredToken (or a 401); log in again once.
		if !errors.As(err, &se) || !(se.Code == http.StatusUnauthorized || strings.Contains(se.Body, "ExpiredToken")) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	var out []NewsItem
	for _, p := range res.Posts {
		text := p.Record.Text + " " + p.Record.Embed.External.URI + " " + p.Record.Embed.External.Title
		if !strings.Contains(strings.ToUpper(text), cveID) {
			continue
		}
		rkey := p.URI[strings.LastIndex(p.URI, "/")+1:]
		post := "https://bsky.app/profile/" + p.Author.Handle + "/post/" + rkey
		title := clean(p.Record.Text)
		if r := []rune(title); len(r) > 300 {
			title = string(r[:300]) + "…"
		}
		out = append(out, NewsItem{
			Title: title, URL: post, Source: "@" + p.Author.Handle, Published: p.Record.CreatedAt,
			DiscussionURL: post, Points: p.LikeCount + p.RepostCount, Comments: p.ReplyCount,
		})
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	slices.SortStableFunc(out, func(a, b NewsItem) int { return cmp.Compare(b.Points, a.Points) })
	return out, nil
}

// postJSON POSTs a JSON body and decodes the JSON reply.
func (c *Client) postJSON(ctx context.Context, u string, extra http.Header, body []byte, v any) error {
	h := http.Header{"Accept": {"application/json"}, "Content-Type": {"application/json"}}
	for k, vals := range extra {
		h[k] = vals
	}
	resp, err := fetch.Do(ctx, c.http, http.MethodPost, u, h, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// --- Mastodon ----------------------------------------------------------------

// mastodonInstances are large general servers whose public hashtag
// timelines include posts federated from the rest of the fediverse.
// infosec.exchange and ioc.exchange require a login for this.
var mastodonInstances = []string{"https://mastodon.social", "https://fosstodon.org"}

// mastodon reads the public hashtag timelines for the CVE ID, in both tag
// spellings people use (#CVE202346604 and #CVE_2023_46604), merged and
// most engaged first.
func (c *Client) mastodon(ctx context.Context, cveID string) ([]NewsItem, error) {
	compact := strings.ReplaceAll(cveID, "-", "")
	tags := []string{compact, strings.ReplaceAll(cveID, "-", "_")}
	type status struct {
		URI       string `json:"uri"`
		URL       string `json:"url"`
		CreatedAt string `json:"created_at"`
		Content   string `json:"content"`
		Replies   int    `json:"replies_count"`
		Reblogs   int    `json:"reblogs_count"`
		Favs      int    `json:"favourites_count"`
		Account   struct {
			Acct string `json:"acct"`
			URL  string `json:"url"`
		} `json:"account"`
	}
	seen := map[string]bool{}
	var out []NewsItem
	var lastErr error
	ok := 0
	for _, inst := range mastodonInstances {
		for _, tag := range tags {
			var list []status
			if err := c.getJSON(ctx, inst+"/api/v1/timelines/tag/"+url.PathEscape(tag)+"?limit=40", &list); err != nil {
				lastErr = err
				continue
			}
			ok++
			for _, st := range list {
				if st.URI == "" || seen[st.URI] {
					continue
				}
				seen[st.URI] = true
				link := st.URL
				if link == "" {
					link = st.URI
				}
				acct := st.Account.Acct
				// Local accounts have no domain in acct.
				if !strings.Contains(acct, "@") {
					if u, err := url.Parse(st.Account.URL); err == nil && u.Host != "" {
						acct += "@" + u.Host
					}
				}
				title := htmlText(st.Content)
				if r := []rune(title); len(r) > 300 {
					title = string(r[:300]) + "…"
				}
				// The same account posting the same text twice (as shown) is
				// one post.
				if k := acct + "\x00" + title; seen[k] {
					continue
				} else {
					seen[k] = true
				}
				out = append(out, NewsItem{
					Title: title, URL: link, Source: "@" + acct, Published: st.CreatedAt,
					DiscussionURL: link, Points: st.Favs + st.Reblogs, Comments: st.Replies,
				})
			}
		}
	}
	if ok == 0 && lastErr != nil {
		return nil, lastErr
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	slices.SortStableFunc(out, func(a, b NewsItem) int { return cmp.Compare(b.Points, a.Points) })
	if len(out) > maxPosts {
		out = out[:maxPosts]
	}
	return out, nil
}

var (
	htmlBreak = regexp.MustCompile(`(?i)<br\s*/?>|</p>`)
	htmlTag   = regexp.MustCompile(`(?s)<[^>]*>`)
)

// htmlText turns a post's HTML into one line of text: paragraphs and line
// breaks become spaces, inline tags (links, hashtags) vanish.
func htmlText(s string) string {
	return clean(htmlTag.ReplaceAllString(htmlBreak.ReplaceAllString(s, " "), ""))
}
