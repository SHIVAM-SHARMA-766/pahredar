package easm

import (
	"context"
	"net"
	"sort"
	"sync"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// subBrute actively discovers subdomains by resolving a curated wordlist of
// common names against the domain (A02). method=active, budgeted: a fixed, small
// wordlist resolved with bounded concurrency — not an open-ended brute force.
// Only names that actually resolve are recorded, each with its IPs.
type subBrute struct{}

func (subBrute) Name() string { return "sub_brute" }

const subBruteConcurrency = 20

// commonSubdomains are frequently-used hostnames worth a direct resolution.
var commonSubdomains = []string{
	"www", "mail", "webmail", "smtp", "imap", "pop", "ns1", "ns2", "mx", "mx1",
	"api", "api2", "dev", "staging", "stage", "test", "qa", "uat", "demo",
	"admin", "portal", "dashboard", "app", "apps", "web", "cdn", "static",
	"assets", "img", "images", "media", "files", "download", "docs", "doc",
	"blog", "news", "shop", "store", "support", "help", "status", "monitor",
	"grafana", "kibana", "prometheus", "vpn", "remote", "gw", "gateway",
	"git", "gitlab", "jenkins", "ci", "registry", "db", "database", "redis",
	"cache", "auth", "sso", "login", "account", "accounts", "beta", "internal",
	"intranet", "secure", "mobile", "m", "cpanel", "webdisk", "autodiscover",
	"ftp", "sftp", "backup", "old", "new", "cloud", "s3", "storage", "proxy",
}

func (subBrute) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	r := net.DefaultResolver
	type hit struct {
		host string
		ips  []string
	}
	hits := make([]hit, 0)
	var mu sync.Mutex
	sem := make(chan struct{}, subBruteConcurrency)
	var wg sync.WaitGroup

	for _, label := range commonSubdomains {
		host := label + "." + domain
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			addrs, err := r.LookupHost(ctx, host)
			if err != nil || len(addrs) == 0 {
				return
			}
			mu.Lock()
			hits = append(hits, hit{host: host, ips: dedupStrings(addrs)})
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool { return hits[i].host < hits[j].host })
	out := []db.AssetRecord{}
	for _, h := range hits {
		out = append(out, recActive("subdomain", h.host, "dns_bruteforce",
			map[string]any{"host": h.host, "ips": h.ips}, "resolved common subdomain"))
		for _, ip := range h.ips {
			out = append(out, recActive("ip", ip, "dns_bruteforce", map[string]any{"ip": ip, "from": h.host}, "resolved common subdomain"))
		}
	}
	return out, nil
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
