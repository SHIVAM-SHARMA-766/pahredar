package easm

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// commonPorts are the ports we TCP-connect scan, with their usual service (A04/
// A05). Kept small and curated so a scan is bounded and low-impact.
var commonPorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 143: "imap", 443: "https", 445: "smb", 465: "smtps",
	587: "smtp-submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
	1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	5672: "rabbitmq", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
	9200: "elasticsearch", 27017: "mongodb",
}

const (
	portScanConcurrency = 20
	portDialTimeout     = 2 * time.Second
	maxScanIPs          = 4 // budget: scan at most this many of the domain's IPs
	bannerReadTimeout   = 1500 * time.Millisecond
)

// portScan does a budgeted TCP-connect scan of the domain's resolved IPs on the
// common ports, recording the open ones. method=active (direct contact).
type portScan struct{}

func (portScan) Name() string { return "port_scan" }

func (portScan) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	// Dedup and bound the IP set.
	seen := map[string]bool{}
	targets := []string{}
	for _, ip := range ips {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			targets = append(targets, s)
			if len(targets) >= maxScanIPs {
				break
			}
		}
	}

	ports := make([]int, 0, len(commonPorts))
	for p := range commonPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	type target struct {
		ip   string
		port int
	}
	jobs := make(chan target)
	var mu sync.Mutex
	out := []db.AssetRecord{}
	var wg sync.WaitGroup
	dialer := &net.Dialer{Timeout: portDialTimeout}

	for i := 0; i < portScanConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				conn, derr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.ip, strconv.Itoa(t.port)))
				if derr != nil {
					continue
				}
				banner := grabBanner(conn) // A05: services that greet on connect
				conn.Close()
				data := map[string]any{
					"ip":      t.ip,
					"port":    t.port,
					"service": commonPorts[t.port],
					"state":   "open",
				}
				if banner != "" {
					data["banner"] = banner
				}
				r := recActive("port", t.ip+":"+strconv.Itoa(t.port), "port_scan", data, "TCP connect")
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
			}
		}()
	}
	for _, ip := range targets {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return out, nil
			case jobs <- target{ip: ip, port: p}:
			}
		}
	}
	close(jobs)
	wg.Wait()
	return out, nil
}

// grabBanner reads the greeting a service sends on connect (SSH/FTP/SMTP/Redis/…)
// and returns its first printable line, or "" when nothing printable arrives in
// time (e.g. HTTP/TLS ports, which wait for a request).
func grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return cleanBanner(buf[:n])
}

// cleanBanner extracts the first line of printable ASCII from raw bytes, trimmed
// and length-capped; returns "" if there is no usable text (e.g. binary/TLS).
func cleanBanner(raw []byte) string {
	// Cut at the first CR/LF.
	end := len(raw)
	for i, b := range raw {
		if b == '\r' || b == '\n' {
			end = i
			break
		}
	}
	line := make([]byte, 0, end)
	for _, b := range raw[:end] {
		if b >= 32 && b <= 126 {
			line = append(line, b)
		}
	}
	s := strings.TrimSpace(string(line))
	if len(s) < 3 { // too short to be a meaningful banner
		return ""
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
