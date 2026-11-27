package easm

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// smtpProbe actively connects to the domain's mail exchangers and records the
// SMTP banner, EHLO capabilities, and STARTTLS support (A14). Non-abusive: it
// greets and quits, never sends mail or attempts relay/AUTH. method=active.
// Note: outbound TCP/25 is blocked on many networks, in which case the dial
// simply fails and nothing is recorded.
type smtpProbe struct{}

func (smtpProbe) Name() string { return "smtp_probe" }

const (
	smtpDialTimeout = 5 * time.Second
	smtpMaxMX       = 2 // probe at most this many mail exchangers
)

func (smtpProbe) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return nil, nil // no mail infrastructure
	}
	out := []db.AssetRecord{}
	for i, mx := range mxs {
		if i >= smtpMaxMX {
			break
		}
		host := strings.TrimSuffix(mx.Host, ".")
		banner, caps, ok := smtpConverse(ctx, host)
		if !ok {
			continue // unreachable or port 25 blocked
		}
		starttls := false
		for _, c := range caps {
			if strings.EqualFold(c, "STARTTLS") {
				starttls = true
				break
			}
		}
		out = append(out, recActive("smtp", host, "smtp_probe", map[string]any{
			"mx":           host,
			"preference":   mx.Pref,
			"banner":       banner,
			"starttls":     starttls,
			"capabilities": caps,
		}, "SMTP EHLO"))
	}
	return out, nil
}

// smtpConverse opens an SMTP session, reads the banner, sends EHLO, and returns
// the banner and advertised capabilities. ok is false if the host is unreachable.
func smtpConverse(ctx context.Context, host string) (banner string, caps []string, ok bool) {
	d := &net.Dialer{Timeout: smtpDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
	if err != nil {
		return "", nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpDialTimeout))
	br := bufio.NewReader(conn)

	greeting, err := br.ReadString('\n')
	if err != nil {
		return "", nil, false
	}
	banner = cleanBanner([]byte(greeting))

	if _, err := fmt.Fprintf(conn, "EHLO pahredar.local\r\n"); err != nil {
		return banner, nil, true
	}
	caps = parseEHLO(br)
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
	return banner, caps, true
}

// parseEHLO reads a multi-line EHLO response ("250-CAP" … "250 CAP") and returns
// the capability tokens. Stops at the final line (space after the code) or EOF.
func parseEHLO(br *bufio.Reader) []string {
	seen := map[string]bool{}
	var caps []string
	for i := 0; i < 50; i++ { // bound the lines read
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if len(line) >= 4 && (line[:3] == "250") {
			cap := strings.TrimSpace(line[4:])
			if cap != "" {
				// A cap may be "SIZE 10240000"; keep the keyword.
				kw := strings.ToUpper(strings.Fields(cap)[0])
				if !seen[kw] {
					seen[kw] = true
					caps = append(caps, kw)
				}
			}
			if line[3] == ' ' { // final line
				break
			}
		}
		if err != nil {
			break
		}
	}
	sort.Strings(caps)
	return caps
}
