package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Nuclei runs intrusive checks with ProjectDiscovery's Nuclei: community
// templates that actively probe a target to verify a vulnerability (the same
// category of check as a Nuclei scan command, not destructive exploitation).
// It is only used when the server enables active scanning and the request is
// marked authorized.
type Nuclei struct {
	bin, templatesDir, home string
	mu                      sync.Mutex // serialises template updates
}

// NewNuclei returns a runner, or nil when no binary path is given. home must
// be a writable directory for Nuclei's config and cache.
func NewNuclei(bin, templatesDir, home string) *Nuclei {
	if bin == "" {
		return nil
	}
	return &Nuclei{bin: bin, templatesDir: templatesDir, home: home}
}

// ActiveScan is the result of the intrusive phase.
type ActiveScan struct {
	Ran      bool            `json:"ran"`
	Engine   string          `json:"engine"`
	Duration string          `json:"duration"`
	Findings []ActiveFinding `json:"findings"`
	Note     string          `json:"note,omitempty"`
}

// ActiveFinding is one template that matched the target.
type ActiveFinding struct {
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Tags       []string `json:"tags"`
	CVEs       []string `json:"cves"`
	MatchedAt  string   `json:"matched_at"`
	Reference  []string `json:"reference,omitempty"`
	// Count is how many times this template matched (e.g. one per missing
	// header); the shown MatchedAt is the first.
	Count int `json:"count"`
}

// nucleiLine is the subset of Nuclei's -jsonl output we read.
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Classification struct {
			CVEID []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
}

const maxActiveFindings = 300

// EnsureTemplates downloads or refreshes the template set if it is missing or
// older than a week. It is safe to call before every active scan.
func (n *Nuclei) EnsureTemplates(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Templates are bundled in the image (read-only); use them as-is.
	if hasTemplates(n.templatesDir) {
		return nil
	}
	if err := os.MkdirAll(n.templatesDir, 0o755); err != nil {
		return err
	}
	uctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(uctx, n.bin, "-update-templates", "-update-template-dir", n.templatesDir, "-disable-update-check", "-no-color")
	cmd.Env = n.env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nuclei update-templates: %w: %s", err, tail(string(out), 300))
	}
	return nil
}

// hasTemplates reports whether dir already contains a template set.
func hasTemplates(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return len(entries) > 3 // the template repo has many top-level folders
}

// Run scans targetURL and returns the templates that matched, calling
// onStats periodically with live progress from Nuclei's statistics and
// onFinding once for each template the first time it matches (so results can
// stream to the UI as they are found).
func (n *Nuclei) Run(ctx context.Context, targetURL string, onStats func(ActiveProgress), onFinding func(ActiveFinding)) (*ActiveScan, error) {
	if onStats == nil {
		onStats = func(ActiveProgress) {}
	}
	if onFinding == nil {
		onFinding = func(ActiveFinding) {}
	}
	start := time.Now()
	if err := n.EnsureTemplates(ctx); err != nil {
		return &ActiveScan{Engine: "nuclei", Note: "templates unavailable: " + err.Error()}, nil
	}
	args := []string{
		"-target", targetURL,
		"-jsonl", "-silent", "-no-color", "-disable-update-check",
		"-templates", n.templatesDir,
		// Reachable-over-the-network checks only (no local file/code templates).
		"-type", "http,ssl",
		// Leave out denial-of-service and fuzzing templates: verification, not harm.
		"-exclude-tags", "dos,fuzz,fuzzing",
		"-rate-limit", "50", "-concurrency", "25", "-timeout", "10", "-retries", "1", "-max-host-error", "40",
		"-no-interactsh",                                // keep the scan self-contained (no out-of-band callbacks)
		"-stats", "-stats-json", "-stats-interval", "2", // live progress on stderr
	}
	cmd := exec.CommandContext(ctx, n.bin, args...)
	cmd.Env = n.env()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	out := &ActiveScan{Ran: true, Engine: "nuclei v3", Findings: []ActiveFinding{}}
	var mu sync.Mutex
	matched := 0
	byTemplate := map[string]int{} // template id -> index in out.Findings

	// Statistics (stderr): live progress.
	var swg sync.WaitGroup
	swg.Add(1)
	go func() {
		defer swg.Done()
		ss := bufio.NewScanner(stderr)
		ss.Buffer(make([]byte, 64<<10), 1<<20)
		for ss.Scan() {
			var st struct {
				Templates, Requests, Total, Percent, Matched string
			}
			if json.Unmarshal(ss.Bytes(), &st) != nil || st.Percent == "" {
				continue
			}
			mu.Lock()
			m := matched
			mu.Unlock()
			onStats(ActiveProgress{
				Templates: atoi(st.Templates), Requests: atoi(st.Requests),
				Total: atoi(st.Total), Percent: atoi(st.Percent), Matched: m,
			})
		}
	}()

	// Findings (stdout).
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var l nucleiLine
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.TemplateID == "" {
			continue
		}
		mu.Lock()
		if i, ok := byTemplate[l.TemplateID]; ok {
			out.Findings[i].Count++
			mu.Unlock()
			continue
		}
		if len(out.Findings) >= maxActiveFindings {
			mu.Unlock()
			continue
		}
		byTemplate[l.TemplateID] = len(out.Findings)
		f := ActiveFinding{
			TemplateID: l.TemplateID, Name: l.Info.Name, Severity: l.Info.Severity,
			Tags: l.Info.Tags, CVEs: l.Info.Classification.CVEID, MatchedAt: l.MatchedAt,
			Reference: l.Info.Reference, Count: 1,
		}
		out.Findings = append(out.Findings, f)
		matched++
		mu.Unlock()
		onFinding(f)
	}
	swg.Wait()
	// Nuclei exits non-zero on some conditions even with results; the parsed
	// output is authoritative, so a wait error is noted, not fatal.
	if err := cmd.Wait(); err != nil && ctx.Err() == nil && len(out.Findings) == 0 {
		out.Note = "nuclei: " + err.Error()
	}
	if ctx.Err() != nil {
		out.Note = "scan time limit reached; results may be partial"
	}
	out.Duration = time.Since(start).Round(time.Millisecond).String()
	return out, nil
}

func (n *Nuclei) env() []string {
	// Nuclei writes its config/cache under HOME; point it at a writable dir
	// (the templates directory is bundled read-only).
	return append(os.Environ(), "HOME="+n.home, "NUCLEI_TEMPLATES_DIR="+n.templatesDir)
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// nucleiSeverity maps Nuclei's severity to the report's scale.
func nucleiSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low":
		return SevLow
	default:
		return SevInfo
	}
}
