package easm

import (
	"context"
	"net/http"
	"sync"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// dirScan probes a bounded, curated list of commonly-exposed sensitive paths
// (VCS metadata, env/config files, backups, debug/admin endpoints) with plain
// GETs (A10). It records paths that are served (200) or protected (401/403);
// the assessment turns the dangerous ones into findings. Non-destructive, no
// downloads beyond a small sample. method=active.
type dirScan struct{}

func (dirScan) Name() string { return "dir_scan" }

const dirScanConcurrency = 10

// sensitivePaths are checked on every active scan. severity is the finding level
// when the path is actually served (200).
var sensitivePaths = []struct {
	path, label, severity string
}{
	{"/.git/config", "Git repository config", "high"},
	{"/.git/HEAD", "Git repository metadata", "high"},
	{"/.env", "Environment file", "high"},
	{"/.env.local", "Environment file", "high"},
	{"/.env.production", "Environment file", "high"},
	{"/config.php.bak", "PHP config backup", "high"},
	{"/wp-config.php.bak", "WordPress config backup", "high"},
	{"/.svn/entries", "Subversion metadata", "high"},
	{"/.DS_Store", "macOS directory index", "low"},
	{"/backup.zip", "Backup archive", "high"},
	{"/backup.sql", "Database dump", "high"},
	{"/dump.sql", "Database dump", "high"},
	{"/phpinfo.php", "PHP info page", "medium"},
	{"/server-status", "Apache server-status", "medium"},
	{"/server-info", "Apache server-info", "medium"},
	{"/actuator", "Spring Boot Actuator", "medium"},
	{"/actuator/env", "Spring Actuator env", "high"},
	{"/actuator/health", "Spring Actuator health", "low"},
	{"/adminer.php", "Adminer DB console", "medium"},
	{"/.htaccess", "Apache htaccess", "low"},
	{"/web.config", "IIS web.config", "medium"},
	{"/.aws/credentials", "AWS credentials", "high"},
	{"/.npmrc", "npm config (may hold tokens)", "medium"},
}

func (dirScan) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	client := wellKnownClient()
	out := make([]db.AssetRecord, 0)
	var mu sync.Mutex
	sem := make(chan struct{}, dirScanConcurrency)
	var wg sync.WaitGroup

	for _, p := range sensitivePaths {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			status := headOrGet(ctx, client, "https://"+domain+p.path)
			// Only record interesting states: served, or present-but-protected.
			if status != http.StatusOK && status != http.StatusUnauthorized && status != http.StatusForbidden {
				return
			}
			mu.Lock()
			out = append(out, recActive("exposed_path", p.path, "http_probe",
				map[string]any{"path": p.path, "status": status, "label": p.label, "severity": p.severity}, "sensitive-path probe"))
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out, nil
}

// headOrGet requests a path and returns its status code (0 on failure). A GET is
// used (some servers mishandle HEAD) with the body discarded by the caller's
// bounded reader.
func headOrGet(ctx context.Context, client *http.Client, u string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "pahredar-easm")
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}
