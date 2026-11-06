// Package config loads runtime configuration from environment variables.
// Every variable is documented in the repository's .env.example.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	HTTPAddr    string
	LogLevel    slog.Level
	NVDAPIKey   string
	GitHubToken string
	// Optional free-signup keys. A source whose key is missing is skipped
	// (sync) or reported as disabled (on-demand reports).
	VulnCheckToken     string
	OTXKey             string
	AbuseCHKey         string
	BlueskyHandle      string
	BlueskyAppPassword string
	// Endpoint scanner settings.
	ScanAllowPrivate   bool   // allow scanning private/internal addresses
	ScanActiveEnabled  bool   // allow active (Nuclei) scanning
	// AssetRescanInterval auto re-scans tracked assets this often (0 disables).
	AssetRescanInterval time.Duration
	// AlertWebhookURL receives new alerts as JSON (Slack-style {text}); empty disables.
	AlertWebhookURL string
	// AlertEPSSThreshold is the minimum EPSS score (0–1) for a non-KEV CVE on a
	// tracked asset to raise a "likely-exploited" alert. Higher = fewer, surer
	// alerts. Default 0.5; raise toward 0.7 to cut noise.
	AlertEPSSThreshold float64
	// SMTP + recipient for email alert delivery; email is enabled when SMTPHost
	// and AlertEmailTo are both set.
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	AlertEmailTo string
	// APIKeys are automation credentials: a matching key is an admin principal
	// (Authorization: Bearer / X-API-Key). Human access is by account; empty
	// disables key auth.
	APIKeys []string
	// Auth: the first admin is seeded from these when no users exist.
	AdminEmail    string
	AdminPassword string
	// AuthCookieSecure sets the Secure flag on the session cookie (enable behind
	// HTTPS). AuthSessionTTL is the session + cookie lifetime.
	AuthCookieSecure bool
	AuthSessionTTL   time.Duration
	NucleiPath         string // nuclei binary, "" disables active scanning
	NucleiTemplatesDir string
	// DataDir holds temporary download artifacts (the extracted cvelist
	// baseline needs ~700 MB during a bootstrap).
	DataDir     string
	SyncEnabled bool
	Intervals   Intervals
}

// Intervals is how often each sync source runs.
type Intervals struct {
	CVEList  time.Duration
	NVD      time.Duration
	KEV      time.Duration
	EPSS     time.Duration
	Exploits time.Duration
	// Stats is a fallback; stats also refresh after cvelist, NVD, or KEV
	// runs that changed data.
	Stats     time.Duration
	CWE       time.Duration
	Feeds     time.Duration
	Detection time.Duration
	// Greenbone is weekly by default: each run downloads a ~230 MB layer.
	Greenbone time.Duration
	// Context covers EUVD, Debian, and VulnCheck KEV (daily) and is multiplied by 7 for
	// the slow-moving ATT&CK mappings and CAPEC.
	Context time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		HTTPAddr:           getenv("HTTP_ADDR", ":8080"),
		NVDAPIKey:          os.Getenv("NVD_API_KEY"),
		GitHubToken:        os.Getenv("GITHUB_TOKEN"),
		VulnCheckToken:     os.Getenv("VULNCHECK_API_TOKEN"),
		OTXKey:             os.Getenv("OTX_API_KEY"),
		AbuseCHKey:         os.Getenv("ABUSECH_AUTH_KEY"),
		BlueskyHandle:      strings.TrimPrefix(os.Getenv("BLUESKY_HANDLE"), "@"),
		BlueskyAppPassword: os.Getenv("BLUESKY_APP_PASSWORD"),
		NucleiPath:         getenv("NUCLEI_PATH", "nuclei"),
		NucleiTemplatesDir: getenv("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates"),
		AlertWebhookURL:    getenv("ALERT_WEBHOOK_URL", ""),
		SMTPHost:           getenv("SMTP_HOST", ""),
		SMTPPort:           getenv("SMTP_PORT", "587"),
		SMTPUsername:       getenv("SMTP_USERNAME", ""),
		SMTPPassword:       getenv("SMTP_PASSWORD", ""),
		SMTPFrom:           getenv("SMTP_FROM", "pahredar@localhost"),
		AlertEmailTo:       getenv("ALERT_EMAIL_TO", ""),
		APIKeys:            splitCommaNonEmpty(getenv("API_KEY", "")),
		AdminEmail:         getenv("ADMIN_EMAIL", ""),
		AdminPassword:      getenv("ADMIN_PASSWORD", ""),
		DataDir:            getenv("DATA_DIR", os.TempDir()),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if err := cfg.LogLevel.UnmarshalText([]byte(strings.ToUpper(getenv("LOG_LEVEL", "info")))); err != nil {
		return Config{}, errors.New("LOG_LEVEL must be one of debug, info, warn, error")
	}
	var err error
	if cfg.SyncEnabled, err = strconv.ParseBool(getenv("SYNC_ENABLED", "true")); err != nil {
		return Config{}, errors.New("SYNC_ENABLED must be true or false")
	}
	if cfg.ScanAllowPrivate, err = strconv.ParseBool(getenv("SCAN_ALLOW_PRIVATE", "false")); err != nil {
		return Config{}, errors.New("SCAN_ALLOW_PRIVATE must be true or false")
	}
	if cfg.ScanActiveEnabled, err = strconv.ParseBool(getenv("SCAN_ACTIVE_ENABLED", "false")); err != nil {
		return Config{}, errors.New("SCAN_ACTIVE_ENABLED must be true or false")
	}
	if cfg.AlertEPSSThreshold, err = strconv.ParseFloat(getenv("ALERT_EPSS_THRESHOLD", "0.5"), 64); err != nil || cfg.AlertEPSSThreshold < 0 || cfg.AlertEPSSThreshold > 1 {
		return Config{}, errors.New("ALERT_EPSS_THRESHOLD must be a number between 0 and 1")
	}
	if cfg.AuthCookieSecure, err = strconv.ParseBool(getenv("AUTH_COOKIE_SECURE", "false")); err != nil {
		return Config{}, errors.New("AUTH_COOKIE_SECURE must be true or false")
	}
	for _, d := range []struct {
		key      string
		dst      *time.Duration
		fallback time.Duration
	}{
		{"CVELIST_SYNC_INTERVAL", &cfg.Intervals.CVEList, time.Hour},
		{"NVD_SYNC_INTERVAL", &cfg.Intervals.NVD, 2 * time.Hour},
		{"KEV_SYNC_INTERVAL", &cfg.Intervals.KEV, 6 * time.Hour},
		{"EPSS_SYNC_INTERVAL", &cfg.Intervals.EPSS, 6 * time.Hour},
		{"EXPLOITS_SYNC_INTERVAL", &cfg.Intervals.Exploits, 24 * time.Hour},
		{"STATS_REFRESH_INTERVAL", &cfg.Intervals.Stats, 6 * time.Hour},
		{"CWE_SYNC_INTERVAL", &cfg.Intervals.CWE, 7 * 24 * time.Hour},
		{"FEEDS_SYNC_INTERVAL", &cfg.Intervals.Feeds, time.Hour},
		{"DETECTION_SYNC_INTERVAL", &cfg.Intervals.Detection, 24 * time.Hour},
		{"CONTEXT_SYNC_INTERVAL", &cfg.Intervals.Context, 24 * time.Hour},
		{"GREENBONE_SYNC_INTERVAL", &cfg.Intervals.Greenbone, 7 * 24 * time.Hour},
		{"ASSET_RESCAN_INTERVAL", &cfg.AssetRescanInterval, 24 * time.Hour},
		{"AUTH_SESSION_TTL", &cfg.AuthSessionTTL, 168 * time.Hour},
	} {
		if *d.dst, err = duration(d.key, d.fallback); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

// splitCommaNonEmpty splits a comma-separated list, trimming and dropping blanks.
func splitCommaNonEmpty(v string) []string {
	out := []string{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func duration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute {
		return 0, fmt.Errorf("%s must be a duration of at least 1m, like 1h or 90m", key)
	}
	return d, nil
}
