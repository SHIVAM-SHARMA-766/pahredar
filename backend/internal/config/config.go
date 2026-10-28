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
	// DataDir holds temporary download artifacts (the extracted cvelist
	// baseline needs ~700 MB during a bootstrap).
	DataDir             string
	SyncEnabled         bool
	CVEListSyncInterval time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		HTTPAddr:    getenv("HTTP_ADDR", ":8080"),
		NVDAPIKey:   os.Getenv("NVD_API_KEY"),
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		DataDir:     getenv("DATA_DIR", os.TempDir()),
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
	if cfg.CVEListSyncInterval, err = duration("CVELIST_SYNC_INTERVAL", time.Hour); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
