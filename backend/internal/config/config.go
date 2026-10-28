// Package config loads runtime configuration from environment variables.
// Every variable is documented in the repository's .env.example.
package config

import (
	"errors"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL string
	HTTPAddr    string
	LogLevel    slog.Level
	NVDAPIKey   string
	GitHubToken string
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		HTTPAddr:    getenv("HTTP_ADDR", ":8080"),
		NVDAPIKey:   os.Getenv("NVD_API_KEY"),
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if err := cfg.LogLevel.UnmarshalText([]byte(strings.ToUpper(getenv("LOG_LEVEL", "info")))); err != nil {
		return Config{}, errors.New("LOG_LEVEL must be one of debug, info, warn, error")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
