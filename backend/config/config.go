package config

import (
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL    string
	JWTSecret      string
	S3Endpoint     string
	S3AccessKey    string
	S3SecretKey    string
	S3Bucket       string
	S3Region       string
	AppEnv         string
	AdminAccounts  string
	ServerURL      string // e.g. https://kutup.example.com — used for federation invite links
	AllowedOrigins string // comma-separated CORS allowlist; "*" allowed in dev only
	// StorageTotalBytes is the total capacity advertised to the admin UI
	// (S3 bucket / volume size). 0 means "unknown" — the admin page hides
	// the capacity readout and just shows used bytes. Configured via the
	// STORAGE_TOTAL_BYTES env var. A future follow-up may auto-detect this
	// from the SeaweedFS master.
	StorageTotalBytes int64
}

func Load() *Config {
	cfg := &Config{
		DatabaseURL:       mustEnv("DATABASE_URL"),
		JWTSecret:         mustEnv("JWT_SECRET"),
		S3Endpoint:        mustEnv("S3_ENDPOINT"),
		S3AccessKey:       mustEnv("S3_ACCESS_KEY"),
		S3SecretKey:       mustEnv("S3_SECRET_KEY"),
		S3Bucket:          getEnv("S3_BUCKET", "kutup-files"),
		S3Region:          getEnv("S3_REGION", "us-east-1"),
		AppEnv:            getEnv("APP_ENV", "development"),
		AdminAccounts:     getEnv("ADMIN_ACCOUNTS", ""),
		ServerURL:         getEnv("SERVER_URL", "http://kutup.local"),
		AllowedOrigins:    getEnv("ALLOWED_ORIGINS", "https://localhost:38443,tauri://localhost,http://tauri.localhost"),
		StorageTotalBytes: getEnvInt64("STORAGE_TOTAL_BYTES", 0),
	}
	if len(cfg.JWTSecret) < 32 {
		panic("JWT_SECRET must be at least 32 characters long")
	}
	return cfg
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required environment variable not set: " + key)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvInt64 reads an int64 env var, returning fallback if unset or unparseable.
// Used by STORAGE_TOTAL_BYTES — admins may pass e.g. "536870912000" for 500 GB.
func getEnvInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}
