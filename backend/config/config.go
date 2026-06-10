package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL string
	JWTSecret   string
	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string
	S3Bucket    string
	S3Region    string
	AppEnv      string
	// AdminAccount is the single bootstrap admin account, in the form
	// email:username:password. Created at first boot; this account is the
	// protected "break-glass" admin (see BreakGlassAdminEmail). Configured
	// via the ADMIN_ACCOUNT env var.
	AdminAccount string
	// BreakGlassAdminEmail is the email of the break-glass admin, derived
	// from AdminAccount at startup. The break-glass admin can never be
	// demoted, disabled, or deleted via the API/UI — it guarantees the
	// server maintainer always has a working admin account. Empty when
	// ADMIN_ACCOUNT is unset.
	BreakGlassAdminEmail string
	ServerURL            string // e.g. https://kutup.example.com — used for federation invite links
	AllowedOrigins       string // comma-separated CORS allowlist; "*" allowed in dev only
	// StorageTotalBytes is the total capacity advertised to the admin UI
	// (S3 bucket / volume size). 0 means "unknown" — the admin page hides
	// the capacity readout and just shows used bytes. Configured via the
	// STORAGE_TOTAL_BYTES env var. Used as a fallback / override when the
	// live SeaweedFS probe (SeaweedFSMasterURL) is unavailable.
	StorageTotalBytes int64
	// SeaweedFSMasterURL is the SeaweedFS master endpoint used to probe
	// real storage capacity + usage for the admin dashboard. Empty disables
	// the probe (the admin UI then falls back to StorageTotalBytes).
	SeaweedFSMasterURL string
}

func Load() *Config {
	adminAccount := getEnv("ADMIN_ACCOUNT", "")
	cfg := &Config{
		DatabaseURL:          mustEnv("DATABASE_URL"),
		JWTSecret:            mustEnv("JWT_SECRET"),
		S3Endpoint:           mustEnv("S3_ENDPOINT"),
		S3AccessKey:          mustEnv("S3_ACCESS_KEY"),
		S3SecretKey:          mustEnv("S3_SECRET_KEY"),
		S3Bucket:             getEnv("S3_BUCKET", "kutup-files"),
		S3Region:             getEnv("S3_REGION", "us-east-1"),
		AppEnv:               getEnv("APP_ENV", "development"),
		AdminAccount:         adminAccount,
		BreakGlassAdminEmail: breakGlassEmail(adminAccount),
		ServerURL:            getEnv("SERVER_URL", "http://kutup.local"),
		AllowedOrigins:       getEnv("ALLOWED_ORIGINS", "https://localhost:38443,tauri://localhost,http://tauri.localhost"),
		StorageTotalBytes:    getEnvInt64("STORAGE_TOTAL_BYTES", 0),
		SeaweedFSMasterURL:   getEnv("SEAWEEDFS_MASTER_URL", "http://seaweedfs-master:9333"),
	}
	if len(cfg.JWTSecret) < 32 {
		panic("JWT_SECRET must be at least 32 characters long")
	}
	return cfg
}

// breakGlassEmail extracts the email from an ADMIN_ACCOUNT value
// (email:username:password). Returns "" for an empty or malformed value.
func breakGlassEmail(adminAccount string) string {
	if adminAccount == "" {
		return ""
	}
	parts := strings.SplitN(strings.TrimSpace(adminAccount), ":", 3)
	if len(parts) != 3 {
		return ""
	}
	return strings.TrimSpace(parts[0])
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
