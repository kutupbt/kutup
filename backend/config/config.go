package config

import (
	"os"
)

type Config struct {
	DatabaseURL   string
	JWTSecret     string
	S3Endpoint    string
	S3AccessKey   string
	S3SecretKey   string
	S3Bucket      string
	S3Region      string
	AppEnv        string
	AdminAccounts string
	ServerURL     string // e.g. https://kutup.example.com — used for federation invite links
}

func Load() *Config {
	cfg := &Config{
		DatabaseURL:   mustEnv("DATABASE_URL"),
		JWTSecret:     mustEnv("JWT_SECRET"),
		S3Endpoint:    mustEnv("S3_ENDPOINT"),
		S3AccessKey:   mustEnv("S3_ACCESS_KEY"),
		S3SecretKey:   mustEnv("S3_SECRET_KEY"),
		S3Bucket:      getEnv("S3_BUCKET", "depo-files"),
		S3Region:      getEnv("S3_REGION", "us-east-1"),
		AppEnv:        getEnv("APP_ENV", "development"),
		AdminAccounts: getEnv("ADMIN_ACCOUNTS", ""),
		ServerURL:     getEnv("SERVER_URL", "http://kutup.local"),
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
