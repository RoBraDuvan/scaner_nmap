package config

import (
	"os"
)

type Config struct {
	Port          string
	DatabaseURL   string
	RedisURL      string
	Environment   string
	SubfinderPath string
	AmassPath     string
	HttpxPath     string
}

func Load() *Config {
	return &Config{
		Port:          getEnv("PORT", "8003"),
		DatabaseURL:   getEnv("DATABASE_URL", "postgresql://scanner_user:scanner_pass_2024@localhost:5432/nmap_scanner"),
		RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379/0"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		SubfinderPath: getEnv("SUBFINDER_PATH", "/usr/local/bin/subfinder"),
		AmassPath:     getEnv("AMASS_PATH", "/usr/local/bin/amass"),
		HttpxPath:     getEnv("HTTPX_PATH", "/usr/local/bin/httpx"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
