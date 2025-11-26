package config

import (
	"os"
	"strconv"
)

type Config struct {
	// Server
	Port string

	// Database
	DatabaseURL string

	// Redis
	RedisURL string

	// Nmap
	UseSystemNmap bool
	NmapPath      string

	// Masscan
	MasscanPath string

	// App
	Environment string
	SecretKey   string
}

func Load() *Config {
	return &Config{
		Port:          getEnv("PORT", "8001"),
		DatabaseURL:   getEnv("DATABASE_URL", "postgresql://scanner_user:scanner_pass_2024@database:5432/nmap_scanner"),
		RedisURL:      getEnv("REDIS_URL", "redis://redis:6379/0"),
		UseSystemNmap: getEnvBool("USE_SYSTEM_NMAP", false),
		NmapPath:      getEnv("NMAP_PATH", "/usr/bin/nmap"),
		MasscanPath:   getEnv("MASSCAN_PATH", "/usr/bin/masscan"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		SecretKey:     getEnv("SECRET_KEY", "supersecretkey"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return defaultValue
		}
		return boolVal
	}
	return defaultValue
}
