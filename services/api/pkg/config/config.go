package config

import (
	"os"
)

type Config struct {
	Port           string
	DatabaseURL    string
	RedisURL       string
	Environment    string
	KiterunnerPath string
	ArjunPath      string
	FfufPath       string
	NucleiPath     string
	WordlistsPath  string
}

func Load() *Config {
	return &Config{
		Port:           getEnv("PORT", "8004"),
		DatabaseURL:    getEnv("DATABASE_URL", "postgresql://scanner_user:scanner_pass_2024@localhost:5432/nmap_scanner"),
		RedisURL:       getEnv("REDIS_URL", "redis://localhost:6379/0"),
		Environment:    getEnv("ENVIRONMENT", "development"),
		KiterunnerPath: getEnv("KITERUNNER_PATH", "/usr/local/bin/kr"),
		ArjunPath:      getEnv("ARJUN_PATH", "/usr/local/bin/arjun"),
		FfufPath:       getEnv("FFUF_PATH", "/usr/local/bin/ffuf"),
		NucleiPath:     getEnv("NUCLEI_PATH", "/usr/local/bin/nuclei"),
		WordlistsPath:  getEnv("WORDLISTS_PATH", "/usr/share/wordlists"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
