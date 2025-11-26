package config

import (
	"os"
)

// Config holds all configuration for the web service
type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	Environment string

	// Nuclei configuration
	NucleiPath    string
	TemplatesPath string

	// ffuf configuration
	FfufPath      string
	WordlistsPath string

	// Gowitness configuration
	GowitnessPath   string
	ScreenshotsPath string
	ChromePath      string

	// testssl.sh configuration
	TestsslPath string
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Port:        getEnv("PORT", "8002"),
		DatabaseURL: getEnv("DATABASE_URL", "postgresql://scanner_user:scanner_pass_2024@database:5432/nmap_scanner"),
		RedisURL:    getEnv("REDIS_URL", "redis://redis:6379/0"),
		Environment: getEnv("ENVIRONMENT", "development"),

		// Nuclei
		NucleiPath:    getEnv("NUCLEI_PATH", "/usr/local/bin/nuclei"),
		TemplatesPath: getEnv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates"),

		// ffuf
		FfufPath:      getEnv("FFUF_PATH", "/usr/local/bin/ffuf"),
		WordlistsPath: getEnv("WORDLISTS_PATH", "/root/wordlists"),

		// Gowitness
		GowitnessPath:   getEnv("GOWITNESS_PATH", "/usr/local/bin/gowitness"),
		ScreenshotsPath: getEnv("SCREENSHOTS_PATH", "/root/screenshots"),
		ChromePath:      getEnv("CHROME_PATH", "/usr/bin/chromium-browser"),

		// testssl.sh
		TestsslPath: getEnv("TESTSSL_PATH", "/usr/local/bin/testssl.sh"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
