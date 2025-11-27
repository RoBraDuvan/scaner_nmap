package config

import (
	"os"
)

type Config struct {
	Port              string
	Environment       string
	NetworkServiceURL string
	WebServiceURL     string
	ReconServiceURL   string
	APIServiceURL     string
	CMSServiceURL     string
	CloudServiceURL   string
}

func Load() *Config {
	return &Config{
		Port:              getEnv("PORT", "8000"),
		Environment:       getEnv("ENVIRONMENT", "development"),
		NetworkServiceURL: getEnv("NETWORK_SERVICE_URL", "http://network-service:8001"),
		WebServiceURL:     getEnv("WEB_SERVICE_URL", "http://web-service:8002"),
		ReconServiceURL:   getEnv("RECON_SERVICE_URL", "http://recon-service:8003"),
		APIServiceURL:     getEnv("API_SERVICE_URL", "http://api-service:8004"),
		CMSServiceURL:     getEnv("CMS_SERVICE_URL", "http://cms-service:8005"),
		CloudServiceURL:   getEnv("CLOUD_SERVICE_URL", "http://cloud-service:8006"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
