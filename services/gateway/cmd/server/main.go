package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/security-scanner/gateway/internal/middleware"
	"github.com/security-scanner/gateway/internal/proxy"
	"github.com/security-scanner/gateway/pkg/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Println("Starting Security Scanner API Gateway")
	log.Printf("Environment: %s", cfg.Environment)
	log.Printf("Network Service: %s", cfg.NetworkServiceURL)
	log.Printf("Web Service: %s", cfg.WebServiceURL)
	log.Printf("Recon Service: %s", cfg.ReconServiceURL)
	log.Printf("API Service: %s", cfg.APIServiceURL)
	log.Printf("CMS Service: %s", cfg.CMSServiceURL)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Security Scanner API Gateway",
		ServerHeader: "SecurityScanner",
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(middleware.Logger())
	app.Use(middleware.CORS())

	// Create proxy
	serviceProxy := proxy.NewServiceProxy()

	// API routes
	api := app.Group("/api")

	// ============================================
	// Network Service Routes (Port 8001)
	// Handles: Nmap scans, port scanning, network discovery
	// ============================================
	network := api.Group("/network")
	network.All("/scans", serviceProxy.ProxyTo(cfg.NetworkServiceURL+"/api", "/api/network"))
	network.All("/scans/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL+"/api", "/api/network"))
	network.All("/templates", serviceProxy.ProxyTo(cfg.NetworkServiceURL+"/api", "/api/network"))
	network.All("/templates/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL+"/api", "/api/network"))
	network.All("/reports/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL+"/api", "/api/network"))

	// ============================================
	// Web Service Routes (Port 8002)
	// Handles: Nuclei scans, fuzzing, screenshots, SSL analysis
	// ============================================
	web := api.Group("/web")
	web.All("/vulnerabilities", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/vulnerabilities/*", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/fuzzing", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/fuzzing/*", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/screenshots", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/screenshots/*", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/ssl", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/ssl/*", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))
	web.All("/templates/*", serviceProxy.ProxyTo(cfg.WebServiceURL+"/api", "/api/web"))

	// ============================================
	// Legacy routes (backward compatibility)
	// These map old routes directly to services
	// No prefix stripping - forward path as-is
	// ============================================
	// /api/scans -> Network Service /api/scans
	api.All("/scans", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))
	api.All("/scans/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))

	// /api/templates -> Network Service /api/templates
	api.All("/templates", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))
	api.All("/templates/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))

	// /api/reports -> Network Service /api/reports
	api.All("/reports/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))

	// /api/vulnerabilities -> Web Service /api/vulnerabilities
	api.All("/vulnerabilities", serviceProxy.ProxyTo(cfg.WebServiceURL, ""))
	api.All("/vulnerabilities/*", serviceProxy.ProxyTo(cfg.WebServiceURL, ""))

	// /api/webscans -> Web Service /api/webscans (ffuf, gowitness, testssl)
	api.All("/webscans", serviceProxy.ProxyTo(cfg.WebServiceURL, ""))
	api.All("/webscans/*", serviceProxy.ProxyTo(cfg.WebServiceURL, ""))

	// /api/recon -> Recon Service /api/recon (subdomains, whois, dns, tech)
	api.All("/recon", serviceProxy.ProxyTo(cfg.ReconServiceURL, ""))
	api.All("/recon/*", serviceProxy.ProxyTo(cfg.ReconServiceURL, ""))

	// /api/apiscans -> API Service /api/apiscans (kiterunner, arjun, graphql, swagger)
	api.All("/apiscans", serviceProxy.ProxyTo(cfg.APIServiceURL, ""))
	api.All("/apiscans/*", serviceProxy.ProxyTo(cfg.APIServiceURL, ""))

	// /api/cmsscans -> CMS Service /api/cmsscans (whatweb, cmseek, wpscan)
	api.All("/cmsscans", serviceProxy.ProxyTo(cfg.CMSServiceURL, ""))
	api.All("/cmsscans/*", serviceProxy.ProxyTo(cfg.CMSServiceURL, ""))

	// /api/vulnerability-templates -> Network Service (still has the templates)
	api.All("/vulnerability-templates", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))
	api.All("/vulnerability-templates/*", serviceProxy.ProxyTo(cfg.NetworkServiceURL, ""))

	// ============================================
	// Health & Status
	// ============================================
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "api-gateway",
			"version": "1.0.0",
		})
	})

	// Service status endpoint
	app.Get("/api/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"gateway": "ok",
			"services": fiber.Map{
				"network": cfg.NetworkServiceURL,
				"web":     cfg.WebServiceURL,
				"recon":   cfg.ReconServiceURL,
				"api":     cfg.APIServiceURL,
				"cms":     cfg.CMSServiceURL,
			},
		})
	})

	// Start server
	log.Printf("Gateway listening on port %s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start gateway: %v", err)
	}
}
