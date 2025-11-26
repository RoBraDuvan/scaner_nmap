package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/security-scanner/web-service/internal/api/handlers"
	"github.com/security-scanner/web-service/internal/api/middleware"
	"github.com/security-scanner/web-service/internal/database"
	"github.com/security-scanner/web-service/internal/scanner"
	"github.com/security-scanner/web-service/pkg/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Printf("Starting Web Service (Nuclei, ffuf, Gowitness, testssl.sh) on port %s...", cfg.Port)
	log.Printf("Environment: %s", cfg.Environment)

	// Connect to database
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to database")

	// Initialize scanners
	nucleiScanner := scanner.NewNucleiScanner(db, cfg.NucleiPath, cfg.TemplatesPath)
	ffufScanner := scanner.NewFfufScanner(db, cfg.FfufPath, cfg.WordlistsPath)
	gowitnessScanner := scanner.NewGowitnessScanner(db, cfg.GowitnessPath, cfg.ScreenshotsPath, cfg.ChromePath)
	testsslScanner := scanner.NewTestsslScanner(db, cfg.TestsslPath)

	log.Printf("Initialized scanners:")
	log.Printf("  - Nuclei: %s", cfg.NucleiPath)
	log.Printf("  - ffuf: %s (wordlists: %s)", cfg.FfufPath, cfg.WordlistsPath)
	log.Printf("  - Gowitness: %s (screenshots: %s)", cfg.GowitnessPath, cfg.ScreenshotsPath)
	log.Printf("  - testssl.sh: %s", cfg.TestsslPath)

	// Initialize handlers
	vulnHandler := handlers.NewVulnerabilityHandler(db, nucleiScanner)
	webScanHandler := handlers.NewWebScanHandler(db, ffufScanner, gowitnessScanner, testsslScanner)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Security Scanner - Web Service",
		ServerHeader: "Web-Service",
	})

	// Global middleware
	app.Use(middleware.CORS())
	app.Use(middleware.Logger())

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "web-service",
			"version": "2.0.0",
			"tools":   []string{"nuclei", "ffuf", "gowitness", "testssl"},
		})
	})

	// API routes
	api := app.Group("/api")

	// Vulnerability scan routes (Nuclei)
	vulns := api.Group("/vulnerabilities")
	vulns.Get("/", vulnHandler.ListVulnScans)
	vulns.Post("/", vulnHandler.CreateVulnScan)
	vulns.Get("/:id", vulnHandler.GetVulnScan)
	vulns.Delete("/:id", vulnHandler.DeleteVulnScan)
	vulns.Post("/:id/cancel", vulnHandler.CancelVulnScan)
	vulns.Get("/:id/results", vulnHandler.GetVulnScanResults)
	vulns.Get("/:id/logs", vulnHandler.GetVulnScanLogs)
	vulns.Get("/:id/stats", vulnHandler.GetVulnScanStats)

	// Web scanning routes (ffuf, gowitness, testssl)
	webscans := api.Group("/webscans")
	webscans.Get("/", webScanHandler.ListWebScans)
	webscans.Get("/templates", webScanHandler.GetWebScanTemplates)
	webscans.Get("/wordlists", webScanHandler.GetWordlists)
	webscans.Get("/:id", webScanHandler.GetWebScan)
	webscans.Delete("/:id", webScanHandler.DeleteWebScan)
	webscans.Post("/:id/cancel", webScanHandler.CancelWebScan)
	webscans.Get("/:id/results", webScanHandler.GetWebScanResults)
	webscans.Get("/:id/logs", webScanHandler.GetWebScanLogs)
	webscans.Get("/:id/stats", webScanHandler.GetWebScanStats)

	// Tool-specific scan creation endpoints
	webscans.Post("/ffuf", webScanHandler.CreateFfufScan)
	webscans.Post("/gowitness", webScanHandler.CreateGowintessScan)
	webscans.Post("/testssl", webScanHandler.CreateTestsslScan)

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Fatal(app.Listen(addr))
}
