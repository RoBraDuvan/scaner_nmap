package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/nmap-scanner/backend-go/internal/api/handlers"
	"github.com/nmap-scanner/backend-go/internal/api/middleware"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/scanner"
	"github.com/nmap-scanner/backend-go/pkg/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Println("🚀 Starting Nmap Scanner API (Go)")
	log.Printf("📊 Database: %s", cfg.DatabaseURL)
	log.Printf("🔴 Redis: %s", cfg.RedisURL)
	log.Printf("🔧 Use System Nmap: %v", cfg.UseSystemNmap)
	log.Printf("🌍 Environment: %s", cfg.Environment)

	// Initialize database
	db, err := database.NewDatabase(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize scanners
	nmapScanner := scanner.NewScanner(db, cfg.UseSystemNmap, cfg.NmapPath)
	nucleiScanner := scanner.NewNucleiScanner(db)

	// Initialize handlers
	scanHandler := handlers.NewScanHandler(db, nmapScanner)
	templateHandler := handlers.NewTemplateHandler(db)
	vulnHandler := handlers.NewVulnerabilityHandler(db, nucleiScanner)
	reportHandler := handlers.NewReportHandler(db)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Nmap Scanner API (Go)",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(middleware.Logger())
	app.Use(middleware.CORS())

	// Routes
	api := app.Group("/api")

	// Scan routes
	scans := api.Group("/scans")
	scans.Get("/", scanHandler.ListScans)
	scans.Post("/", scanHandler.CreateScan)
	scans.Get("/:id", scanHandler.GetScan)
	scans.Get("/:id/results", scanHandler.GetScanResults)
	scans.Get("/:id/logs", scanHandler.GetScanLogs)
	scans.Delete("/:id", scanHandler.DeleteScan)
	scans.Post("/:id/cancel", scanHandler.CancelScan)

	// Template routes
	templates := api.Group("/templates")
	templates.Get("/", templateHandler.ListTemplates)
	templates.Get("/builtin", templateHandler.ListBuiltinTemplates)
	templates.Post("/", templateHandler.CreateTemplate)
	templates.Get("/:id", templateHandler.GetTemplate)
	templates.Put("/:id", templateHandler.UpdateTemplate)
	templates.Delete("/:id", templateHandler.DeleteTemplate)

	// Vulnerability templates route
	api.Get("/vulnerability-templates", templateHandler.ListVulnerabilityTemplates)

	// Report routes
	reports := api.Group("/reports")
	reports.Get("/:id/json", reportHandler.GetJSONReport)
	reports.Get("/:id/html", reportHandler.GetHTMLReport)
	reports.Get("/:id/csv", reportHandler.GetCSVReport)

	// Vulnerability scan routes
	vulns := api.Group("/vulnerabilities")
	vulns.Get("/", vulnHandler.ListVulnScans)
	vulns.Post("/", vulnHandler.CreateVulnScan)
	vulns.Get("/:id", vulnHandler.GetVulnScan)
	vulns.Get("/:id/results", vulnHandler.GetVulnScanResults)
	vulns.Get("/:id/logs", vulnHandler.GetVulnScanLogs)
	vulns.Get("/:id/stats", vulnHandler.GetVulnScanStats)
	vulns.Post("/:id/cancel", vulnHandler.CancelVulnScan)
	vulns.Delete("/:id", vulnHandler.DeleteVulnScan)

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "ok",
			"backend": "go",
		})
	})

	// Start server
	log.Printf("✅ Server listening on port %s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
