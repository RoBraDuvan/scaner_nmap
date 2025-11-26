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

	log.Println("Starting Network Service (Nmap, Masscan, DNS)")
	log.Printf("Database: %s", cfg.DatabaseURL)
	log.Printf("Redis: %s", cfg.RedisURL)
	log.Printf("Use System Nmap: %v", cfg.UseSystemNmap)
	log.Printf("Environment: %s", cfg.Environment)

	// Initialize database
	db, err := database.NewDatabase(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize scanners
	nmapScanner := scanner.NewScanner(db, cfg.UseSystemNmap, cfg.NmapPath)
	masscanScanner := scanner.NewMasscanScanner(db, cfg.MasscanPath)
	dnsScanner := scanner.NewDNSScanner(db)

	log.Printf("Initialized scanners: Nmap (%s), Masscan (%s), DNS", cfg.NmapPath, cfg.MasscanPath)

	// Initialize handlers
	scanHandler := handlers.NewScanHandler(db, nmapScanner, masscanScanner, dnsScanner)
	templateHandler := handlers.NewTemplateHandler(db)
	reportHandler := handlers.NewReportHandler(db)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Security Scanner - Network Service",
		ServerHeader: "Network-Service",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(middleware.Logger())
	app.Use(middleware.CORS())

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":   "ok",
			"service":  "network-service",
			"version":  "1.1.0",
			"scanners": []string{"nmap", "masscan", "dns"},
		})
	})

	// Routes
	api := app.Group("/api")

	// Scan routes (Nmap, Masscan, DNS scans)
	scans := api.Group("/scans")
	scans.Get("/", scanHandler.ListScans)
	scans.Post("/", scanHandler.CreateScan)
	scans.Get("/templates/all", scanHandler.GetAllTemplates) // All scanner templates
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

	// Vulnerability templates route (for Nmap scan type selection)
	api.Get("/vulnerability-templates", templateHandler.ListVulnerabilityTemplates)

	// Report routes
	reports := api.Group("/reports")
	reports.Get("/:id/json", reportHandler.GetJSONReport)
	reports.Get("/:id/html", reportHandler.GetHTMLReport)
	reports.Get("/:id/csv", reportHandler.GetCSVReport)

	// Start server
	log.Printf("Server listening on port %s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
