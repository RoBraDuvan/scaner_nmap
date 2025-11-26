package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/security-scanner/recon-service/internal/api/handlers"
	"github.com/security-scanner/recon-service/internal/api/middleware"
	"github.com/security-scanner/recon-service/internal/database"
	"github.com/security-scanner/recon-service/internal/recon"
	"github.com/security-scanner/recon-service/pkg/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Println("Starting Recon Service (Subdomain, WHOIS, DNS, Tech Detection)")
	log.Printf("Database: %s", cfg.DatabaseURL)
	log.Printf("Environment: %s", cfg.Environment)

	// Initialize database
	db, err := database.NewDatabase(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize scanners
	subdomainScanner := recon.NewSubdomainScanner(db, cfg.SubfinderPath, cfg.AmassPath)
	whoisScanner := recon.NewWhoisScanner(db)
	dnsScanner := recon.NewDNSScanner(db)
	techScanner := recon.NewTechScanner(db, cfg.HttpxPath)

	log.Printf("Initialized scanners: Subfinder (%s), Amass (%s), Httpx (%s)",
		cfg.SubfinderPath, cfg.AmassPath, cfg.HttpxPath)

	// Initialize handlers
	reconHandler := handlers.NewReconHandler(db, subdomainScanner, whoisScanner, dnsScanner, techScanner)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Security Scanner - Recon Service",
		ServerHeader: "Recon-Service",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(middleware.Logger())
	app.Use(middleware.CORS())

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "recon-service",
			"version": "1.0.0",
			"tools":   []string{"subfinder", "amass", "whois", "dns", "httpx"},
		})
	})

	// Routes
	api := app.Group("/api")

	// Recon routes
	recons := api.Group("/recon")
	recons.Get("/", reconHandler.ListScans)
	recons.Post("/", reconHandler.CreateScan)
	recons.Get("/:id", reconHandler.GetScan)
	recons.Get("/:id/results", reconHandler.GetScanResults)
	recons.Get("/:id/logs", reconHandler.GetScanLogs)
	recons.Delete("/:id", reconHandler.DeleteScan)
	recons.Post("/:id/cancel", reconHandler.CancelScan)

	// Start server
	log.Printf("Server listening on port %s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
