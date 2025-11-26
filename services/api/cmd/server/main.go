package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/security-scanner/api-service/internal/database"
	"github.com/security-scanner/api-service/internal/handlers"
	"github.com/security-scanner/api-service/internal/scanner"
	"github.com/security-scanner/api-service/pkg/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Println("Starting API Discovery Service...")
	log.Printf("Environment: %s", cfg.Environment)
	log.Printf("Database: %s", maskConnectionString(cfg.DatabaseURL))

	// Connect to database
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to database")

	// Initialize scanner manager
	scannerManager := scanner.NewManager(
		db,
		cfg.KiterunnerPath,
		cfg.ArjunPath,
		cfg.WordlistsPath,
	)
	log.Printf("Initialized scanners: Kiterunner (%s), Arjun (%s)", cfg.KiterunnerPath, cfg.ArjunPath)

	// Initialize handlers
	h := handlers.New(db, scannerManager)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:       "Security Scanner - API Discovery Service",
		CaseSensitive: false,
		StrictRouting: false,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// Health check
	app.Get("/health", h.HealthCheck)

	// API routes
	api := app.Group("/api")

	// API Scans
	apiScans := api.Group("/apiscans")
	apiScans.Get("/", h.ListAPIScans)
	apiScans.Post("/", h.CreateAPIScan)
	apiScans.Get("/:id", h.GetAPIScan)
	apiScans.Delete("/:id", h.DeleteAPIScan)
	apiScans.Post("/:id/cancel", h.CancelAPIScan)
	apiScans.Get("/:id/results", h.GetAPIScanResults)
	apiScans.Get("/:id/logs", h.GetAPIScanLogs)
	apiScans.Get("/:id/stats", h.GetScanStats)
	apiScans.Get("/:id/endpoints", h.GetAPIEndpoints)
	apiScans.Get("/:id/parameters", h.GetAPIParameters)
	apiScans.Get("/:id/graphql", h.GetGraphQLSchemas)
	apiScans.Get("/:id/swagger", h.GetSwaggerSpecs)

	// Start server
	log.Printf("Server starting on port %s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func maskConnectionString(connStr string) string {
	// Simple masking for logs
	if len(connStr) > 30 {
		return connStr[:20] + "..."
	}
	return "***"
}
