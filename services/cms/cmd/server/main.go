package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/handlers"
	"github.com/security-scanner/cms-service/internal/scanner"
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Database configuration
	dbHost := getEnv("DB_HOST", "database")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "scanner")
	dbPassword := getEnv("DB_PASSWORD", "scanner123")
	dbName := getEnv("DB_NAME", "scanner_db")

	// Tool paths
	whatwebPath := getEnv("WHATWEB_PATH", "whatweb")
	cmseekPath := getEnv("CMSEEK_PATH", "cmseek")
	wpscanPath := getEnv("WPSCAN_PATH", "wpscan")
	joomscanPath := getEnv("JOOMSCAN_PATH", "joomscan")
	droopescanPath := getEnv("DROOPESCAN_PATH", "droopescan")

	// Connect to database
	db, err := database.New(dbHost, dbPort, dbUser, dbPassword, dbName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("Connected to database successfully")

	// Create scan manager
	manager := scanner.NewScanManager(db, whatwebPath, cmseekPath, wpscanPath, joomscanPath, droopescanPath)

	// Create handlers
	h := handlers.NewHandler(db, manager)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Health check
	r.GET("/health", h.HealthCheck)

	// API routes
	api := r.Group("/api")
	{
		// CMS Scans
		cmsScans := api.Group("/cmsscans")
		{
			cmsScans.GET("/", h.GetScans)
			cmsScans.GET("/:id", h.GetScan)
			cmsScans.POST("/", h.CreateScan)
			cmsScans.DELETE("/:id", h.DeleteScan)
			cmsScans.POST("/:id/cancel", h.CancelScan)
			cmsScans.GET("/:id/results", h.GetScanResults)
			cmsScans.GET("/:id/technologies", h.GetScanTechnologies)
			cmsScans.GET("/:id/logs", h.GetScanLogs)
		}

		// Tools info
		api.GET("/tools", h.GetAvailableTools)
	}

	// Start server
	port := getEnv("PORT", "8005")
	log.Printf("CMS Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
