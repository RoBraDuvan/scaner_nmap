package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/security-scanner/cloud-service/internal/database"
	"github.com/security-scanner/cloud-service/internal/handlers"
	"github.com/security-scanner/cloud-service/internal/scanner"
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
	trivyPath := getEnv("TRIVY_PATH", "/usr/local/bin/trivy")
	prowlerPath := getEnv("PROWLER_PATH", "/usr/local/bin/prowler")
	scoutsuitePath := getEnv("SCOUTSUITE_PATH", "/usr/local/bin/scout")

	// Connect to database
	db, err := database.New(dbHost, dbPort, dbUser, dbPassword, dbName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("Connected to database successfully")

	// Create scan manager
	manager := scanner.NewScanManager(db, trivyPath, prowlerPath, scoutsuitePath)

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
		// Cloud Scans
		cloudScans := api.Group("/cloudscans")
		{
			cloudScans.GET("/", h.GetScans)
			cloudScans.GET("/:id", h.GetScan)
			cloudScans.POST("/", h.CreateScan)
			cloudScans.DELETE("/:id", h.DeleteScan)
			cloudScans.POST("/:id/cancel", h.CancelScan)
			cloudScans.GET("/:id/findings", h.GetScanFindings)
			cloudScans.GET("/:id/vulnerabilities", h.GetScanVulnerabilities)
			cloudScans.GET("/:id/results", h.GetScanResults)
			cloudScans.GET("/:id/logs", h.GetScanLogs)
		}

		// Cloud Credentials Management
		credentials := api.Group("/credentials")
		{
			credentials.GET("/", h.GetCredentialsStatus)
			// AWS
			credentials.GET("/aws", h.GetAWSCredentialsStatus)
			credentials.POST("/aws", h.SetAWSCredentials)
			credentials.DELETE("/aws", h.DeleteAWSCredentials)
			// GCP
			credentials.GET("/gcp", h.GetGCPCredentialsStatus)
			credentials.POST("/gcp", h.SetGCPCredentials)
			credentials.POST("/gcp/upload", h.UploadGCPCredentials)
			credentials.DELETE("/gcp", h.DeleteGCPCredentials)
			// Azure
			credentials.GET("/azure", h.GetAzureCredentialsStatus)
			credentials.POST("/azure", h.SetAzureCredentials)
			credentials.DELETE("/azure", h.DeleteAzureCredentials)
		}

		// Tools info
		api.GET("/tools", h.GetAvailableTools)
	}

	// Start server
	port := getEnv("PORT", "8006")
	log.Printf("Cloud Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
