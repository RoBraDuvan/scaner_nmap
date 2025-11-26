package handlers

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/security-scanner/api-service/internal/database"
	"github.com/security-scanner/api-service/internal/models"
	"github.com/security-scanner/api-service/internal/scanner"
)

type Handlers struct {
	db      *database.Database
	scanner *scanner.Manager
}

func New(db *database.Database, scannerManager *scanner.Manager) *Handlers {
	return &Handlers{
		db:      db,
		scanner: scannerManager,
	}
}

// CreateAPIScan creates a new API scan
func (h *Handlers) CreateAPIScan(c *fiber.Ctx) error {
	var req models.CreateAPIScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate
	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Name is required"})
	}
	if req.Target == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Target is required"})
	}
	if req.ScanType == "" {
		return c.Status(400).JSON(fiber.Map{"error": "scan_type is required"})
	}

	// Validate scan type
	validTypes := map[string]bool{
		"kiterunner": true,
		"arjun":      true,
		"graphql":    true,
		"swagger":    true,
		"full":       true,
	}
	if !validTypes[req.ScanType] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan_type. Must be one of: kiterunner, arjun, graphql, swagger, full"})
	}

	scan := &models.APIScan{
		ID:        uuid.New(),
		Name:      req.Name,
		Target:    req.Target,
		ScanType:  req.ScanType,
		Status:    "pending",
		Progress:  0,
		Config:    req.Config,
		CreatedAt: time.Now(),
	}

	if err := h.db.CreateAPIScan(scan); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan: " + err.Error()})
	}

	// Start scan
	if err := h.scanner.StartScan(scan); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to start scan: " + err.Error()})
	}

	return c.Status(201).JSON(scan)
}

// ListAPIScans lists all API scans
func (h *Handlers) ListAPIScans(c *fiber.Ctx) error {
	scanType := c.Query("type", "")
	status := c.Query("status", "")
	limit := c.QueryInt("limit", 100)

	scans, err := h.db.ListAPIScans(scanType, status, limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to list scans: " + err.Error()})
	}

	if scans == nil {
		scans = []models.APIScan{}
	}

	return c.JSON(scans)
}

// GetAPIScan gets a specific API scan
func (h *Handlers) GetAPIScan(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	scan, err := h.db.GetAPIScan(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get scan: " + err.Error()})
	}
	if scan == nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	return c.JSON(scan)
}

// GetAPIScanResults gets scan results
func (h *Handlers) GetAPIScanResults(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	results, err := h.db.GetAPIScanResults(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get results: " + err.Error()})
	}

	if results == nil {
		results = &models.APIScanResults{
			Endpoints:  []models.APIEndpoint{},
			Parameters: []models.APIParameter{},
		}
	}

	return c.JSON(results)
}

// GetAPIScanLogs gets scan logs
func (h *Handlers) GetAPIScanLogs(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	logs, err := h.db.GetLogs(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get logs: " + err.Error()})
	}

	if logs == nil {
		logs = []models.ScanLog{}
	}

	return c.JSON(logs)
}

// CancelAPIScan cancels a running scan
func (h *Handlers) CancelAPIScan(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	// Check if scan exists
	scan, err := h.db.GetAPIScan(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get scan"})
	}
	if scan == nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	if scan.Status != "running" && scan.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "Scan is not running"})
	}

	// Cancel scan
	h.scanner.CancelScan(id.String())
	h.db.UpdateAPIScanStatus(id, "cancelled", scan.Progress, nil)

	return c.JSON(fiber.Map{"message": "Scan cancelled"})
}

// DeleteAPIScan deletes a scan
func (h *Handlers) DeleteAPIScan(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	// Check if scan exists
	scan, err := h.db.GetAPIScan(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get scan"})
	}
	if scan == nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	// Cancel if running
	if scan.Status == "running" {
		h.scanner.CancelScan(id.String())
	}

	// Delete scan
	if err := h.db.DeleteAPIScan(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete scan: " + err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Scan deleted"})
}

// GetAPIEndpoints gets endpoints for a scan
func (h *Handlers) GetAPIEndpoints(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	endpoints, err := h.db.GetAPIEndpoints(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get endpoints: " + err.Error()})
	}

	if endpoints == nil {
		endpoints = []models.APIEndpoint{}
	}

	return c.JSON(endpoints)
}

// GetAPIParameters gets parameters for a scan
func (h *Handlers) GetAPIParameters(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	params, err := h.db.GetAPIParameters(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get parameters: " + err.Error()})
	}

	if params == nil {
		params = []models.APIParameter{}
	}

	return c.JSON(params)
}

// GetGraphQLSchemas gets GraphQL schemas for a scan
func (h *Handlers) GetGraphQLSchemas(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	schemas, err := h.db.GetGraphQLSchemas(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get schemas: " + err.Error()})
	}

	if schemas == nil {
		schemas = []models.GraphQLSchema{}
	}

	return c.JSON(schemas)
}

// GetSwaggerSpecs gets Swagger specs for a scan
func (h *Handlers) GetSwaggerSpecs(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	specs, err := h.db.GetSwaggerSpecs(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get specs: " + err.Error()})
	}

	if specs == nil {
		specs = []models.SwaggerSpec{}
	}

	return c.JSON(specs)
}

// GetScanStats returns statistics for API scans
func (h *Handlers) GetScanStats(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	results, err := h.db.GetAPIScanResults(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get results"})
	}

	stats := fiber.Map{
		"total_endpoints":  0,
		"total_parameters": 0,
		"graphql_schemas":  0,
		"swagger_specs":    0,
		"endpoints_by_method": map[string]int{},
		"params_by_type":      map[string]int{},
	}

	if results != nil {
		stats["total_endpoints"] = len(results.Endpoints)
		stats["total_parameters"] = len(results.Parameters)
		stats["graphql_schemas"] = len(results.GraphQL)
		stats["swagger_specs"] = len(results.Swagger)

		// Count by method
		methodCounts := make(map[string]int)
		for _, e := range results.Endpoints {
			methodCounts[e.Method]++
		}
		stats["endpoints_by_method"] = methodCounts

		// Count by param type
		paramCounts := make(map[string]int)
		for _, p := range results.Parameters {
			paramCounts[p.ParamType]++
		}
		stats["params_by_type"] = paramCounts
	}

	return c.JSON(stats)
}

// HealthCheck returns service health
func (h *Handlers) HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "healthy",
		"service": "api-service",
		"time":    time.Now().Format(time.RFC3339),
	})
}

// Suppress unused import warning
var _ = json.Marshal
