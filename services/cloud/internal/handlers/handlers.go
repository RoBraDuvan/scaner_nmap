package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/security-scanner/cloud-service/internal/database"
	"github.com/security-scanner/cloud-service/internal/models"
	"github.com/security-scanner/cloud-service/internal/scanner"
)

type Handler struct {
	db      *database.Database
	manager *scanner.ScanManager
}

func NewHandler(db *database.Database, manager *scanner.ScanManager) *Handler {
	return &Handler{
		db:      db,
		manager: manager,
	}
}

// GetScans returns all cloud scans
func (h *Handler) GetScans(c *gin.Context) {
	// Optional filter by provider
	provider := c.Query("provider")

	scans, err := h.db.GetAllScans()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scans"})
		return
	}

	// Filter by provider if specified
	if provider != "" {
		var filtered []models.CloudScan
		for _, scan := range scans {
			if scan.Provider == provider {
				filtered = append(filtered, scan)
			}
		}
		scans = filtered
	}

	if scans == nil {
		scans = []models.CloudScan{}
	}
	c.JSON(http.StatusOK, scans)
}

// GetScan returns a single cloud scan
func (h *Handler) GetScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	scan, err := h.db.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// CreateScan creates a new cloud security scan
func (h *Handler) CreateScan(c *gin.Context) {
	var req models.CreateCloudScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate provider
	validProviders := map[string]bool{
		"aws":    true,
		"azure":  true,
		"gcp":    true,
		"docker": true,
	}
	if !validProviders[req.Provider] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider. Must be: aws, azure, gcp, or docker"})
		return
	}

	// Validate scan type
	validTypes := map[string]bool{
		"trivy":      true,
		"prowler":    true,
		"scoutsuite": true,
		"image":      true,
		"config":     true,
		"full":       true,
	}
	if !validTypes[req.ScanType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan type. Must be: trivy, prowler, scoutsuite, image, config, or full"})
		return
	}

	scan := &models.CloudScan{
		ID:        uuid.New(),
		Name:      req.Name,
		Provider:  req.Provider,
		ScanType:  req.ScanType,
		Target:    req.Target,
		Status:    "pending",
		Progress:  0,
		Config:    req.Config,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := h.db.CreateScan(scan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan"})
		return
	}

	// Start the scan
	h.manager.StartScan(scan)

	c.JSON(http.StatusCreated, scan)
}

// DeleteScan deletes a cloud scan
func (h *Handler) DeleteScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	// Cancel if running
	h.manager.CancelScan(id)

	if err := h.db.DeleteScan(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scan deleted"})
}

// CancelScan cancels a running scan
func (h *Handler) CancelScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	if !h.manager.CancelScan(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scan is not running"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scan cancelled"})
}

// GetScanFindings returns security findings for a scan
func (h *Handler) GetScanFindings(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	// Optional severity filter
	severity := c.Query("severity")

	findings, err := h.db.GetFindings(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch findings"})
		return
	}

	// Filter by severity if specified
	if severity != "" {
		var filtered []models.CloudFinding
		for _, f := range findings {
			if f.Severity == severity {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	if findings == nil {
		findings = []models.CloudFinding{}
	}
	c.JSON(http.StatusOK, findings)
}

// GetScanVulnerabilities returns vulnerabilities for a scan
func (h *Handler) GetScanVulnerabilities(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	vulns, err := h.db.GetVulnerabilities(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch vulnerabilities"})
		return
	}

	if vulns == nil {
		vulns = []models.VulnerabilityResult{}
	}
	c.JSON(http.StatusOK, vulns)
}

// GetScanResults returns combined results for a scan
func (h *Handler) GetScanResults(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	findings, _ := h.db.GetFindings(id)
	vulns, _ := h.db.GetVulnerabilities(id)
	summary := h.db.CalculateSummary(id)

	if findings == nil {
		findings = []models.CloudFinding{}
	}
	if vulns == nil {
		vulns = []models.VulnerabilityResult{}
	}

	c.JSON(http.StatusOK, gin.H{
		"findings":        findings,
		"vulnerabilities": vulns,
		"summary":         summary,
	})
}

// GetScanLogs returns scan logs
func (h *Handler) GetScanLogs(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	logs, err := h.db.GetLogs(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch logs"})
		return
	}

	if logs == nil {
		logs = []models.ScanLog{}
	}
	c.JSON(http.StatusOK, logs)
}

// GetAvailableTools returns available scanning tools
func (h *Handler) GetAvailableTools(c *gin.Context) {
	tools := h.manager.GetAvailableTools()
	c.JSON(http.StatusOK, gin.H{
		"tools": tools,
	})
}

// HealthCheck returns service health
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "cloud-service",
	})
}
