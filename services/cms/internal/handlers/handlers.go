package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
	"github.com/security-scanner/cms-service/internal/scanner"
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

// GetScans returns all CMS scans
func (h *Handler) GetScans(c *gin.Context) {
	scans, err := h.db.GetAllScans()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scans"})
		return
	}
	if scans == nil {
		scans = []models.CMSScan{}
	}
	c.JSON(http.StatusOK, scans)
}

// GetScan returns a single CMS scan
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

// CreateScan creates a new CMS scan
func (h *Handler) CreateScan(c *gin.Context) {
	var req models.CreateCMSScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate scan type
	validTypes := map[string]bool{"whatweb": true, "cmseek": true, "wpscan": true, "full": true}
	if !validTypes[req.ScanType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan type. Must be: whatweb, cmseek, wpscan, or full"})
		return
	}

	scan := &models.CMSScan{
		ID:        uuid.New(),
		Name:      req.Name,
		Target:    req.Target,
		ScanType:  req.ScanType,
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

// DeleteScan deletes a CMS scan
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

// GetScanResults returns CMS detection results
func (h *Handler) GetScanResults(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	// Get CMS results
	cmsResults, err := h.db.GetCMSResults(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch CMS results"})
		return
	}
	if cmsResults == nil {
		cmsResults = []models.CMSResult{}
	}

	// Get technologies
	techs, err := h.db.GetTechnologies(id)
	if err != nil {
		techs = []models.Technology{}
	}

	// Get WPScan results
	wpResults, err := h.db.GetWPScanResults(id)
	if err != nil {
		wpResults = []models.WPScanResult{}
	}

	c.JSON(http.StatusOK, gin.H{
		"cms":          cmsResults,
		"technologies": techs,
		"wpscan":       wpResults,
	})
}

// GetScanTechnologies returns all detected technologies
func (h *Handler) GetScanTechnologies(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	techs, err := h.db.GetTechnologies(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch technologies"})
		return
	}
	if techs == nil {
		techs = []models.Technology{}
	}

	c.JSON(http.StatusOK, techs)
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

// HealthCheck returns service health
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "cms-service",
	})
}
