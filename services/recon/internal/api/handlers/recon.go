package handlers

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/security-scanner/recon-service/internal/database"
	"github.com/security-scanner/recon-service/internal/models"
	"github.com/security-scanner/recon-service/internal/recon"
)

type ReconHandler struct {
	db               *database.Database
	subdomainScanner *recon.SubdomainScanner
	whoisScanner     *recon.WhoisScanner
	dnsScanner       *recon.DNSScanner
	techScanner      *recon.TechScanner
}

func NewReconHandler(db *database.Database, subdomain *recon.SubdomainScanner, whois *recon.WhoisScanner, dns *recon.DNSScanner, tech *recon.TechScanner) *ReconHandler {
	return &ReconHandler{
		db:               db,
		subdomainScanner: subdomain,
		whoisScanner:     whois,
		dnsScanner:       dns,
		techScanner:      tech,
	}
}

// ListScans returns all recon scans
func (h *ReconHandler) ListScans(c *fiber.Ctx) error {
	scanType := c.Query("type", "")
	status := c.Query("status", "")

	scans, err := h.db.ListScans(scanType, status)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if scans == nil {
		scans = []models.ReconScan{}
	}

	return c.JSON(scans)
}

// CreateScan creates a new recon scan
func (h *ReconHandler) CreateScan(c *fiber.Ctx) error {
	var req models.CreateReconRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Target == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Target is required"})
	}

	if req.ScanType == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Scan type is required"})
	}

	// Validate scan type
	validTypes := map[string]bool{"subdomain": true, "whois": true, "dns": true, "tech": true}
	if !validTypes[req.ScanType] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan type. Valid types: subdomain, whois, dns, tech"})
	}

	scan := &models.ReconScan{
		ID:        uuid.New(),
		Name:      req.Name,
		Target:    req.Target,
		ScanType:  req.ScanType,
		Status:    "pending",
		Progress:  0,
		CreatedAt: time.Now(),
		Options:   req.Options,
	}

	if scan.Name == "" {
		scan.Name = req.ScanType + " - " + req.Target
	}

	if err := h.db.CreateScan(scan); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// Start scan in background
	go h.runScan(scan)

	return c.Status(201).JSON(scan)
}

func (h *ReconHandler) runScan(scan *models.ReconScan) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var err error
	switch scan.ScanType {
	case "subdomain":
		err = h.subdomainScanner.Scan(ctx, scan)
	case "whois":
		err = h.whoisScanner.Scan(ctx, scan)
	case "dns":
		err = h.dnsScanner.Scan(ctx, scan)
	case "tech":
		err = h.techScanner.Scan(ctx, scan)
	}

	if err != nil {
		errMsg := err.Error()
		h.db.UpdateScanStatus(scan.ID, "failed", 0, &errMsg)
	}
}

// GetScan returns a single scan
func (h *ReconHandler) GetScan(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	scan, err := h.db.GetScan(id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	return c.JSON(scan)
}

// GetScanResults returns the results for a scan
func (h *ReconHandler) GetScanResults(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	scan, err := h.db.GetScan(id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	result := fiber.Map{
		"scan": scan,
	}

	switch scan.ScanType {
	case "subdomain":
		subdomains, _ := h.db.GetSubdomainResults(id)
		if subdomains == nil {
			subdomains = []models.SubdomainResult{}
		}
		result["subdomains"] = subdomains
		result["total"] = len(subdomains)

	case "whois":
		whois, _ := h.db.GetWhoisResult(id)
		result["whois"] = whois

	case "dns":
		dns, _ := h.db.GetDNSResult(id)
		result["dns"] = dns

	case "tech":
		tech, _ := h.db.GetTechResults(id)
		if tech == nil {
			tech = []models.TechResult{}
		}
		result["technologies"] = tech
	}

	return c.JSON(result)
}

// GetScanLogs returns logs for a scan
func (h *ReconHandler) GetScanLogs(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	logs, err := h.db.GetLogs(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if logs == nil {
		logs = []models.ReconLog{}
	}

	return c.JSON(logs)
}

// DeleteScan deletes a scan
func (h *ReconHandler) DeleteScan(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	if err := h.db.DeleteScan(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Scan deleted"})
}

// CancelScan cancels a running scan
func (h *ReconHandler) CancelScan(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	scan, err := h.db.GetScan(id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	if scan.Status != "running" && scan.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "Scan is not running"})
	}

	if err := h.db.UpdateScanStatus(id, "cancelled", scan.Progress, nil); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Scan cancelled"})
}
