package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/security-scanner/web-service/internal/database"
	"github.com/security-scanner/web-service/internal/models"
	"github.com/security-scanner/web-service/internal/scanner"
)

// VulnerabilityHandler handles vulnerability scan requests
type VulnerabilityHandler struct {
	db            *database.Database
	nucleiScanner *scanner.NucleiScanner
}

// NewVulnerabilityHandler creates a new vulnerability handler
func NewVulnerabilityHandler(db *database.Database, nucleiScanner *scanner.NucleiScanner) *VulnerabilityHandler {
	return &VulnerabilityHandler{
		db:            db,
		nucleiScanner: nucleiScanner,
	}
}

// CreateVulnScan creates a new vulnerability scan
func (h *VulnerabilityHandler) CreateVulnScan(c *fiber.Ctx) error {
	var req models.CreateVulnScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate required fields
	if req.Target == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Target is required"})
	}

	// Create scan record
	scanID := uuid.New()
	scan := models.VulnerabilityScan{
		ID:            scanID,
		Name:          req.Name,
		Target:        req.Target,
		Status:        "pending",
		Progress:      0,
		CreatedAt:     time.Now(),
		Templates:     req.Templates,
		Severity:      req.Severity,
		Tags:          req.Tags,
		Configuration: req.Configuration,
	}

	// Insert into database
	query := `INSERT INTO vulnerability_scans
	          (id, name, target, status, progress, created_at, templates, severity, tags, configuration)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := h.db.Pool.Exec(context.Background(), query,
		scan.ID, scan.Name, scan.Target, scan.Status, scan.Progress, scan.CreatedAt,
		scan.Templates, scan.Severity, scan.Tags, scan.Configuration)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Failed to create scan: %v", err)})
	}

	// Start scan in background
	go func() {
		ctx := context.Background()
		if err := h.nucleiScanner.ExecuteVulnScan(ctx, scanID, req.Target, req.Templates, req.Severity, req.Tags); err != nil {
			fmt.Printf("Vulnerability scan %s failed: %v\n", scanID, err)
		}
	}()

	return c.Status(201).JSON(scan)
}

// ListVulnScans returns all vulnerability scans
func (h *VulnerabilityHandler) ListVulnScans(c *fiber.Ctx) error {
	status := c.Query("status", "")

	query := `SELECT id, name, target, status, progress, created_at, started_at, completed_at,
	          error_message, templates, severity, tags, configuration
	          FROM vulnerability_scans`

	args := []interface{}{}
	if status != "" {
		query += " WHERE status = $1"
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC"

	rows, err := h.db.Pool.Query(context.Background(), query, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch scans"})
	}
	defer rows.Close()

	scans := []models.VulnerabilityScan{}
	for rows.Next() {
		var scan models.VulnerabilityScan
		err := rows.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.Status, &scan.Progress,
			&scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage,
			&scan.Templates, &scan.Severity, &scan.Tags, &scan.Configuration)
		if err != nil {
			continue
		}
		scans = append(scans, scan)
	}

	return c.JSON(scans)
}

// GetVulnScan returns a specific vulnerability scan
func (h *VulnerabilityHandler) GetVulnScan(c *fiber.Ctx) error {
	scanID := c.Params("id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	query := `SELECT id, name, target, status, progress, created_at, started_at, completed_at,
	          error_message, templates, severity, tags, configuration
	          FROM vulnerability_scans WHERE id = $1`

	var scan models.VulnerabilityScan
	err = h.db.Pool.QueryRow(context.Background(), query, id).Scan(
		&scan.ID, &scan.Name, &scan.Target, &scan.Status, &scan.Progress,
		&scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage,
		&scan.Templates, &scan.Severity, &scan.Tags, &scan.Configuration)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	return c.JSON(scan)
}

// GetVulnScanResults returns vulnerabilities found in a scan
func (h *VulnerabilityHandler) GetVulnScanResults(c *fiber.Ctx) error {
	scanID := c.Params("id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	query := `SELECT id, scan_id, template_id, template_name, severity, type, host, matched_at,
	          extracted_results, curl_command, request, response, metadata, created_at
	          FROM vulnerabilities WHERE scan_id = $1 ORDER BY created_at DESC`

	rows, err := h.db.Pool.Query(context.Background(), query, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch vulnerabilities"})
	}
	defer rows.Close()

	vulnerabilities := []models.Vulnerability{}
	for rows.Next() {
		var vuln models.Vulnerability
		err := rows.Scan(&vuln.ID, &vuln.ScanID, &vuln.TemplateID, &vuln.TemplateName,
			&vuln.Severity, &vuln.Type, &vuln.Host, &vuln.MatchedAt,
			&vuln.ExtractedResults, &vuln.CURLCommand, &vuln.Request, &vuln.Response,
			&vuln.Metadata, &vuln.CreatedAt)
		if err != nil {
			continue
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return c.JSON(vulnerabilities)
}

// GetVulnScanLogs returns logs for a vulnerability scan
func (h *VulnerabilityHandler) GetVulnScanLogs(c *fiber.Ctx) error {
	scanID := c.Params("id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	query := `SELECT id, scan_id, level, message, created_at
	          FROM vulnerability_scan_logs WHERE scan_id = $1 ORDER BY created_at ASC`

	rows, err := h.db.Pool.Query(context.Background(), query, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch logs"})
	}
	defer rows.Close()

	logs := []models.VulnScanLog{}
	for rows.Next() {
		var log models.VulnScanLog
		err := rows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return c.JSON(logs)
}

// GetVulnScanStats returns statistics for a vulnerability scan
func (h *VulnerabilityHandler) GetVulnScanStats(c *fiber.Ctx) error {
	scanID := c.Params("id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	// Get total count and group by severity
	query := `SELECT
	            COUNT(*) as total,
	            severity,
	            COUNT(*) as count
	          FROM vulnerabilities
	          WHERE scan_id = $1
	          GROUP BY severity`

	rows, err := h.db.Pool.Query(context.Background(), query, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch stats"})
	}
	defer rows.Close()

	stats := models.VulnScanStats{
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}

	for rows.Next() {
		var total, count int
		var severity string
		if err := rows.Scan(&total, &severity, &count); err != nil {
			continue
		}
		stats.Total = total
		stats.BySeverity[severity] = count
	}

	// Get count by type
	typeQuery := `SELECT type, COUNT(*) as count
	              FROM vulnerabilities
	              WHERE scan_id = $1
	              GROUP BY type`

	typeRows, err := h.db.Pool.Query(context.Background(), typeQuery, id)
	if err == nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var vulnType string
			var count int
			if err := typeRows.Scan(&vulnType, &count); err == nil {
				stats.ByType[vulnType] = count
			}
		}
	}

	return c.JSON(stats)
}

// CancelVulnScan cancels a running vulnerability scan
func (h *VulnerabilityHandler) CancelVulnScan(c *fiber.Ctx) error {
	scanID := c.Params("id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	// Check if scan is running
	var status string
	checkQuery := `SELECT status FROM vulnerability_scans WHERE id = $1`
	err = h.db.Pool.QueryRow(context.Background(), checkQuery, id).Scan(&status)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	if status != "running" && status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "Scan is not running"})
	}

	// Update status to cancelled
	updateQuery := `UPDATE vulnerability_scans
	                SET status = 'cancelled', completed_at = NOW()
	                WHERE id = $1`
	_, err = h.db.Pool.Exec(context.Background(), updateQuery, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to cancel scan"})
	}

	return c.JSON(fiber.Map{"message": "Scan cancelled successfully"})
}

// DeleteVulnScan deletes a vulnerability scan and its results
func (h *VulnerabilityHandler) DeleteVulnScan(c *fiber.Ctx) error {
	scanID := c.Params("id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid scan ID"})
	}

	// Delete in transaction
	tx, err := h.db.Pool.Begin(context.Background())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to start transaction"})
	}
	defer tx.Rollback(context.Background())

	// Delete vulnerabilities
	_, err = tx.Exec(context.Background(), `DELETE FROM vulnerabilities WHERE scan_id = $1`, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete vulnerabilities"})
	}

	// Delete logs
	_, err = tx.Exec(context.Background(), `DELETE FROM vulnerability_scan_logs WHERE scan_id = $1`, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete logs"})
	}

	// Delete scan
	_, err = tx.Exec(context.Background(), `DELETE FROM vulnerability_scans WHERE id = $1`, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete scan"})
	}

	if err := tx.Commit(context.Background()); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to commit transaction"})
	}

	return c.JSON(fiber.Map{"message": "Scan deleted successfully"})
}
