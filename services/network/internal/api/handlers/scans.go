package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
	"github.com/nmap-scanner/backend-go/internal/scanner"
)

type ScanHandler struct {
	db             *database.Database
	nmapScanner    *scanner.Scanner
	masscanScanner *scanner.MasscanScanner
	dnsScanner     *scanner.DNSScanner
}

func NewScanHandler(db *database.Database, nmapScanner *scanner.Scanner, masscanScanner *scanner.MasscanScanner, dnsScanner *scanner.DNSScanner) *ScanHandler {
	return &ScanHandler{
		db:             db,
		nmapScanner:    nmapScanner,
		masscanScanner: masscanScanner,
		dnsScanner:     dnsScanner,
	}
}

// determineScannerType returns the scanner name based on scan_type
func determineScannerType(scanType string) string {
	scanTypeLower := strings.ToLower(scanType)
	switch {
	case strings.HasPrefix(scanTypeLower, "masscan"):
		return "masscan"
	case strings.HasPrefix(scanTypeLower, "dns"):
		return "dns"
	default:
		return "nmap"
	}
}

// cleanTarget extracts hostname from URL if needed
func cleanTarget(target string) string {
	target = strings.TrimSpace(target)

	// If it looks like a URL, extract the hostname
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}

	// Remove trailing slashes
	target = strings.TrimSuffix(target, "/")

	return target
}

// CreateScan creates and starts a new scan
func (h *ScanHandler) CreateScan(c *fiber.Ctx) error {
	var req models.CreateScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate required fields
	if req.Name == "" || req.Target == "" || req.ScanType == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name, target, and scan_type are required"})
	}

	// Clean the target (extract hostname from URL if needed)
	req.Target = cleanTarget(req.Target)

	// Determine scanner type based on scan_type
	scanner := determineScannerType(req.ScanType)

	// Create scan record
	scanID := uuid.New()
	query := `
		INSERT INTO scans (id, name, target, scan_type, scanner, status, progress, created_at, configuration)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, name, target, scan_type, scanner, status, progress, created_at
	`

	var scan models.Scan
	err := h.db.Pool.QueryRow(context.Background(), query,
		scanID, req.Name, req.Target, req.ScanType, scanner, "pending", 0, time.Now(), req.Configuration,
	).Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Scanner, &scan.Status, &scan.Progress, &scan.CreatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan"})
	}

	// Route to appropriate scanner based on scan type
	go h.executeScan(scanID, req)

	return c.Status(201).JSON(scan)
}

// executeScan routes the scan to the appropriate scanner
func (h *ScanHandler) executeScan(scanID uuid.UUID, req models.CreateScanRequest) {
	ctx := context.Background()

	// Determine scanner type based on scan_type prefix or name
	scanType := strings.ToLower(req.ScanType)

	switch {
	// Masscan types
	case strings.HasPrefix(scanType, "masscan"):
		h.executeMasscanScan(ctx, scanID, req)

	// DNS scan types
	case strings.HasPrefix(scanType, "dns"):
		h.executeDNSScan(ctx, scanID, req)

	// Default to Nmap for all other types
	default:
		h.executeNmapScan(ctx, scanID, req)
	}
}

// executeNmapScan runs an Nmap scan
func (h *ScanHandler) executeNmapScan(ctx context.Context, scanID uuid.UUID, req models.CreateScanRequest) {
	nmapArgs := ""
	if req.NmapArguments != nil {
		nmapArgs = *req.NmapArguments
	} else {
		templates := h.nmapScanner.GetScanTemplates()
		if template, ok := templates[req.ScanType]; ok {
			nmapArgs = template["arguments"]
		} else {
			// Default to quick scan
			nmapArgs = "-F -T4"
		}
	}

	if err := h.nmapScanner.ExecuteScan(ctx, scanID, req.Target, nmapArgs); err != nil {
		fmt.Printf("Nmap scan %s failed: %v\n", scanID, err)
	}
}

// executeMasscanScan runs a Masscan scan
func (h *ScanHandler) executeMasscanScan(ctx context.Context, scanID uuid.UUID, req models.CreateScanRequest) {
	ports := "1-65535"
	rate := 10000

	// Get configuration from request or use template defaults
	if req.Configuration != nil {
		if p, ok := req.Configuration["ports"].(string); ok {
			ports = p
		}
		if r, ok := req.Configuration["rate"].(float64); ok {
			rate = int(r)
		}
		if r, ok := req.Configuration["rate"].(string); ok {
			if parsed, err := strconv.Atoi(r); err == nil {
				rate = parsed
			}
		}
	} else {
		// Use template defaults
		templates := h.masscanScanner.GetTemplates()
		if template, ok := templates[req.ScanType]; ok {
			if p, ok := template["ports"].(string); ok {
				ports = p
			}
			if r, ok := template["rate"].(int); ok {
				rate = r
			}
		}
	}

	if err := h.masscanScanner.ExecuteScan(ctx, scanID, req.Target, ports, rate); err != nil {
		fmt.Printf("Masscan scan %s failed: %v\n", scanID, err)
	}
}

// executeDNSScan runs a DNS scan
func (h *ScanHandler) executeDNSScan(ctx context.Context, scanID uuid.UUID, req models.CreateScanRequest) {
	if err := h.dnsScanner.ExecuteScan(ctx, scanID, req.Target, req.ScanType); err != nil {
		fmt.Printf("DNS scan %s failed: %v\n", scanID, err)
	}
}

// ListScans returns all scans
func (h *ScanHandler) ListScans(c *fiber.Ctx) error {
	status := c.Query("status", "")
	scanner := c.Query("scanner", "")

	query := `
		SELECT id, name, target, scan_type, scanner, status, progress, created_at, started_at, completed_at, error_message
		FROM scans
	`
	args := []interface{}{}
	conditions := []string{}
	argIndex := 1

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, status)
		argIndex++
	}

	if scanner != "" {
		conditions = append(conditions, fmt.Sprintf("scanner = $%d", argIndex))
		args = append(args, scanner)
		argIndex++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := h.db.Pool.Query(context.Background(), query, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch scans"})
	}
	defer rows.Close()

	scans := []models.Scan{}
	for rows.Next() {
		var scan models.Scan
		var scanner *string
		err := rows.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scanner, &scan.Status,
			&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage)
		if err != nil {
			continue
		}
		// Default to nmap if scanner is null (for old records)
		if scanner != nil {
			scan.Scanner = *scanner
		} else {
			scan.Scanner = determineScannerType(scan.ScanType)
		}
		scans = append(scans, scan)
	}

	return c.JSON(scans)
}

// GetScan returns a specific scan by ID
func (h *ScanHandler) GetScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, name, target, scan_type, scanner, status, progress, created_at, started_at, completed_at, error_message
		FROM scans
		WHERE id = $1
	`

	var scan models.Scan
	var scanner *string
	err := h.db.Pool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scanner, &scan.Status,
		&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage,
	)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	// Default to nmap if scanner is null (for old records)
	if scanner != nil {
		scan.Scanner = *scanner
	} else {
		scan.Scanner = determineScannerType(scan.ScanType)
	}

	return c.JSON(scan)
}

// GetScanResults returns results for a specific scan
func (h *ScanHandler) GetScanResults(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, scan_id, host, hostname, state, ports, os_detection, services, mac_address, mac_vendor, created_at
		FROM scan_results
		WHERE scan_id = $1
	`

	rows, err := h.db.Pool.Query(context.Background(), query, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch results"})
	}
	defer rows.Close()

	results := []models.ScanResult{}
	for rows.Next() {
		var result models.ScanResult
		err := rows.Scan(&result.ID, &result.ScanID, &result.Host, &result.Hostname, &result.State,
			&result.Ports, &result.OSDetection, &result.Services, &result.MacAddress, &result.MacVendor, &result.CreatedAt)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	return c.JSON(results)
}

// GetScanLogs returns logs for a specific scan
func (h *ScanHandler) GetScanLogs(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, scan_id, level, message, created_at
		FROM scan_logs
		WHERE scan_id = $1
		ORDER BY created_at ASC
	`

	rows, err := h.db.Pool.Query(context.Background(), query, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch logs"})
	}
	defer rows.Close()

	logs := []models.ScanLog{}
	for rows.Next() {
		var log models.ScanLog
		err := rows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return c.JSON(logs)
}

// DeleteScan deletes a scan and its related data
func (h *ScanHandler) DeleteScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	// Check if scan exists and get its status and type
	var status, scanType string
	checkQuery := `SELECT status, scan_type FROM scans WHERE id = $1`
	err := h.db.Pool.QueryRow(context.Background(), checkQuery, scanID).Scan(&status, &scanType)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	// If scan is running, cancel it first
	if status == "running" {
		h.cancelScanByType(scanID, scanType)
	}

	// Delete scan (cascade will delete results and logs)
	query := `DELETE FROM scans WHERE id = $1`
	result, err := h.db.Pool.Exec(context.Background(), query, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete scan"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	return c.JSON(fiber.Map{"message": "Scan deleted successfully"})
}

// CancelScan cancels a running scan
func (h *ScanHandler) CancelScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	// Check if scan exists and is running
	var status, scanType string
	checkQuery := `SELECT status, scan_type FROM scans WHERE id = $1`
	err := h.db.Pool.QueryRow(context.Background(), checkQuery, scanID).Scan(&status, &scanType)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	if status != "running" && status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Cannot cancel scan with status: %s", status)})
	}

	// Cancel the scan based on type
	h.cancelScanByType(scanID, scanType)

	// Update status to cancelled
	updateQuery := `UPDATE scans SET status = 'cancelled', completed_at = NOW() WHERE id = $1`
	_, err = h.db.Pool.Exec(context.Background(), updateQuery, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update scan status"})
	}

	return c.JSON(fiber.Map{"message": "Scan cancelled successfully"})
}

// cancelScanByType cancels a scan using the appropriate scanner
func (h *ScanHandler) cancelScanByType(scanID string, scanType string) {
	scanTypeLower := strings.ToLower(scanType)

	switch {
	case strings.HasPrefix(scanTypeLower, "masscan"):
		h.masscanScanner.CancelScan(scanID)
	case strings.HasPrefix(scanTypeLower, "dns"):
		h.dnsScanner.CancelScan(scanID)
	default:
		h.nmapScanner.CancelScan(scanID)
	}
}

// GetAllTemplates returns all available scan templates from all scanners
func (h *ScanHandler) GetAllTemplates(c *fiber.Ctx) error {
	templates := make(map[string]interface{})

	// Nmap templates
	for key, tmpl := range h.nmapScanner.GetScanTemplates() {
		templates[key] = map[string]interface{}{
			"name":        tmpl["name"],
			"description": tmpl["description"],
			"scanner":     "nmap",
			"arguments":   tmpl["arguments"],
		}
	}

	// Masscan templates
	for key, tmpl := range h.masscanScanner.GetTemplates() {
		templates[key] = map[string]interface{}{
			"name":        tmpl["name"],
			"description": tmpl["description"],
			"scanner":     "masscan",
			"ports":       tmpl["ports"],
			"rate":        tmpl["rate"],
		}
	}

	// DNS templates
	for key, tmpl := range h.dnsScanner.GetTemplates() {
		templates[key] = map[string]interface{}{
			"name":        tmpl["name"],
			"description": tmpl["description"],
			"scanner":     "dns",
			"scan_type":   tmpl["scan_type"],
		}
	}

	return c.JSON(templates)
}
