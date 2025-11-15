package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
	"github.com/nmap-scanner/backend-go/internal/scanner"
)

type ScanHandler struct {
	db      *database.Database
	scanner *scanner.Scanner
}

func NewScanHandler(db *database.Database, scanner *scanner.Scanner) *ScanHandler {
	return &ScanHandler{
		db:      db,
		scanner: scanner,
	}
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

	// Determine nmap arguments
	nmapArgs := ""
	if req.NmapArguments != nil {
		nmapArgs = *req.NmapArguments
	} else {
		templates := h.scanner.GetScanTemplates()
		if template, ok := templates[req.ScanType]; ok {
			nmapArgs = template["arguments"]
		} else {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Unknown scan type: %s", req.ScanType)})
		}
	}

	// Create scan record
	scanID := uuid.New()
	query := `
		INSERT INTO scans (id, name, target, scan_type, status, progress, created_at, configuration)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, target, scan_type, status, progress, created_at
	`

	var scan models.Scan
	err := h.db.Pool.QueryRow(context.Background(), query,
		scanID, req.Name, req.Target, req.ScanType, "pending", 0, time.Now(), req.Configuration,
	).Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status, &scan.Progress, &scan.CreatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan"})
	}

	// Start scan in background
	go func() {
		ctx := context.Background()
		if err := h.scanner.ExecuteScan(ctx, scanID, req.Target, nmapArgs); err != nil {
			fmt.Printf("Scan %s failed: %v\n", scanID, err)
		}
	}()

	return c.Status(201).JSON(scan)
}

// ListScans returns all scans
func (h *ScanHandler) ListScans(c *fiber.Ctx) error {
	query := `
		SELECT id, name, target, scan_type, status, progress, created_at, started_at, completed_at, error_message
		FROM scans
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := h.db.Pool.Query(context.Background(), query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch scans"})
	}
	defer rows.Close()

	scans := []models.Scan{}
	for rows.Next() {
		var scan models.Scan
		err := rows.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status,
			&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage)
		if err != nil {
			continue
		}
		scans = append(scans, scan)
	}

	return c.JSON(scans)
}

// GetScan returns a specific scan by ID
func (h *ScanHandler) GetScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, name, target, scan_type, status, progress, created_at, started_at, completed_at, error_message
		FROM scans
		WHERE id = $1
	`

	var scan models.Scan
	err := h.db.Pool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status,
		&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage,
	)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
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
