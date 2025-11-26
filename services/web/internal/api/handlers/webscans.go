package handlers

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/security-scanner/web-service/internal/database"
	"github.com/security-scanner/web-service/internal/models"
	"github.com/security-scanner/web-service/internal/scanner"
)

// WebScanHandler handles web scanning requests (ffuf, gowitness, testssl)
type WebScanHandler struct {
	db               *database.Database
	ffufScanner      *scanner.FfufScanner
	gowitnessScanner *scanner.GowitnessScanner
	testsslScanner   *scanner.TestsslScanner
}

// NewWebScanHandler creates a new web scan handler
func NewWebScanHandler(
	db *database.Database,
	ffufScanner *scanner.FfufScanner,
	gowitnessScanner *scanner.GowitnessScanner,
	testsslScanner *scanner.TestsslScanner,
) *WebScanHandler {
	return &WebScanHandler{
		db:               db,
		ffufScanner:      ffufScanner,
		gowitnessScanner: gowitnessScanner,
		testsslScanner:   testsslScanner,
	}
}

// ListWebScans returns all web scans
func (h *WebScanHandler) ListWebScans(c *fiber.Ctx) error {
	// Pagination
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	tool := c.Query("tool", "")
	status := c.Query("status", "")

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	query := `
		SELECT id, name, target, tool, status, progress, created_at, started_at, completed_at, error_message
		FROM web_scans
	`
	args := []interface{}{}
	argIndex := 1
	conditions := []string{}

	if tool != "" {
		conditions = append(conditions, "tool = $"+strconv.Itoa(argIndex))
		args = append(args, tool)
		argIndex++
	}

	if status != "" {
		conditions = append(conditions, "status = $"+strconv.Itoa(argIndex))
		args = append(args, status)
		argIndex++
	}

	if len(conditions) > 0 {
		query += " WHERE " + conditions[0]
		for i := 1; i < len(conditions); i++ {
			query += " AND " + conditions[i]
		}
	}

	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(argIndex) + " OFFSET $" + strconv.Itoa(argIndex+1)
	args = append(args, limit, offset)

	rows, err := h.db.Pool.Query(context.Background(), query, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch scans"})
	}
	defer rows.Close()

	scans := []models.WebScan{}
	for rows.Next() {
		var scan models.WebScan
		err := rows.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.Tool, &scan.Status,
			&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage)
		if err != nil {
			continue
		}
		scans = append(scans, scan)
	}

	return c.JSON(scans)
}

// GetWebScan returns a specific web scan
func (h *WebScanHandler) GetWebScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, name, target, tool, status, progress, created_at, started_at, completed_at, error_message, configuration
		FROM web_scans WHERE id = $1
	`

	var scan models.WebScan
	var configJSON []byte
	err := h.db.Pool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID, &scan.Name, &scan.Target, &scan.Tool, &scan.Status,
		&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt,
		&scan.ErrorMessage, &configJSON)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	if configJSON != nil {
		json.Unmarshal(configJSON, &scan.Configuration)
	}

	return c.JSON(scan)
}

// CreateFfufScan creates a new ffuf scan
func (h *WebScanHandler) CreateFfufScan(c *fiber.Ctx) error {
	var req models.CreateFfufScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Name == "" || req.URL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name and url are required"})
	}

	// Default wordlist
	if req.Wordlist == "" {
		req.Wordlist = "common"
	}

	scanID := uuid.New()
	config := map[string]interface{}{
		"url":             req.URL,
		"wordlist":        req.Wordlist,
		"method":          req.Method,
		"threads":         req.Threads,
		"timeout":         req.Timeout,
		"match_codes":     req.MatchCodes,
		"filter_codes":    req.FilterCodes,
		"filter_size":     req.FilterSize,
		"extensions":      req.Extensions,
		"headers":         req.Headers,
		"recursion":       req.Recursion,
		"recursion_depth": req.RecursionDepth,
	}
	configJSON, _ := json.Marshal(config)

	query := `
		INSERT INTO web_scans (id, name, target, tool, status, progress, created_at, configuration)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, target, tool, status, progress, created_at
	`

	var scan models.WebScan
	err := h.db.Pool.QueryRow(context.Background(), query,
		scanID, req.Name, req.URL, "ffuf", "pending", 0, time.Now(), configJSON,
	).Scan(&scan.ID, &scan.Name, &scan.Target, &scan.Tool, &scan.Status, &scan.Progress, &scan.CreatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan"})
	}

	// Start scan in background
	go h.ffufScanner.ExecuteScan(context.Background(), scanID, scanner.FfufScanConfig{
		URL:            req.URL,
		Wordlist:       req.Wordlist,
		Method:         req.Method,
		Threads:        req.Threads,
		Timeout:        req.Timeout,
		MatchCodes:     req.MatchCodes,
		FilterCodes:    req.FilterCodes,
		FilterSize:     req.FilterSize,
		Extensions:     req.Extensions,
		Headers:        req.Headers,
		Recursion:      req.Recursion,
		RecursionDepth: req.RecursionDepth,
	})

	return c.Status(201).JSON(scan)
}

// CreateGowintessScan creates a new gowitness scan
func (h *WebScanHandler) CreateGowintessScan(c *fiber.Ctx) error {
	var req models.CreateGowintessScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Name == "" || len(req.URLs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "name and urls are required"})
	}

	scanID := uuid.New()
	config := map[string]interface{}{
		"urls":       req.URLs,
		"timeout":    req.Timeout,
		"resolution": req.Resolution,
		"delay":      req.Delay,
		"user_agent": req.UserAgent,
		"full_page":  req.FullPage,
	}
	configJSON, _ := json.Marshal(config)

	// Use first URL as target for display
	target := req.URLs[0]
	if len(req.URLs) > 1 {
		target += " (+" + strconv.Itoa(len(req.URLs)-1) + " more)"
	}

	query := `
		INSERT INTO web_scans (id, name, target, tool, status, progress, created_at, configuration)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, target, tool, status, progress, created_at
	`

	var scan models.WebScan
	err := h.db.Pool.QueryRow(context.Background(), query,
		scanID, req.Name, target, "gowitness", "pending", 0, time.Now(), configJSON,
	).Scan(&scan.ID, &scan.Name, &scan.Target, &scan.Tool, &scan.Status, &scan.Progress, &scan.CreatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan"})
	}

	// Start scan in background
	go h.gowitnessScanner.ExecuteScan(context.Background(), scanID, scanner.GowitnessConfig{
		URLs:       req.URLs,
		Timeout:    req.Timeout,
		Resolution: req.Resolution,
		Delay:      req.Delay,
		UserAgent:  req.UserAgent,
		FullPage:   req.FullPage,
	})

	return c.Status(201).JSON(scan)
}

// CreateTestsslScan creates a new testssl scan
func (h *WebScanHandler) CreateTestsslScan(c *fiber.Ctx) error {
	var req models.CreateTestsslScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Name == "" || req.Target == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name and target are required"})
	}

	scanID := uuid.New()
	config := map[string]interface{}{
		"target":          req.Target,
		"protocols":       req.Protocols,
		"ciphers":         req.Ciphers,
		"vulnerabilities": req.Vulnerabilities,
		"headers":         req.Headers,
		"certificate":     req.Certificate,
		"full":            req.Full,
		"fast":            req.Fast,
		"sni":             req.SNI,
		"starttls":        req.StartTLS,
	}
	configJSON, _ := json.Marshal(config)

	query := `
		INSERT INTO web_scans (id, name, target, tool, status, progress, created_at, configuration)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, target, tool, status, progress, created_at
	`

	var scan models.WebScan
	err := h.db.Pool.QueryRow(context.Background(), query,
		scanID, req.Name, req.Target, "testssl", "pending", 0, time.Now(), configJSON,
	).Scan(&scan.ID, &scan.Name, &scan.Target, &scan.Tool, &scan.Status, &scan.Progress, &scan.CreatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan"})
	}

	// Start scan in background
	go h.testsslScanner.ExecuteScan(context.Background(), scanID, scanner.TestsslConfig{
		Target:          req.Target,
		Protocols:       req.Protocols,
		Ciphers:         req.Ciphers,
		Vulnerabilities: req.Vulnerabilities,
		Headers:         req.Headers,
		Certificate:     req.Certificate,
		Full:            req.Full,
		Fast:            req.Fast,
		SNI:             req.SNI,
		StartTLS:        req.StartTLS,
	})

	return c.Status(201).JSON(scan)
}

// DeleteWebScan deletes a web scan
func (h *WebScanHandler) DeleteWebScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	// Check if scan exists and is not running
	var status string
	checkQuery := `SELECT status FROM web_scans WHERE id = $1`
	err := h.db.Pool.QueryRow(context.Background(), checkQuery, scanID).Scan(&status)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	if status == "running" {
		return c.Status(400).JSON(fiber.Map{"error": "Cannot delete running scan. Cancel it first."})
	}

	// Delete results first (cascade should handle this but being explicit)
	h.db.Pool.Exec(context.Background(), `DELETE FROM web_scan_results WHERE scan_id = $1`, scanID)
	h.db.Pool.Exec(context.Background(), `DELETE FROM web_scan_logs WHERE scan_id = $1`, scanID)

	// Delete scan
	result, err := h.db.Pool.Exec(context.Background(), `DELETE FROM web_scans WHERE id = $1`, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete scan"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	return c.JSON(fiber.Map{"message": "Scan deleted successfully"})
}

// CancelWebScan cancels a running web scan
func (h *WebScanHandler) CancelWebScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		UPDATE web_scans
		SET status = 'cancelled', completed_at = $1
		WHERE id = $2 AND status IN ('pending', 'running')
		RETURNING id
	`

	var id uuid.UUID
	err := h.db.Pool.QueryRow(context.Background(), query, time.Now(), scanID).Scan(&id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found or already completed"})
	}

	return c.JSON(fiber.Map{"message": "Scan cancelled successfully"})
}

// GetWebScanResults returns results for a web scan
func (h *WebScanHandler) GetWebScanResults(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, scan_id, tool, url, status_code, content_length, words, lines,
			content_type, redirect_url, title, screenshot_path, screenshot_b64,
			finding_id, severity, finding_text, cve, cwe, metadata, created_at
		FROM web_scan_results
		WHERE scan_id = $1
		ORDER BY created_at DESC
	`

	rows, err := h.db.Pool.Query(context.Background(), query, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch results"})
	}
	defer rows.Close()

	results := []models.WebScanResult{}
	for rows.Next() {
		var result models.WebScanResult
		var metadataJSON []byte
		var statusCode, contentLength, words, lines *int
		var contentType, redirectURL, title, screenshotPath, screenshotB64, findingID, severity, findingText, cve, cwe *string

		err := rows.Scan(&result.ID, &result.ScanID, &result.Tool, &result.URL,
			&statusCode, &contentLength, &words, &lines,
			&contentType, &redirectURL, &title, &screenshotPath, &screenshotB64,
			&findingID, &severity, &findingText, &cve, &cwe, &metadataJSON, &result.CreatedAt)
		if err != nil {
			continue
		}

		// Handle nullable fields
		if statusCode != nil {
			result.StatusCode = *statusCode
		}
		if contentLength != nil {
			result.ContentLength = *contentLength
		}
		if words != nil {
			result.Words = *words
		}
		if lines != nil {
			result.Lines = *lines
		}
		if contentType != nil {
			result.ContentType = *contentType
		}
		if redirectURL != nil {
			result.RedirectURL = *redirectURL
		}
		if title != nil {
			result.Title = *title
		}
		if screenshotPath != nil {
			result.ScreenshotPath = *screenshotPath
		}
		if screenshotB64 != nil {
			result.ScreenshotB64 = *screenshotB64
		}
		if findingID != nil {
			result.FindingID = *findingID
		}
		if severity != nil {
			result.Severity = *severity
		}
		if findingText != nil {
			result.FindingText = *findingText
		}
		if cve != nil {
			result.CVE = *cve
		}
		if cwe != nil {
			result.CWE = *cwe
		}
		if metadataJSON != nil {
			json.Unmarshal(metadataJSON, &result.Metadata)
		}

		results = append(results, result)
	}

	return c.JSON(results)
}

// GetWebScanLogs returns logs for a web scan
func (h *WebScanHandler) GetWebScanLogs(c *fiber.Ctx) error {
	scanID := c.Params("id")

	query := `
		SELECT id, scan_id, level, message, created_at
		FROM web_scan_logs
		WHERE scan_id = $1
		ORDER BY created_at ASC
	`

	rows, err := h.db.Pool.Query(context.Background(), query, scanID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch logs"})
	}
	defer rows.Close()

	logs := []models.WebScanLog{}
	for rows.Next() {
		var log models.WebScanLog
		err := rows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return c.JSON(logs)
}

// GetWebScanStats returns statistics for a web scan
func (h *WebScanHandler) GetWebScanStats(c *fiber.Ctx) error {
	scanID := c.Params("id")

	// Get tool type
	var tool string
	h.db.Pool.QueryRow(context.Background(), `SELECT tool FROM web_scans WHERE id = $1`, scanID).Scan(&tool)

	stats := models.WebScanStats{}

	// Total count
	h.db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM web_scan_results WHERE scan_id = $1`, scanID).Scan(&stats.Total)

	switch tool {
	case "ffuf":
		// Count by status code
		stats.ByStatusCode = make(map[int]int)
		rows, _ := h.db.Pool.Query(context.Background(),
			`SELECT status_code, COUNT(*) FROM web_scan_results WHERE scan_id = $1 GROUP BY status_code`, scanID)
		defer rows.Close()
		for rows.Next() {
			var code, count int
			rows.Scan(&code, &count)
			stats.ByStatusCode[code] = count
		}

	case "testssl":
		// Count by severity
		stats.BySeverity = make(map[string]int)
		rows, _ := h.db.Pool.Query(context.Background(),
			`SELECT COALESCE(severity, 'unknown'), COUNT(*) FROM web_scan_results WHERE scan_id = $1 GROUP BY severity`, scanID)
		defer rows.Close()
		for rows.Next() {
			var severity string
			var count int
			rows.Scan(&severity, &count)
			stats.BySeverity[severity] = count
		}

	case "gowitness":
		// Count screenshots
		h.db.Pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM web_scan_results WHERE scan_id = $1 AND screenshot_b64 IS NOT NULL`, scanID).Scan(&stats.Screenshots)
	}

	return c.JSON(stats)
}

// GetWebScanTemplates returns available templates for web scans
func (h *WebScanHandler) GetWebScanTemplates(c *fiber.Ctx) error {
	templates := []models.WebScanTemplate{
		// ffuf templates
		{ID: "ffuf_common", Name: "Common Paths", Description: "Scan for common web paths and directories", Tool: "ffuf", Category: "discovery", Config: map[string]interface{}{"wordlist": "common", "threads": 40}, IsDefault: true},
		{ID: "ffuf_directories", Name: "Directory Bruteforce", Description: "Comprehensive directory discovery", Tool: "ffuf", Category: "discovery", Config: map[string]interface{}{"wordlist": "directory-list-small", "threads": 50}, IsDefault: true},
		{ID: "ffuf_files", Name: "File Discovery", Description: "Find common files and backups", Tool: "ffuf", Category: "discovery", Config: map[string]interface{}{"wordlist": "raft-medium-files", "threads": 40, "extensions": []string{".bak", ".old", ".txt", ".log"}}, IsDefault: true},
		{ID: "ffuf_api", Name: "API Endpoints", Description: "Discover API endpoints", Tool: "ffuf", Category: "api", Config: map[string]interface{}{"wordlist": "common", "threads": 30}, IsDefault: true},

		// gowitness templates
		{ID: "gowitness_single", Name: "Single Screenshot", Description: "Capture screenshot of a single URL", Tool: "gowitness", Category: "recon", Config: map[string]interface{}{"timeout": 30}, IsDefault: true},
		{ID: "gowitness_full", Name: "Full Page Screenshot", Description: "Capture full page screenshot", Tool: "gowitness", Category: "recon", Config: map[string]interface{}{"timeout": 60, "full_page": true}, IsDefault: true},

		// testssl templates
		{ID: "testssl_quick", Name: "Quick SSL Check", Description: "Fast SSL/TLS configuration check", Tool: "testssl", Category: "ssl", Config: map[string]interface{}{"protocols": true, "fast": true}, IsDefault: true},
		{ID: "testssl_full", Name: "Full SSL Audit", Description: "Comprehensive SSL/TLS security audit", Tool: "testssl", Category: "ssl", Config: map[string]interface{}{"full": true}, IsDefault: true},
		{ID: "testssl_vulns", Name: "SSL Vulnerabilities", Description: "Check for SSL/TLS vulnerabilities", Tool: "testssl", Category: "ssl", Config: map[string]interface{}{"vulnerabilities": true}, IsDefault: true},
		{ID: "testssl_ciphers", Name: "Cipher Analysis", Description: "Analyze supported ciphers", Tool: "testssl", Category: "ssl", Config: map[string]interface{}{"ciphers": true}, IsDefault: true},
	}

	// Filter by tool if specified
	tool := c.Query("tool", "")
	if tool != "" {
		filtered := []models.WebScanTemplate{}
		for _, t := range templates {
			if t.Tool == tool {
				filtered = append(filtered, t)
			}
		}
		return c.JSON(filtered)
	}

	return c.JSON(templates)
}

// GetWordlists returns available wordlists for ffuf
func (h *WebScanHandler) GetWordlists(c *fiber.Ctx) error {
	return c.JSON(h.ffufScanner.GetAvailableWordlists())
}
