package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
)

// NucleiScanner handles vulnerability scanning using Nuclei CLI
type NucleiScanner struct {
	db         *database.Database
	nucleiPath string
}

// NucleiOutput represents the JSON output from Nuclei
type NucleiOutput struct {
	TemplateID    string          `json:"template-id"`
	TemplatePath  string          `json:"template-path"`
	Info          NucleiInfo      `json:"info"`
	Type          string          `json:"type"`
	Host          string          `json:"host"`
	MatchedAt     string          `json:"matched-at"`
	ExtractedResults []string     `json:"extracted-results"`
	Request       string          `json:"request"`
	Response      string          `json:"response"`
	CURLCommand   string          `json:"curl-command"`
	IP            string          `json:"ip"`
	Timestamp     string          `json:"timestamp"`
}

// NucleiInfo contains template info
type NucleiInfo struct {
	Name           string           `json:"name"`
	Author         []string         `json:"author"`
	Tags           []string         `json:"tags"`
	Description    string           `json:"description"`
	Reference      []string         `json:"reference"`
	Severity       string           `json:"severity"`
	Classification *NucleiClassification `json:"classification,omitempty"`
}

// NucleiClassification contains vulnerability classification
type NucleiClassification struct {
	CVEId     string  `json:"cve-id,omitempty"`
	CWEId     string  `json:"cwe-id,omitempty"`
	CVSSScore string  `json:"cvss-score,omitempty"`
}

// NewNucleiScanner creates a new Nuclei scanner instance
func NewNucleiScanner(db *database.Database) *NucleiScanner {
	return &NucleiScanner{
		db:         db,
		nucleiPath: "/usr/local/bin/nuclei",
	}
}

// ExecuteVulnScan runs a Nuclei vulnerability scan using CLI
func (ns *NucleiScanner) ExecuteVulnScan(ctx context.Context, scanID uuid.UUID, target string, templates []string, severity []string, tags []string) error {
	// Update scan status to running
	if err := ns.updateScanStatus(scanID, "running", 0, nil); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	// Log scan start
	ns.addLog(scanID, "info", fmt.Sprintf("Starting vulnerability scan on target: %s", target))

	// Build Nuclei command
	args := []string{
		"-target", target,
		"-jsonl",       // JSONL output for parsing (Nuclei v3)
		"-silent",      // Suppress banner
		"-nc",          // No color codes
	}

	// Add template filters if specified
	if len(templates) > 0 {
		args = append(args, "-t", strings.Join(templates, ","))
	}

	// Add severity filters if specified
	if len(severity) > 0 {
		args = append(args, "-severity", strings.Join(severity, ","))
	}

	// Add tag filters if specified
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	ns.addLog(scanID, "info", fmt.Sprintf("Running: nuclei %s", strings.Join(args, " ")))

	// Create command with context
	cmd := exec.CommandContext(ctx, ns.nucleiPath, args...)

	// Get stdout pipe for streaming results
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create stdout pipe: %v", err)
		ns.addLog(scanID, "error", errMsg)
		ns.updateScanStatus(scanID, "failed", 0, &errMsg)
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Get stderr pipe for error messages
	stderr, err := cmd.StderrPipe()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create stderr pipe: %v", err)
		ns.addLog(scanID, "error", errMsg)
		ns.updateScanStatus(scanID, "failed", 0, &errMsg)
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		errMsg := fmt.Sprintf("Failed to start Nuclei: %v", err)
		ns.addLog(scanID, "error", errMsg)
		ns.updateScanStatus(scanID, "failed", 0, &errMsg)
		return fmt.Errorf("failed to start nuclei: %w", err)
	}

	// Process stdout (JSON results)
	vulnCount := 0
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var output NucleiOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// Not a valid JSON line, skip
			continue
		}

		// Convert to our vulnerability model and save
		vuln := ns.parseNucleiOutput(scanID, &output)
		if err := ns.saveVulnerability(vuln); err != nil {
			ns.addLog(scanID, "error", fmt.Sprintf("Failed to save vulnerability: %v", err))
		} else {
			vulnCount++
			ns.addLog(scanID, "info", fmt.Sprintf("Found: [%s] %s - %s",
				output.Info.Severity, output.TemplateID, output.Host))
		}

		// Update progress (estimate)
		ns.updateScanStatus(scanID, "running", 50, nil)
	}

	// Read stderr for any error messages
	stderrScanner := bufio.NewScanner(stderr)
	var stderrLines []string
	for stderrScanner.Scan() {
		stderrLines = append(stderrLines, stderrScanner.Text())
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		// Check if context was cancelled
		if ctx.Err() == context.Canceled {
			ns.addLog(scanID, "info", "Scan was cancelled")
			ns.updateScanStatus(scanID, "cancelled", 100, nil)
			return nil
		}

		// Log stderr if there was an error
		if len(stderrLines) > 0 {
			ns.addLog(scanID, "warning", fmt.Sprintf("Nuclei stderr: %s", strings.Join(stderrLines, "\n")))
		}

		// Nuclei can return non-zero even if it found vulns, so just log
		ns.addLog(scanID, "info", fmt.Sprintf("Nuclei process exited: %v", err))
	}

	// Complete scan
	ns.addLog(scanID, "info", fmt.Sprintf("Scan completed. Found %d vulnerabilities", vulnCount))
	ns.updateScanStatus(scanID, "completed", 100, nil)

	return nil
}

// parseNucleiOutput converts Nuclei JSON output to our Vulnerability model
func (ns *NucleiScanner) parseNucleiOutput(scanID uuid.UUID, output *NucleiOutput) *models.Vulnerability {
	vuln := &models.Vulnerability{
		ID:           uuid.New(),
		ScanID:       scanID,
		TemplateID:   output.TemplateID,
		TemplateName: output.Info.Name,
		Severity:     output.Info.Severity,
		Type:         output.Type,
		Host:         output.Host,
		MatchedAt:    output.MatchedAt,
		CURLCommand:  output.CURLCommand,
		Request:      output.Request,
		Response:     output.Response,
		CreatedAt:    time.Now(),
	}

	// Parse extracted results
	if len(output.ExtractedResults) > 0 {
		vuln.ExtractedResults = output.ExtractedResults
	}

	// Parse metadata
	vuln.Metadata = models.VulnMeta{
		Description: output.Info.Description,
		Tags:        output.Info.Tags,
		Author:      output.Info.Author,
		Reference:   output.Info.Reference,
	}

	// Parse classification if available
	if output.Info.Classification != nil {
		if output.Info.Classification.CVEId != "" {
			vuln.Metadata.CVE = []string{output.Info.Classification.CVEId}
		}
		if output.Info.Classification.CWEId != "" {
			vuln.Metadata.CWE = []string{output.Info.Classification.CWEId}
		}
		vuln.Metadata.Classification = output.Info.Classification.CVSSScore
	}

	return vuln
}

// Helper functions for database operations

func (ns *NucleiScanner) updateScanStatus(scanID uuid.UUID, status string, progress int, errorMsg *string) error {
	var query string
	var args []interface{}

	if status == "running" && progress == 0 {
		query = `UPDATE vulnerability_scans SET status = $1, progress = $2, started_at = NOW() WHERE id = $3`
		args = []interface{}{status, progress, scanID}
	} else if status == "completed" || status == "failed" || status == "cancelled" {
		query = `UPDATE vulnerability_scans SET status = $1, progress = $2, completed_at = NOW(), error_message = $3 WHERE id = $4`
		args = []interface{}{status, progress, errorMsg, scanID}
	} else {
		query = `UPDATE vulnerability_scans SET status = $1, progress = $2 WHERE id = $3`
		args = []interface{}{status, progress, scanID}
	}

	_, err := ns.db.Pool.Exec(context.Background(), query, args...)
	return err
}

func (ns *NucleiScanner) addLog(scanID uuid.UUID, level, message string) error {
	query := `INSERT INTO vulnerability_scan_logs (id, scan_id, level, message, created_at)
	          VALUES ($1, $2, $3, $4, NOW())`
	_, err := ns.db.Pool.Exec(context.Background(), query, uuid.New(), scanID, level, message)
	return err
}

func (ns *NucleiScanner) saveVulnerability(vuln *models.Vulnerability) error {
	query := `INSERT INTO vulnerabilities
	          (id, scan_id, template_id, template_name, severity, type, host, matched_at,
	           extracted_results, curl_command, request, response, metadata, created_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := ns.db.Pool.Exec(context.Background(), query,
		vuln.ID, vuln.ScanID, vuln.TemplateID, vuln.TemplateName, vuln.Severity,
		vuln.Type, vuln.Host, vuln.MatchedAt, vuln.ExtractedResults, vuln.CURLCommand,
		vuln.Request, vuln.Response, vuln.Metadata, vuln.CreatedAt)

	return err
}
