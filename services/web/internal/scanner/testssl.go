package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/web-service/internal/database"
)

// TestsslScanner handles SSL/TLS analysis with testssl.sh
type TestsslScanner struct {
	db          *database.Database
	testsslPath string
}

// TestsslFinding represents a single testssl.sh finding
type TestsslFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve,omitempty"`
	CWE      string `json:"cwe,omitempty"`
}

// TestsslResult represents testssl.sh scan results
type TestsslResult struct {
	TargetHost     string           `json:"targetHost"`
	IP             string           `json:"ip"`
	Port           string           `json:"port"`
	RDNs           string           `json:"rDNS"`
	Service        string           `json:"service"`
	Pretest        []TestsslFinding `json:"pretest"`
	Protocols      []TestsslFinding `json:"protocols"`
	Grease         []TestsslFinding `json:"grease"`
	Ciphers        []TestsslFinding `json:"ciphers"`
	PFS            []TestsslFinding `json:"pfs"`
	ServerPrefs    []TestsslFinding `json:"serverPreferences"`
	ServerDefaults []TestsslFinding `json:"serverDefaults"`
	HeaderResponse []TestsslFinding `json:"headerResponse"`
	Vulnerabilities []TestsslFinding `json:"vulnerabilities"`
	CipherTests    []TestsslFinding `json:"cipherTests"`
	BrowserSims    []TestsslFinding `json:"browserSimulations"`
	ScanTime       int              `json:"scanTime"`
}

// TestsslConfig holds configuration for testssl.sh scan
type TestsslConfig struct {
	Target          string   `json:"target"`           // hostname:port or URL
	Protocols       bool     `json:"protocols"`        // Check protocols
	Ciphers         bool     `json:"ciphers"`          // Check ciphers
	Vulnerabilities bool     `json:"vulnerabilities"`  // Check vulnerabilities
	Headers         bool     `json:"headers"`          // Check HTTP headers
	Certificate     bool     `json:"certificate"`      // Check certificate
	Full            bool     `json:"full"`             // Full scan
	Fast            bool     `json:"fast"`             // Fast mode (omit some tests)
	Quiet           bool     `json:"quiet"`            // Quiet mode
	SNI             string   `json:"sni"`              // Server Name Indication
	StartTLS        string   `json:"starttls"`         // smtp, pop3, imap, ftp, etc.
}

// NewTestsslScanner creates a new testssl.sh scanner
func NewTestsslScanner(db *database.Database, testsslPath string) *TestsslScanner {
	return &TestsslScanner{
		db:          db,
		testsslPath: testsslPath,
	}
}

// ExecuteScan runs a testssl.sh scan
func (s *TestsslScanner) ExecuteScan(ctx context.Context, scanID uuid.UUID, config TestsslConfig) error {
	// Update scan status to running
	s.updateScanStatus(scanID, "running", 0)
	s.addLog(scanID, "info", fmt.Sprintf("Starting testssl.sh scan on target: %s", config.Target))

	// Create temp file for JSON output
	outputFile := fmt.Sprintf("/tmp/testssl_%s.json", scanID.String())
	defer os.Remove(outputFile)

	// Build testssl.sh command
	args := []string{
		"--jsonfile", outputFile,
		"--warnings", "off",
	}

	// Add scan options
	if config.Full {
		// Full scan includes everything
	} else {
		// Selective tests
		if config.Protocols {
			args = append(args, "-p")
		}
		if config.Ciphers {
			args = append(args, "-E")
		}
		if config.Vulnerabilities {
			args = append(args, "-U")
		}
		if config.Headers {
			args = append(args, "-h")
		}
		if config.Certificate {
			args = append(args, "-S")
		}
	}

	// Fast mode
	if config.Fast {
		args = append(args, "--fast")
	}

	// Quiet mode
	if config.Quiet {
		args = append(args, "--quiet")
	}

	// SNI
	if config.SNI != "" {
		args = append(args, "--sni", config.SNI)
	}

	// StartTLS
	if config.StartTLS != "" {
		args = append(args, "--starttls", config.StartTLS)
	}

	// Add target
	args = append(args, config.Target)

	s.addLog(scanID, "info", fmt.Sprintf("Executing: %s %v", s.testsslPath, args))

	// Execute testssl.sh
	cmd := exec.CommandContext(ctx, s.testsslPath, args...)

	// Capture stderr for progress
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		s.updateScanStatus(scanID, "failed", 0)
		s.addLog(scanID, "error", fmt.Sprintf("Failed to start testssl.sh: %v", err))
		return err
	}

	// Read progress from output
	go func() {
		scanner := bufio.NewScanner(stdout)
		lineCount := 0
		for scanner.Scan() {
			line := scanner.Text()
			lineCount++
			// Update progress based on output
			if strings.Contains(line, "Testing protocols") {
				s.updateScanStatus(scanID, "running", 10)
			} else if strings.Contains(line, "Testing cipher") {
				s.updateScanStatus(scanID, "running", 30)
			} else if strings.Contains(line, "Testing vulnerabilities") {
				s.updateScanStatus(scanID, "running", 50)
			} else if strings.Contains(line, "Testing HTTP") {
				s.updateScanStatus(scanID, "running", 70)
			}
			s.addLog(scanID, "debug", line)
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			s.addLog(scanID, "debug", scanner.Text())
		}
	}()

	// Wait for completion
	if err := cmd.Wait(); err != nil {
		log.Printf("testssl.sh exited with: %v", err)
		// Continue to parse results even if exit code is non-zero
	}

	s.updateScanStatus(scanID, "running", 90)

	// Parse results
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		s.addLog(scanID, "warning", "No results file generated")
		s.updateScanStatus(scanID, "completed", 100)
		return nil
	}

	// testssl.sh outputs multiple JSON objects, one per line
	var findings []TestsslFinding
	scanner := bufio.NewScanner(strings.NewReader(string(outputData)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var finding TestsslFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			// Try parsing as array
			var findingArray []TestsslFinding
			if err2 := json.Unmarshal([]byte(line), &findingArray); err2 == nil {
				findings = append(findings, findingArray...)
			}
			continue
		}
		findings = append(findings, finding)
	}

	// Save results
	s.saveTestsslResults(scanID, config.Target, findings)

	// Count findings by severity
	severityCounts := make(map[string]int)
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	s.addLog(scanID, "info", fmt.Sprintf("Scan completed. Found %d findings (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)",
		len(findings),
		severityCounts["CRITICAL"],
		severityCounts["HIGH"],
		severityCounts["MEDIUM"],
		severityCounts["LOW"],
		severityCounts["INFO"]+severityCounts["OK"]))

	s.updateScanStatus(scanID, "completed", 100)

	return nil
}

func (s *TestsslScanner) saveTestsslResults(scanID uuid.UUID, target string, findings []TestsslFinding) {
	query := `
		INSERT INTO web_scan_results (id, scan_id, tool, url, finding_id, severity,
			finding_text, cve, cwe, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	for _, finding := range findings {
		// Map testssl severity to standard
		severity := s.mapSeverity(finding.Severity)

		metadata, _ := json.Marshal(map[string]interface{}{
			"original_severity": finding.Severity,
			"id":                finding.ID,
		})

		_, err := s.db.Pool.Exec(context.Background(), query,
			uuid.New(), scanID, "testssl", target, finding.ID, severity,
			finding.Finding, finding.CVE, finding.CWE, metadata, time.Now())

		if err != nil {
			log.Printf("Failed to save testssl result: %v", err)
		}
	}
}

func (s *TestsslScanner) mapSeverity(testsslSeverity string) string {
	switch strings.ToUpper(testsslSeverity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "OK", "INFO":
		return "info"
	case "WARN":
		return "medium"
	default:
		return "info"
	}
}

func (s *TestsslScanner) updateScanStatus(scanID uuid.UUID, status string, progress int) {
	query := `UPDATE web_scans SET status = $1, progress = $2`
	args := []interface{}{status, progress}
	argIndex := 3

	if status == "running" && progress == 0 {
		query += fmt.Sprintf(", started_at = $%d", argIndex)
		args = append(args, time.Now())
		argIndex++
	}

	if status == "completed" || status == "failed" {
		query += fmt.Sprintf(", completed_at = $%d", argIndex)
		args = append(args, time.Now())
		argIndex++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argIndex)
	args = append(args, scanID)

	s.db.Pool.Exec(context.Background(), query, args...)
}

func (s *TestsslScanner) addLog(scanID uuid.UUID, level, message string) {
	query := `INSERT INTO web_scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	s.db.Pool.Exec(context.Background(), query, uuid.New(), scanID, level, message, time.Now())
	log.Printf("[%s] %s: %s", scanID.String()[:8], level, message)
}
