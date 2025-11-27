package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
)

// JoomScanScanner handles Joomla scanning with OWASP JoomScan
type JoomScanScanner struct {
	db           *database.Database
	joomscanPath string
}

// NewJoomScanScanner creates a new JoomScan scanner
func NewJoomScanScanner(db *database.Database, joomscanPath string) *JoomScanScanner {
	if joomscanPath == "" {
		joomscanPath = "/usr/local/bin/joomscan"
	}
	return &JoomScanScanner{
		db:           db,
		joomscanPath: joomscanPath,
	}
}

// Scan runs a JoomScan scan
func (s *JoomScanScanner) Scan(ctx context.Context, scan *models.CMSScan, config *models.CMSScanConfig) error {
	s.db.AddLog(scan.ID, "info", "Starting JoomScan scan for: "+scan.Target)
	s.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Build command arguments
	args := []string{
		"-u", scan.Target,
		"--ec", // Enumerate components
	}

	// Add user agent if specified
	if config != nil && config.Headers != nil {
		if ua, ok := config.Headers["User-Agent"]; ok {
			args = append(args, "-a", ua)
		}
	}

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Running: joomscan %s", strings.Join(args, " ")))

	cmd := exec.CommandContext(ctx, s.joomscanPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start joomscan: %w", err)
	}

	// Parse output in real-time
	scanner := bufio.NewScanner(stdout)
	var output strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		output.WriteString(line + "\n")

		// Log interesting findings
		if strings.Contains(line, "[+]") || strings.Contains(line, "[!]") {
			s.db.AddLog(scan.ID, "info", line)
		}
	}

	if err := cmd.Wait(); err != nil {
		// JoomScan may exit with non-zero even on success
		s.db.AddLog(scan.ID, "warning", fmt.Sprintf("JoomScan exited: %v", err))
	}

	s.db.UpdateScanStatus(scan.ID, "running", 70, nil)

	// Parse results
	s.parseResults(scan.ID, scan.Target, output.String())

	s.db.UpdateScanStatus(scan.ID, "running", 90, nil)
	s.db.AddLog(scan.ID, "info", "JoomScan scan completed")

	return nil
}

func (s *JoomScanScanner) parseResults(scanID uuid.UUID, target, output string) {
	lines := strings.Split(output, "\n")

	var joomlaVersion string
	var components []string
	var vulnerabilities []string

	// Regex patterns
	versionRe := regexp.MustCompile(`Joomla\s+(\d+\.\d+(?:\.\d+)?)`)
	componentRe := regexp.MustCompile(`\[!\]\s+Component\s+found:\s+(.+)`)
	vulnRe := regexp.MustCompile(`\[!\]\s+(.+vulnerability.+|CVE-\d+-\d+.+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract version
		if matches := versionRe.FindStringSubmatch(line); len(matches) > 1 {
			joomlaVersion = matches[1]
		}

		// Extract components
		if matches := componentRe.FindStringSubmatch(line); len(matches) > 1 {
			components = append(components, matches[1])
		}

		// Extract vulnerabilities
		if matches := vulnRe.FindStringSubmatch(line); len(matches) > 1 {
			vulnerabilities = append(vulnerabilities, matches[1])
		}
	}

	// Save CMS result if Joomla detected
	if joomlaVersion != "" || strings.Contains(output, "Joomla") {
		version := joomlaVersion
		if version == "" {
			version = "unknown"
		}

		details := fmt.Sprintf("Components: %d, Vulnerabilities: %d", len(components), len(vulnerabilities))

		result := &models.CMSResult{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        target,
			CMSName:    "Joomla",
			CMSVersion: &version,
			Confidence: 95,
			Source:     "joomscan",
			Details:    &details,
		}
		s.db.SaveCMSResult(result)

		// Save components as technologies
		for _, comp := range components {
			tech := &models.Technology{
				ID:         uuid.New(),
				ScanID:     scanID,
				URL:        target,
				Category:   "joomla-component",
				Name:       comp,
				Confidence: 90,
				Source:     "joomscan",
			}
			s.db.SaveTechnology(tech)
		}

		// Log vulnerabilities
		for _, vuln := range vulnerabilities {
			s.db.AddLog(scanID, "warning", "Vulnerability found: "+vuln)
		}
	}
}

// IsAvailable checks if JoomScan is available
func (s *JoomScanScanner) IsAvailable() bool {
	_, err := os.Stat(s.joomscanPath)
	return err == nil
}
