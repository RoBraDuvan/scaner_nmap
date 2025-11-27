package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/cloud-service/internal/database"
	"github.com/security-scanner/cloud-service/internal/models"
)

// ScoutSuiteScanner handles multi-cloud security auditing with ScoutSuite
type ScoutSuiteScanner struct {
	db             *database.Database
	scoutsuitePath string
}

// ScoutSuiteReport represents the ScoutSuite report structure
type ScoutSuiteReport struct {
	Provider string                    `json:"provider"`
	Account  string                    `json:"account_id"`
	Services map[string]ScoutService   `json:"services"`
	LastRun  ScoutLastRun              `json:"last_run"`
}

type ScoutLastRun struct {
	Time         string `json:"time"`
	RulesCount   int    `json:"rules_count"`
	ResourcesCount int  `json:"resources_count"`
}

type ScoutService struct {
	Findings map[string]ScoutFinding `json:"findings"`
}

type ScoutFinding struct {
	Description string                 `json:"description"`
	Path        string                 `json:"path"`
	Level       string                 `json:"level"` // danger, warning, info
	Items       []string               `json:"items,omitempty"`
	FlaggedItems int                   `json:"flagged_items"`
	CheckedItems int                   `json:"checked_items"`
	Rationale   string                 `json:"rationale,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Compliance  []map[string]string    `json:"compliance,omitempty"`
}

// NewScoutSuiteScanner creates a new ScoutSuite scanner
func NewScoutSuiteScanner(db *database.Database, scoutsuitePath string) *ScoutSuiteScanner {
	if scoutsuitePath == "" {
		scoutsuitePath = "/usr/local/bin/scout"
	}
	return &ScoutSuiteScanner{
		db:             db,
		scoutsuitePath: scoutsuitePath,
	}
}

// Scan runs a ScoutSuite scan
func (s *ScoutSuiteScanner) Scan(ctx context.Context, scan *models.CloudScan, config *models.CloudScanConfig) error {
	s.db.AddLog(scan.ID, "info", "Starting ScoutSuite security assessment...")
	s.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Create temp directory for report
	reportDir, err := os.MkdirTemp("", "scoutsuite-*")
	if err != nil {
		return fmt.Errorf("failed to create report directory: %w", err)
	}
	defer os.RemoveAll(reportDir)

	// Build command
	args := []string{
		scan.Provider,
		"--report-dir", reportDir,
		"--no-browser",
		"--force",
	}

	// Add provider-specific options
	switch scan.Provider {
	case "aws":
		if config != nil && config.AWSProfile != "" {
			args = append(args, "--profile", config.AWSProfile)
		}
		if config != nil && len(config.AWSRegions) > 0 {
			args = append(args, "--regions", strings.Join(config.AWSRegions, ","))
		}
		if config != nil && len(config.AWSServices) > 0 {
			args = append(args, "--services", strings.Join(config.AWSServices, ","))
		}
	case "azure":
		if config != nil && config.AzureSubscription != "" {
			args = append(args, "--subscription-ids", config.AzureSubscription)
		}
		if config != nil && config.AzureTenantID != "" {
			args = append(args, "--tenant-id", config.AzureTenantID)
		}
	case "gcp":
		// GCP requires --service-account flag with path to credentials file
		gcpCredPath := "/root/.config/gcloud/application_default_credentials.json"
		if _, err := os.Stat(gcpCredPath); err == nil {
			args = append(args, "--service-account", gcpCredPath)
		}
		if config != nil && config.GCPProject != "" {
			args = append(args, "--project-id", config.GCPProject)
		}
	}

	// Add specific rules/services
	if config != nil && len(config.ScoutSuiteServices) > 0 {
		args = append(args, "--services", strings.Join(config.ScoutSuiteServices, ","))
	}

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Running: scout %s", strings.Join(args, " ")))
	s.db.UpdateScanStatus(scan.ID, "running", 15, nil)

	// Set timeout
	timeout := 30 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.scoutsuitePath, args...)

	// Set environment variables for cloud providers
	cmd.Env = os.Environ()
	switch scan.Provider {
	case "gcp":
		gcpCredPath := "/root/.config/gcloud/application_default_credentials.json"
		if _, err := os.Stat(gcpCredPath); err == nil {
			cmd.Env = append(cmd.Env, "GOOGLE_APPLICATION_CREDENTIALS="+gcpCredPath)
			s.db.AddLog(scan.ID, "debug", "Using GCP credentials from "+gcpCredPath)
		}
	case "azure":
		azureEnvPath := "/root/.azure/env"
		if content, err := os.ReadFile(azureEnvPath); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "export ") {
					envVar := strings.TrimPrefix(line, "export ")
					cmd.Env = append(cmd.Env, envVar)
				}
			}
			s.db.AddLog(scan.ID, "debug", "Loaded Azure credentials from environment file")
		}
	}

	// Capture stderr and stdout for progress
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start ScoutSuite: %w", err)
	}

	// Monitor stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Fetching") || strings.Contains(line, "INFO") {
				s.db.AddLog(scan.ID, "debug", line)
			}
			if strings.Contains(line, "Error") || strings.Contains(line, "ERROR") {
				s.db.AddLog(scan.ID, "warning", line)
			}
		}
	}()

	// Monitor stdout - ScoutSuite logs progress here
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Fetching") || strings.Contains(line, "INFO") {
				s.db.AddLog(scan.ID, "info", line)
				s.db.UpdateScanStatus(scan.ID, "running", 50, nil)
			}
			if strings.Contains(line, "Running") {
				s.db.AddLog(scan.ID, "info", line)
				s.db.UpdateScanStatus(scan.ID, "running", 70, nil)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		s.db.AddLog(scan.ID, "warning", "ScoutSuite finished with warnings: "+err.Error())
	}

	s.db.UpdateScanStatus(scan.ID, "running", 80, nil)
	s.db.AddLog(scan.ID, "info", "Parsing ScoutSuite results...")

	// Find and parse the results file - ScoutSuite creates files in {report_dir}/scoutsuite-results/
	var outputFile string

	// Walk the report directory to find the results file
	err = filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasPrefix(filepath.Base(path), "scoutsuite_results_") && strings.HasSuffix(path, ".js") {
			outputFile = path
			return filepath.SkipAll
		}
		return nil
	})

	if outputFile != "" {
		s.db.AddLog(scan.ID, "debug", "Found ScoutSuite output file: "+filepath.Base(outputFile))
		s.parseResultsFile(scan.ID, scan.Provider, outputFile)
	} else {
		// List directory contents for debugging
		var fileNames []string
		filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				relPath, _ := filepath.Rel(reportDir, path)
				fileNames = append(fileNames, relPath)
			}
			return nil
		})
		if len(fileNames) > 0 {
			s.db.AddLog(scan.ID, "warning", "Could not find ScoutSuite results file. Directory contents: "+strings.Join(fileNames, ", "))
		} else {
			s.db.AddLog(scan.ID, "warning", "ScoutSuite did not generate any output files")
		}
	}

	s.db.UpdateScanStatus(scan.ID, "running", 95, nil)
	return nil
}

func (s *ScoutSuiteScanner) parseResultsFile(scanID uuid.UUID, provider, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		s.db.AddLog(scanID, "error", "Failed to read results file: "+err.Error())
		return
	}

	// ScoutSuite results are JavaScript, extract JSON
	content := string(data)

	// Find the JSON object
	start := strings.Index(content, "{")
	if start == -1 {
		s.db.AddLog(scanID, "error", "Could not find JSON in results file")
		return
	}
	content = content[start:]

	// Find matching closing brace
	braceCount := 0
	end := 0
	for i, char := range content {
		if char == '{' {
			braceCount++
		} else if char == '}' {
			braceCount--
			if braceCount == 0 {
				end = i + 1
				break
			}
		}
	}
	if end == 0 {
		end = len(content)
	}
	content = content[:end]

	var report ScoutSuiteReport
	if err := json.Unmarshal([]byte(content), &report); err != nil {
		s.db.AddLog(scanID, "error", "Failed to parse ScoutSuite JSON: "+err.Error())
		return
	}

	s.processReport(scanID, provider, &report)
}

func (s *ScoutSuiteScanner) processReport(scanID uuid.UUID, provider string, report *ScoutSuiteReport) {
	findingCount := 0
	criticalCount := 0
	highCount := 0

	for serviceName, service := range report.Services {
		for findingID, finding := range service.Findings {
			// Skip if no flagged items
			if finding.FlaggedItems == 0 {
				continue
			}

			// Map level to severity
			severity := s.mapLevel(finding.Level)

			// Build compliance array
			var compliance []string
			for _, comp := range finding.Compliance {
				for framework, control := range comp {
					compliance = append(compliance, fmt.Sprintf("%s: %s", framework, control))
				}
			}

			// Create finding for each flagged item
			description := finding.Description
			if finding.Rationale != "" {
				description += "\n\nRationale: " + finding.Rationale
			}

			cloudFinding := &models.CloudFinding{
				ID:          uuid.New(),
				ScanID:      scanID,
				Provider:    provider,
				Service:     serviceName,
				ResourceID:  findingID,
				Title:       finding.Description,
				Description: fmt.Sprintf("%s\n\nFlagged Items: %d / %d checked", description, finding.FlaggedItems, finding.CheckedItems),
				Severity:    severity,
				Status:      "FAIL",
				Compliance:  compliance,
				Remediation: finding.Remediation,
				Source:      "scoutsuite",
				CreatedAt:   time.Now(),
			}

			if err := s.db.SaveFinding(cloudFinding); err == nil {
				findingCount++
				if severity == "CRITICAL" {
					criticalCount++
				} else if severity == "HIGH" {
					highCount++
				}
			}
		}
	}

	s.db.AddLog(scanID, "info", fmt.Sprintf("ScoutSuite found %d security issues (%d critical, %d high)", findingCount, criticalCount, highCount))
}

func (s *ScoutSuiteScanner) mapLevel(level string) string {
	switch strings.ToLower(level) {
	case "danger":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "info":
		return "INFO"
	default:
		return "LOW"
	}
}

// ScanAWS runs an AWS-specific scan
func (s *ScoutSuiteScanner) ScanAWS(ctx context.Context, scan *models.CloudScan) error {
	scan.Provider = "aws"
	return s.Scan(ctx, scan, scan.Config)
}

// ScanAzure runs an Azure-specific scan
func (s *ScoutSuiteScanner) ScanAzure(ctx context.Context, scan *models.CloudScan) error {
	scan.Provider = "azure"
	return s.Scan(ctx, scan, scan.Config)
}

// ScanGCP runs a GCP-specific scan
func (s *ScoutSuiteScanner) ScanGCP(ctx context.Context, scan *models.CloudScan) error {
	scan.Provider = "gcp"
	return s.Scan(ctx, scan, scan.Config)
}

// IsAvailable checks if ScoutSuite is available
func (s *ScoutSuiteScanner) IsAvailable() bool {
	_, err := os.Stat(s.scoutsuitePath)
	return err == nil
}
