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

// ProwlerScanner handles AWS/Azure/GCP security auditing with Prowler
type ProwlerScanner struct {
	db          *database.Database
	prowlerPath string
}

// ProwlerFindingOCSF represents a single Prowler finding in OCSF format (v5.x)
type ProwlerFindingOCSF struct {
	Message      string                `json:"message"`
	Severity     string                `json:"severity"`
	SeverityID   int                   `json:"severity_id"`
	StatusCode   string                `json:"status_code"` // PASS, FAIL, MANUAL, MUTED
	StatusDetail string                `json:"status_detail"`
	Metadata     ProwlerMetadata       `json:"metadata"`
	FindingInfo  ProwlerFindingInfo    `json:"finding_info"`
	Resources    []ProwlerResource     `json:"resources,omitempty"`
	Cloud        ProwlerCloud          `json:"cloud,omitempty"`
	Remediation  ProwlerRemediation    `json:"remediation,omitempty"`
	RiskDetails  string                `json:"risk_details,omitempty"`
	Unmapped     ProwlerUnmapped       `json:"unmapped,omitempty"`
}

type ProwlerMetadata struct {
	EventCode string `json:"event_code"`
	TenantUID string `json:"tenant_uid"`
}

type ProwlerFindingInfo struct {
	Title       string `json:"title"`
	Description string `json:"desc"`
	UID         string `json:"uid"`
}

type ProwlerResource struct {
	Region string `json:"region,omitempty"`
	UID    string `json:"uid,omitempty"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Group  struct {
		Name string `json:"name,omitempty"`
	} `json:"group,omitempty"`
}

type ProwlerCloud struct {
	Provider string `json:"provider,omitempty"`
	Region   string `json:"region,omitempty"`
	Account  struct {
		UID  string `json:"uid,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"account,omitempty"`
}

type ProwlerRemediation struct {
	Description string   `json:"desc,omitempty"`
	References  []string `json:"references,omitempty"`
}

type ProwlerUnmapped struct {
	Compliance map[string][]string `json:"compliance,omitempty"`
}

// ProwlerFinding represents a single Prowler finding (legacy format, kept for compatibility)
type ProwlerFinding struct {
	Provider        string   `json:"Provider"`
	AccountID       string   `json:"Account"`
	Region          string   `json:"Region"`
	ServiceName     string   `json:"Service"`
	CheckID         string   `json:"CheckID"`
	CheckTitle      string   `json:"CheckTitle"`
	Status          string   `json:"Status"` // PASS, FAIL, INFO, WARNING
	StatusExtended  string   `json:"StatusExtended"`
	Severity        string   `json:"Severity"`
	ResourceID      string   `json:"ResourceId"`
	ResourceARN     string   `json:"ResourceArn"`
	Description     string   `json:"Description"`
	Risk            string   `json:"Risk"`
	Remediation     string   `json:"Remediation"`
	Compliance      []string `json:"Compliance,omitempty"`
}

// NewProwlerScanner creates a new Prowler scanner
func NewProwlerScanner(db *database.Database, prowlerPath string) *ProwlerScanner {
	if prowlerPath == "" {
		prowlerPath = "/usr/local/bin/prowler"
	}
	return &ProwlerScanner{
		db:          db,
		prowlerPath: prowlerPath,
	}
}

// Scan runs a Prowler scan
func (s *ProwlerScanner) Scan(ctx context.Context, scan *models.CloudScan, config *models.CloudScanConfig) error {
	s.db.AddLog(scan.ID, "info", "Starting Prowler security audit...")
	s.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Build command based on provider
	// Prowler 5.x uses json-ocsf format (not just json)
	args := []string{
		scan.Provider,
		"-M", "json-ocsf",
		"--no-banner",
	}

	// Add provider-specific options
	switch scan.Provider {
	case "aws":
		if config != nil && config.AWSProfile != "" {
			args = append(args, "--profile", config.AWSProfile)
		}
		if config != nil && len(config.AWSRegions) > 0 {
			args = append(args, "-f", strings.Join(config.AWSRegions, ","))
		}
		if config != nil && len(config.AWSServices) > 0 {
			args = append(args, "--service", strings.Join(config.AWSServices, " "))
		}
	case "azure":
		if config != nil && config.AzureSubscription != "" {
			args = append(args, "--subscription-ids", config.AzureSubscription)
		}
		if config != nil && config.AzureTenantID != "" {
			args = append(args, "--tenant-id", config.AzureTenantID)
		}
	case "gcp":
		if config != nil && config.GCPProject != "" {
			args = append(args, "--project-id", config.GCPProject)
		}
	}

	// Add compliance framework
	if config != nil && config.ProwlerCompliance != "" {
		args = append(args, "--compliance", config.ProwlerCompliance)
	}

	// Add specific checks
	if config != nil && len(config.ProwlerChecks) > 0 {
		args = append(args, "--check", strings.Join(config.ProwlerChecks, " "))
	}

	// Create temp directory for output
	outputDir, err := os.MkdirTemp("", "prowler-*")
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	defer os.RemoveAll(outputDir)

	// Add output directory
	args = append(args, "--output-directory", outputDir)

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Running: prowler %s", strings.Join(args, " ")))
	s.db.UpdateScanStatus(scan.ID, "running", 20, nil)

	// Set timeout
	timeout := 30 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.prowlerPath, args...)

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

	// Capture stderr for progress
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Prowler: %w", err)
	}

	// Monitor progress from stderr and stdout
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Executing") {
				s.db.AddLog(scan.ID, "debug", line)
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			// Log progress indicators
			if strings.Contains(line, "Scan completed") || strings.Contains(line, "%]") {
				s.db.AddLog(scan.ID, "info", "Prowler scan in progress...")
				s.db.UpdateScanStatus(scan.ID, "running", 60, nil)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		// Prowler may exit non-zero if findings exist, that's OK
		s.db.AddLog(scan.ID, "info", "Prowler completed")
	}

	s.db.UpdateScanStatus(scan.ID, "running", 85, nil)
	s.db.AddLog(scan.ID, "info", "Parsing Prowler results...")

	// Find the OCSF JSON output file - Prowler creates files with complex names
	// like: prowler-output-email@project.iam.gserviceaccount.com-20251127044314.ocsf.json
	var outputFile string
	err = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".ocsf.json") {
			outputFile = path
			return filepath.SkipDir
		}
		return nil
	})

	// Fallback to any JSON file if no OCSF found
	if outputFile == "" {
		filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, ".json") && !strings.Contains(path, "compliance") {
				outputFile = path
				return filepath.SkipDir
			}
			return nil
		})
	}

	if outputFile != "" {
		s.db.AddLog(scan.ID, "debug", "Found Prowler output file: "+filepath.Base(outputFile))
		outputData, err := os.ReadFile(outputFile)
		if err == nil && len(outputData) > 0 {
			s.parseResultsOCSF(scan.ID, scan.Provider, outputData)
		} else {
			s.db.AddLog(scan.ID, "warning", "Could not read Prowler output file: "+err.Error())
		}
	} else {
		// List directory contents for debugging
		entries, _ := os.ReadDir(outputDir)
		fileNames := []string{}
		for _, e := range entries {
			fileNames = append(fileNames, e.Name())
		}
		s.db.AddLog(scan.ID, "warning", "No Prowler output file found. Directory contents: "+strings.Join(fileNames, ", "))
	}

	s.db.UpdateScanStatus(scan.ID, "running", 95, nil)
	return nil
}

func (s *ProwlerScanner) parseResults(scanID uuid.UUID, provider, output string) {
	findingCount := 0
	passCount := 0
	failCount := 0

	// Prowler outputs JSON Lines (one JSON object per line)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var finding ProwlerFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}

		// Map Prowler severity to standard
		severity := s.mapSeverity(finding.Severity)

		// Create finding
		cloudFinding := &models.CloudFinding{
			ID:          uuid.New(),
			ScanID:      scanID,
			Provider:    finding.Provider,
			Service:     finding.ServiceName,
			Region:      finding.Region,
			ResourceID:  finding.ResourceID,
			ResourceARN: finding.ResourceARN,
			Title:       finding.CheckTitle,
			Description: finding.Description + "\n\nRisk: " + finding.Risk,
			Severity:    severity,
			Status:      finding.Status,
			Compliance:  finding.Compliance,
			Remediation: finding.Remediation,
			Source:      "prowler",
			CreatedAt:   time.Now(),
		}

		if err := s.db.SaveFinding(cloudFinding); err == nil {
			findingCount++
			if finding.Status == "PASS" {
				passCount++
			} else {
				failCount++
			}
		}
	}

	s.db.AddLog(scanID, "info", fmt.Sprintf("Prowler audit complete: %d checks (%d passed, %d failed)", findingCount, passCount, failCount))
}

// parseResultsOCSF parses Prowler 5.x OCSF JSON format
func (s *ProwlerScanner) parseResultsOCSF(scanID uuid.UUID, provider string, data []byte) {
	findingCount := 0
	passCount := 0
	failCount := 0

	// OCSF format is a JSON array
	var findings []ProwlerFindingOCSF
	if err := json.Unmarshal(data, &findings); err != nil {
		s.db.AddLog(scanID, "error", "Failed to parse OCSF JSON: "+err.Error())
		return
	}

	s.db.AddLog(scanID, "debug", fmt.Sprintf("Parsing %d OCSF findings", len(findings)))

	for _, finding := range findings {
		// Extract service - prefer resource group name, fallback to event_code prefix
		service := provider
		if len(finding.Resources) > 0 && finding.Resources[0].Group.Name != "" {
			service = finding.Resources[0].Group.Name
		} else if finding.Metadata.EventCode != "" {
			parts := strings.Split(finding.Metadata.EventCode, "_")
			if len(parts) > 0 {
				service = parts[0]
			}
		}

		// Extract region
		region := "global"
		if finding.Cloud.Region != "" {
			region = finding.Cloud.Region
		}
		if len(finding.Resources) > 0 && finding.Resources[0].Region != "" {
			region = finding.Resources[0].Region
		}

		// Extract resource ID
		resourceID := ""
		if len(finding.Resources) > 0 {
			resourceID = finding.Resources[0].UID
			if resourceID == "" {
				resourceID = finding.Resources[0].Name
			}
		}

		// Build compliance list
		var compliance []string
		for framework, controls := range finding.Unmapped.Compliance {
			for _, control := range controls {
				compliance = append(compliance, fmt.Sprintf("%s: %s", framework, control))
			}
		}

		// Create finding
		cloudFinding := &models.CloudFinding{
			ID:          uuid.New(),
			ScanID:      scanID,
			Provider:    provider,
			Service:     service,
			Region:      region,
			ResourceID:  resourceID,
			Title:       finding.FindingInfo.Title,
			Description: finding.FindingInfo.Description + "\n\n" + finding.Message,
			Severity:    strings.ToUpper(finding.Severity),
			Status:      finding.StatusCode,
			Compliance:  compliance,
			Remediation: finding.Remediation.Description,
			Source:      "prowler",
			CreatedAt:   time.Now(),
		}

		if err := s.db.SaveFinding(cloudFinding); err != nil {
			// Log the first error to help debugging
			if findingCount == 0 && passCount == 0 && failCount == 0 {
				s.db.AddLog(scanID, "error", "Failed to save finding: "+err.Error())
			}
		} else {
			findingCount++
			if finding.StatusCode == "PASS" {
				passCount++
			} else {
				failCount++
			}
		}
	}

	s.db.AddLog(scanID, "info", fmt.Sprintf("Prowler audit complete: %d checks (%d passed, %d failed)", findingCount, passCount, failCount))
}

func (s *ProwlerScanner) mapSeverity(severity string) string {
	severity = strings.ToUpper(severity)
	switch severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		return severity
	case "INFORMATIONAL":
		return "INFO"
	default:
		return "INFO"
	}
}

// ScanAWS runs an AWS-specific scan
func (s *ProwlerScanner) ScanAWS(ctx context.Context, scan *models.CloudScan) error {
	scan.Provider = "aws"
	return s.Scan(ctx, scan, scan.Config)
}

// ScanAzure runs an Azure-specific scan
func (s *ProwlerScanner) ScanAzure(ctx context.Context, scan *models.CloudScan) error {
	scan.Provider = "azure"
	return s.Scan(ctx, scan, scan.Config)
}

// ScanGCP runs a GCP-specific scan
func (s *ProwlerScanner) ScanGCP(ctx context.Context, scan *models.CloudScan) error {
	scan.Provider = "gcp"
	return s.Scan(ctx, scan, scan.Config)
}

// IsAvailable checks if Prowler is available
func (s *ProwlerScanner) IsAvailable() bool {
	_, err := os.Stat(s.prowlerPath)
	return err == nil
}
