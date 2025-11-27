package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/cloud-service/internal/database"
	"github.com/security-scanner/cloud-service/internal/models"
)

// TrivyScanner handles container and infrastructure scanning
type TrivyScanner struct {
	db        *database.Database
	trivyPath string
}

// TrivyOutput represents Trivy JSON output
type TrivyOutput struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string                `json:"Target"`
	Class           string                `json:"Class"`
	Type            string                `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities,omitempty"`
	Misconfigurations []TrivyMisconfig   `json:"Misconfigurations,omitempty"`
	Secrets         []TrivySecret        `json:"Secrets,omitempty"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	References       []string `json:"References,omitempty"`
	CVSS             *struct {
		NVDV3 *struct {
			Score float64 `json:"V3Score"`
		} `json:"nvd,omitempty"`
	} `json:"CVSS,omitempty"`
}

type TrivyMisconfig struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Resolution  string `json:"Resolution"`
	Severity    string `json:"Severity"`
	Status      string `json:"Status"`
	References  []string `json:"References,omitempty"`
}

type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// NewTrivyScanner creates a new Trivy scanner
func NewTrivyScanner(db *database.Database, trivyPath string) *TrivyScanner {
	if trivyPath == "" {
		trivyPath = "/usr/local/bin/trivy"
	}
	return &TrivyScanner{
		db:        db,
		trivyPath: trivyPath,
	}
}

// Scan runs a Trivy scan
func (s *TrivyScanner) Scan(ctx context.Context, scan *models.CloudScan, config *models.CloudScanConfig) error {
	s.db.AddLog(scan.ID, "info", "Starting Trivy scan...")
	s.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Determine scan type
	targetType := "image"
	target := scan.Target
	if config != nil {
		if config.TrivyTargetType != "" {
			targetType = config.TrivyTargetType
		}
		if config.TrivyTarget != "" {
			target = config.TrivyTarget
		}
	}

	args := []string{
		targetType,
		"--format", "json",
		"--quiet",
	}

	// Add severity filter
	if config != nil && len(config.TrivySeverities) > 0 {
		args = append(args, "--severity", strings.Join(config.TrivySeverities, ","))
	} else {
		args = append(args, "--severity", "CRITICAL,HIGH,MEDIUM,LOW")
	}

	// Ignore unfixed vulnerabilities
	if config != nil && config.TrivyIgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	// Add security checks
	if targetType == "config" || targetType == "fs" {
		args = append(args, "--scanners", "vuln,config,secret")
	}

	args = append(args, target)

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Running: trivy %s", strings.Join(args, " ")))
	s.db.UpdateScanStatus(scan.ID, "running", 20, nil)

	// Set timeout
	timeout := 10 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.trivyPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Trivy exits with non-zero if vulnerabilities found
		if exitErr, ok := err.(*exec.ExitError); ok {
			if len(output) == 0 {
				s.db.AddLog(scan.ID, "error", fmt.Sprintf("Trivy failed: %v, stderr: %s", err, string(exitErr.Stderr)))
				return fmt.Errorf("trivy scan failed: %w", err)
			}
			// We have output, continue parsing
			s.db.AddLog(scan.ID, "info", "Trivy scan completed with findings")
		} else {
			return fmt.Errorf("trivy execution failed: %w", err)
		}
	}

	s.db.UpdateScanStatus(scan.ID, "running", 60, nil)
	s.db.AddLog(scan.ID, "info", "Parsing Trivy results...")

	// Parse JSON output
	var trivyOutput TrivyOutput
	if err := json.Unmarshal(output, &trivyOutput); err != nil {
		s.db.AddLog(scan.ID, "warning", "Failed to parse Trivy JSON output: "+err.Error())
		return nil
	}

	// Process results
	s.processResults(scan.ID, scan.Provider, target, &trivyOutput)

	s.db.UpdateScanStatus(scan.ID, "running", 90, nil)
	return nil
}

func (s *TrivyScanner) processResults(scanID uuid.UUID, provider, target string, output *TrivyOutput) {
	vulnCount := 0
	misconfigCount := 0
	secretCount := 0

	for _, result := range output.Results {
		// Process vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			var cvss float64
			if vuln.CVSS != nil && vuln.CVSS.NVDV3 != nil {
				cvss = vuln.CVSS.NVDV3.Score
			}

			vulnResult := &models.VulnerabilityResult{
				ID:               uuid.New(),
				ScanID:           scanID,
				Target:           result.Target,
				TargetType:       result.Type,
				VulnerabilityID:  vuln.VulnerabilityID,
				PkgName:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Severity:         strings.ToUpper(vuln.Severity),
				Title:            vuln.Title,
				Description:      vuln.Description,
				References:       vuln.References,
				CVSS:             cvss,
				CreatedAt:        time.Now(),
			}

			if err := s.db.SaveVulnerability(vulnResult); err == nil {
				vulnCount++
			}
		}

		// Process misconfigurations as findings
		for _, misconfig := range result.Misconfigurations {
			finding := &models.CloudFinding{
				ID:          uuid.New(),
				ScanID:      scanID,
				Provider:    provider,
				Service:     result.Type,
				ResourceID:  result.Target,
				Title:       misconfig.Title,
				Description: misconfig.Description + "\n\n" + misconfig.Message,
				Severity:    strings.ToUpper(misconfig.Severity),
				Status:      misconfig.Status,
				Remediation: misconfig.Resolution,
				Source:      "trivy",
				CreatedAt:   time.Now(),
			}

			if err := s.db.SaveFinding(finding); err == nil {
				misconfigCount++
			}
		}

		// Process secrets as findings
		for _, secret := range result.Secrets {
			finding := &models.CloudFinding{
				ID:          uuid.New(),
				ScanID:      scanID,
				Provider:    provider,
				Service:     "secrets",
				ResourceID:  result.Target,
				Title:       fmt.Sprintf("Secret found: %s", secret.Title),
				Description: fmt.Sprintf("Category: %s\nLine: %d-%d\nMatch: %s", secret.Category, secret.StartLine, secret.EndLine, secret.Match),
				Severity:    strings.ToUpper(secret.Severity),
				Status:      "FAIL",
				Source:      "trivy",
				CreatedAt:   time.Now(),
			}

			if err := s.db.SaveFinding(finding); err == nil {
				secretCount++
			}
		}
	}

	s.db.AddLog(scanID, "info", fmt.Sprintf("Trivy found: %d vulnerabilities, %d misconfigurations, %d secrets", vulnCount, misconfigCount, secretCount))
}

// ScanImage scans a Docker image
func (s *TrivyScanner) ScanImage(ctx context.Context, scan *models.CloudScan, imageName string) error {
	if scan.Config == nil {
		scan.Config = &models.CloudScanConfig{}
	}
	scan.Config.TrivyTargetType = "image"
	scan.Config.TrivyTarget = imageName
	return s.Scan(ctx, scan, scan.Config)
}

// ScanFilesystem scans a filesystem path
func (s *TrivyScanner) ScanFilesystem(ctx context.Context, scan *models.CloudScan, path string) error {
	if scan.Config == nil {
		scan.Config = &models.CloudScanConfig{}
	}
	scan.Config.TrivyTargetType = "fs"
	scan.Config.TrivyTarget = path
	return s.Scan(ctx, scan, scan.Config)
}

// ScanConfig scans infrastructure as code
func (s *TrivyScanner) ScanConfig(ctx context.Context, scan *models.CloudScan, path string) error {
	if scan.Config == nil {
		scan.Config = &models.CloudScanConfig{}
	}
	scan.Config.TrivyTargetType = "config"
	scan.Config.TrivyTarget = path
	return s.Scan(ctx, scan, scan.Config)
}

// IsAvailable checks if Trivy is available
func (s *TrivyScanner) IsAvailable() bool {
	_, err := os.Stat(s.trivyPath)
	return err == nil
}
