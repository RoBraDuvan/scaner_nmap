package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
)

// DroopescanScanner handles multi-CMS scanning with Droopescan
// Supports: Drupal, Joomla, Moodle, SilverStripe
type DroopescanScanner struct {
	db             *database.Database
	droopescanPath string
}

// DroopescanResult represents droopescan JSON output
type DroopescanResult struct {
	CMS          string              `json:"cms"`
	Version      *DroopescanVersion  `json:"version"`
	Plugins      []DroopescanPlugin  `json:"plugins"`
	Themes       []DroopescanTheme   `json:"themes"`
	Interesting  []DroopescanFile    `json:"interesting_urls"`
}

type DroopescanVersion struct {
	Version     string `json:"version"`
	IsOutdated  bool   `json:"is_outdated"`
}

type DroopescanPlugin struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
}

type DroopescanTheme struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
}

type DroopescanFile struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

// NewDroopescanScanner creates a new Droopescan scanner
func NewDroopescanScanner(db *database.Database, droopescanPath string) *DroopescanScanner {
	if droopescanPath == "" {
		droopescanPath = "/usr/local/bin/droopescan"
	}
	return &DroopescanScanner{
		db:             db,
		droopescanPath: droopescanPath,
	}
}

// Scan runs a Droopescan scan
func (s *DroopescanScanner) Scan(ctx context.Context, scan *models.CMSScan, config *models.CMSScanConfig) error {
	s.db.AddLog(scan.ID, "info", "Starting Droopescan scan for: "+scan.Target)
	s.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Determine CMS type or scan all
	cmsType := s.determineCMSType(config)

	if cmsType == "auto" {
		// Try to auto-detect by scanning all supported CMS
		return s.scanAll(ctx, scan, config)
	}

	return s.scanCMS(ctx, scan, cmsType, config)
}

func (s *DroopescanScanner) determineCMSType(config *models.CMSScanConfig) string {
	if config != nil && config.DroopescanCMS != "" {
		return config.DroopescanCMS
	}
	return "auto"
}

func (s *DroopescanScanner) scanAll(ctx context.Context, scan *models.CMSScan, config *models.CMSScanConfig) error {
	cmsTypes := []string{"drupal", "joomla", "moodle", "silverstripe"}

	for i, cms := range cmsTypes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		progress := 10 + (i * 20)
		s.db.UpdateScanStatus(scan.ID, "running", progress, nil)
		s.db.AddLog(scan.ID, "info", fmt.Sprintf("Scanning for %s...", cms))

		err := s.scanCMS(ctx, scan, cms, config)
		if err != nil {
			s.db.AddLog(scan.ID, "warning", fmt.Sprintf("%s scan failed: %v", cms, err))
		}
	}

	return nil
}

func (s *DroopescanScanner) scanCMS(ctx context.Context, scan *models.CMSScan, cmsType string, config *models.CMSScanConfig) error {
	args := []string{
		"scan", cmsType,
		"-u", scan.Target,
		"-o", "json",
		"--hide-progressbar",
	}

	// Add threads if specified
	if config != nil && config.Timeout > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", config.Timeout/10))
	}

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Running: droopescan %s", strings.Join(args, " ")))

	cmd := exec.CommandContext(ctx, s.droopescanPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start droopescan: %w", err)
	}

	// Read stderr for progress
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "error") || strings.Contains(line, "Error") {
				s.db.AddLog(scan.ID, "warning", line)
			}
		}
	}()

	// Read JSON output
	var output strings.Builder
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		output.WriteString(scanner.Text())
	}

	if err := cmd.Wait(); err != nil {
		// Droopescan exits with non-zero if CMS not found
		s.db.AddLog(scan.ID, "info", fmt.Sprintf("%s not detected or scan completed with status: %v", cmsType, err))
		return nil
	}

	// Parse JSON results
	s.parseResults(scan.ID, scan.Target, cmsType, output.String())

	return nil
}

func (s *DroopescanScanner) parseResults(scanID uuid.UUID, target, cmsType, output string) {
	if output == "" {
		return
	}

	var result DroopescanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		s.db.AddLog(scanID, "warning", fmt.Sprintf("Failed to parse droopescan output: %v", err))
		return
	}

	// Determine CMS name
	cmsName := strings.Title(cmsType)
	if result.CMS != "" {
		cmsName = result.CMS
	}

	// Extract version
	var version *string
	confidence := 80
	if result.Version != nil && result.Version.Version != "" {
		version = &result.Version.Version
		confidence = 95
		if result.Version.IsOutdated {
			s.db.AddLog(scanID, "warning", fmt.Sprintf("%s version %s is OUTDATED", cmsName, *version))
		}
	}

	// Save CMS result
	details := fmt.Sprintf("Plugins: %d, Themes: %d, Interesting files: %d",
		len(result.Plugins), len(result.Themes), len(result.Interesting))

	cmsResult := &models.CMSResult{
		ID:         uuid.New(),
		ScanID:     scanID,
		URL:        target,
		CMSName:    cmsName,
		CMSVersion: version,
		Confidence: confidence,
		Source:     "droopescan",
		Details:    &details,
	}
	s.db.SaveCMSResult(cmsResult)

	s.db.AddLog(scanID, "info", fmt.Sprintf("Detected %s", cmsName))
	if version != nil {
		s.db.AddLog(scanID, "info", fmt.Sprintf("Version: %s", *version))
	}

	// Save plugins as technologies
	for _, plugin := range result.Plugins {
		var ver *string
		if plugin.Version != "" {
			ver = &plugin.Version
		}

		tech := &models.Technology{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        target,
			Category:   cmsType + "-plugin",
			Name:       plugin.Name,
			Version:    ver,
			Confidence: 85,
			Source:     "droopescan",
		}
		s.db.SaveTechnology(tech)
		s.db.AddLog(scanID, "info", fmt.Sprintf("Plugin found: %s", plugin.Name))
	}

	// Save themes as technologies
	for _, theme := range result.Themes {
		var ver *string
		if theme.Version != "" {
			ver = &theme.Version
		}

		tech := &models.Technology{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        target,
			Category:   cmsType + "-theme",
			Name:       theme.Name,
			Version:    ver,
			Confidence: 85,
			Source:     "droopescan",
		}
		s.db.SaveTechnology(tech)
	}

	// Log interesting files
	for _, file := range result.Interesting {
		s.db.AddLog(scanID, "info", fmt.Sprintf("Interesting URL: %s - %s", file.URL, file.Description))
	}
}

// IsAvailable checks if Droopescan is available
func (s *DroopescanScanner) IsAvailable() bool {
	_, err := os.Stat(s.droopescanPath)
	return err == nil
}
