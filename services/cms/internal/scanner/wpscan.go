package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
)

type WPScanScanner struct {
	db         *database.Database
	wpscanPath string
}

func NewWPScanScanner(db *database.Database, wpscanPath string) *WPScanScanner {
	return &WPScanScanner{
		db:         db,
		wpscanPath: wpscanPath,
	}
}

// WPScanJSON represents the JSON output from WPScan
type WPScanJSON struct {
	Banner struct {
		Version string `json:"version"`
	} `json:"banner"`
	TargetURL    string `json:"target_url"`
	EffectiveURL string `json:"effective_url"`
	Interesting  []struct {
		URL       string `json:"url"`
		Type      string `json:"type"`
		ToS       string `json:"to_s"`
		Entries   []struct {
			Type   string `json:"type"`
			Entry  string `json:"entry"`
		} `json:"entries,omitempty"`
	} `json:"interesting_findings"`
	Version *struct {
		Number            string           `json:"number"`
		ReleasedDate      string           `json:"release_date"`
		Status            string           `json:"status"`
		Confidence        int              `json:"confidence"`
		InterestingEntries json.RawMessage `json:"interesting_entries,omitempty"`
		Vulnerabilities   []WPScanVuln     `json:"vulnerabilities,omitempty"`
	} `json:"version"`
	MainTheme *struct {
		Slug         string `json:"slug"`
		Location     string `json:"location"`
		LatestVersion string `json:"latest_version,omitempty"`
		LastUpdated  string `json:"last_updated,omitempty"`
		Outdated     bool   `json:"outdated"`
		Style        struct {
			URL string `json:"url"`
		} `json:"style_url,omitempty"`
		Version *struct {
			Number     string `json:"number"`
			Confidence int    `json:"confidence"`
		} `json:"version,omitempty"`
		Vulnerabilities []WPScanVuln `json:"vulnerabilities,omitempty"`
	} `json:"main_theme"`
	Plugins map[string]struct {
		Slug          string `json:"slug"`
		Location      string `json:"location"`
		LatestVersion string `json:"latest_version,omitempty"`
		LastUpdated   string `json:"last_updated,omitempty"`
		Outdated      bool   `json:"outdated"`
		Version       *struct {
			Number     string `json:"number"`
			Confidence int    `json:"confidence"`
		} `json:"version,omitempty"`
		Vulnerabilities []WPScanVuln `json:"vulnerabilities,omitempty"`
	} `json:"plugins"`
	Users []struct {
		ID          int    `json:"id"`
		Username    string `json:"username"`
		Description string `json:"description,omitempty"`
	} `json:"users,omitempty"`
	PasswordAttack interface{} `json:"password_attack,omitempty"`
	NotFullyConfigured bool `json:"not_fully_configured,omitempty"`
	ConfigBackups []struct {
		URL string `json:"url"`
		ToS string `json:"to_s"`
	} `json:"config_backups,omitempty"`
	DBExports []struct {
		URL string `json:"url"`
		ToS string `json:"to_s"`
	} `json:"db_exports,omitempty"`
	Timthumbs []struct {
		URL string `json:"url"`
	} `json:"timthumbs,omitempty"`
}

type WPScanVuln struct {
	Title      string `json:"title"`
	FixedIn    string `json:"fixed_in,omitempty"`
	References struct {
		URL  []string `json:"url,omitempty"`
		CVE  []string `json:"cve,omitempty"`
		WPVDB []string `json:"wpvdb,omitempty"`
	} `json:"references"`
	Type string `json:"vuln_type,omitempty"`
}

func (w *WPScanScanner) Scan(ctx context.Context, scan *models.CMSScan, config *models.CMSScanConfig) error {
	w.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	w.db.AddLog(scan.ID, "info", "Starting WPScan for "+scan.Target)

	// Build command
	args := []string{
		"--url", scan.Target,
		"--format", "json",
		"--no-banner",
		"--random-user-agent",
	}

	// Add API token if provided
	if config != nil && config.WPScanAPIToken != "" {
		args = append(args, "--api-token", config.WPScanAPIToken)
	}

	// Add enumeration options
	if config != nil && len(config.WPScanEnumerate) > 0 {
		args = append(args, "-e", strings.Join(config.WPScanEnumerate, ","))
	} else {
		// Default enumeration: vulnerable plugins, themes, users
		args = append(args, "-e", "vp,vt,u")
	}

	// Add detection mode
	if config != nil && config.WPScanDetectionMode != "" {
		args = append(args, "--detection-mode", config.WPScanDetectionMode)
	}

	// Add custom headers
	if config != nil && len(config.Headers) > 0 {
		for key, value := range config.Headers {
			args = append(args, "--headers", fmt.Sprintf("%s: %s", key, value))
		}
	}

	w.db.AddLog(scan.ID, "info", "Running: wpscan "+strings.Join(sanitizeArgs(args), " "))
	w.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Set timeout
	timeout := 10 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, w.wpscanPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// WPScan exits with non-zero code if vulnerabilities found
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 0 && len(output) > 0 {
				// This is OK, we have output to parse
				w.db.AddLog(scan.ID, "info", "WPScan found issues (non-zero exit is expected)")
			}
		} else {
			w.db.AddLog(scan.ID, "warning", "WPScan finished with warning: "+err.Error())
		}
	}

	w.db.UpdateScanStatus(scan.ID, "running", 50, nil)
	w.db.AddLog(scan.ID, "info", "Parsing WPScan results...")

	// Parse JSON output
	var result WPScanJSON
	if err := json.Unmarshal(output, &result); err != nil {
		w.db.AddLog(scan.ID, "warning", "Failed to parse JSON output: "+err.Error())
		// Try to extract basic info from text
		w.parseBasicOutput(string(output), scan)
		return nil
	}

	// Process results
	w.processResults(result, scan.ID)

	w.db.UpdateScanStatus(scan.ID, "running", 90, nil)
	w.db.AddLog(scan.ID, "info", "WPScan completed successfully")

	return nil
}

func (w *WPScanScanner) processResults(result WPScanJSON, scanID uuid.UUID) {
	targetURL := result.EffectiveURL
	if targetURL == "" {
		targetURL = result.TargetURL
	}

	// Save CMS detection
	var wpVersion *string
	if result.Version != nil {
		v := result.Version.Number
		wpVersion = &v
	}

	cmsResult := &models.CMSResult{
		ID:         uuid.New(),
		ScanID:     scanID,
		URL:        targetURL,
		CMSName:    "WordPress",
		CMSVersion: wpVersion,
		Confidence: 100,
		Source:     "wpscan",
		CreatedAt:  time.Now(),
	}
	w.db.SaveCMSResult(cmsResult)
	w.db.AddLog(scanID, "info", fmt.Sprintf("Detected WordPress %s", stringOrEmpty(wpVersion)))

	// Build WPScan specific result
	wpScanResult := &models.WPScanResult{
		ID:        uuid.New(),
		ScanID:    scanID,
		URL:       targetURL,
		WPVersion: wpVersion,
		CreatedAt: time.Now(),
	}

	// Process theme
	if result.MainTheme != nil {
		theme := result.MainTheme.Slug
		wpScanResult.MainTheme = &theme
		if result.MainTheme.Version != nil {
			version := result.MainTheme.Version.Number
			wpScanResult.ThemeVersion = &version
		}

		// Save theme as technology
		var themeVersion *string
		if result.MainTheme.Version != nil {
			v := result.MainTheme.Version.Number
			themeVersion = &v
		}
		tech := &models.Technology{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        targetURL,
			Category:   "theme",
			Name:       theme,
			Version:    themeVersion,
			Confidence: 100,
			Source:     "wpscan",
			CreatedAt:  time.Now(),
		}
		w.db.SaveTechnology(tech)
		w.db.AddLog(scanID, "info", fmt.Sprintf("Found theme: %s %s", theme, stringOrEmpty(themeVersion)))

		// Process theme vulnerabilities
		for _, vuln := range result.MainTheme.Vulnerabilities {
			wpScanResult.Vulnerabilities = append(wpScanResult.Vulnerabilities, models.WPVuln{
				Title:     vuln.Title,
				Type:      vuln.Type,
				Component: theme,
			})
		}
	}

	// Process plugins
	for pluginSlug, plugin := range result.Plugins {
		var pluginVersion *string
		var latestVersion *string
		if plugin.Version != nil {
			v := plugin.Version.Number
			pluginVersion = &v
		}
		if plugin.LatestVersion != "" {
			latestVersion = &plugin.LatestVersion
		}

		wpPlugin := models.WPPlugin{
			Name:            pluginSlug,
			Version:         pluginVersion,
			LatestVersion:   latestVersion,
			Outdated:        plugin.Outdated,
			Location:        plugin.Location,
			Vulnerabilities: len(plugin.Vulnerabilities),
		}
		wpScanResult.Plugins = append(wpScanResult.Plugins, wpPlugin)

		// Save plugin as technology
		tech := &models.Technology{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        targetURL,
			Category:   "plugin",
			Name:       pluginSlug,
			Version:    pluginVersion,
			Confidence: 100,
			Source:     "wpscan",
			CreatedAt:  time.Now(),
		}
		w.db.SaveTechnology(tech)

		status := ""
		if plugin.Outdated {
			status = " (OUTDATED)"
		}
		w.db.AddLog(scanID, "info", fmt.Sprintf("Found plugin: %s %s%s", pluginSlug, stringOrEmpty(pluginVersion), status))

		// Process plugin vulnerabilities
		for _, vuln := range plugin.Vulnerabilities {
			var cve *string
			if len(vuln.References.CVE) > 0 {
				cve = &vuln.References.CVE[0]
			}
			wpScanResult.Vulnerabilities = append(wpScanResult.Vulnerabilities, models.WPVuln{
				Title:     vuln.Title,
				Type:      vuln.Type,
				CVE:       cve,
				Component: pluginSlug,
			})
			w.db.AddLog(scanID, "warning", fmt.Sprintf("Vulnerability in %s: %s", pluginSlug, vuln.Title))
		}
	}

	// Process users
	for _, user := range result.Users {
		wpScanResult.Users = append(wpScanResult.Users, models.WPUser{
			ID:       user.ID,
			Username: user.Username,
			Source:   "wpscan",
		})
		w.db.AddLog(scanID, "info", fmt.Sprintf("Found user: %s (ID: %d)", user.Username, user.ID))
	}

	// Process WordPress core vulnerabilities
	if result.Version != nil {
		for _, vuln := range result.Version.Vulnerabilities {
			var cve *string
			if len(vuln.References.CVE) > 0 {
				cve = &vuln.References.CVE[0]
			}
			wpScanResult.Vulnerabilities = append(wpScanResult.Vulnerabilities, models.WPVuln{
				Title:     vuln.Title,
				Type:      vuln.Type,
				CVE:       cve,
				Component: "core",
			})
			w.db.AddLog(scanID, "warning", fmt.Sprintf("Core vulnerability: %s", vuln.Title))
		}
	}

	// Save WPScan result
	w.db.SaveWPScanResult(wpScanResult)

	// Log summary
	w.db.AddLog(scanID, "info", fmt.Sprintf("Summary: %d plugins, %d users, %d vulnerabilities",
		len(wpScanResult.Plugins), len(wpScanResult.Users), len(wpScanResult.Vulnerabilities)))
}

func (w *WPScanScanner) parseBasicOutput(output string, scan *models.CMSScan) {
	// Basic parsing for when JSON fails
	if strings.Contains(output, "WordPress") {
		cmsResult := &models.CMSResult{
			ID:         uuid.New(),
			ScanID:     scan.ID,
			URL:        scan.Target,
			CMSName:    "WordPress",
			Confidence: 80,
			Source:     "wpscan",
			CreatedAt:  time.Now(),
		}
		w.db.SaveCMSResult(cmsResult)
		w.db.AddLog(scan.ID, "info", "Detected WordPress (basic detection)")
	}

	// Check for common error messages
	if strings.Contains(output, "The target is not running WordPress") {
		w.db.AddLog(scan.ID, "info", "Target is not running WordPress")
	}
	if strings.Contains(output, "The remote host is unreachable") {
		w.db.AddLog(scan.ID, "error", "Target is unreachable")
	}
}

func sanitizeArgs(args []string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		prevIdx := i - 1
		if prevIdx >= 0 && strings.HasPrefix(args[prevIdx], "--api-token") {
			result[i] = "[REDACTED]"
		} else {
			result[i] = arg
		}
	}
	return result
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
