package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
)

type CMSeeKScanner struct {
	db         *database.Database
	cmseekPath string
}

func NewCMSeeKScanner(db *database.Database, cmseekPath string) *CMSeeKScanner {
	return &CMSeeKScanner{
		db:         db,
		cmseekPath: cmseekPath,
	}
}

// CMSeeKResult represents the JSON output from CMSeeK
type CMSeeKResult struct {
	URL           string `json:"url"`
	CMSName       string `json:"cms_name"`
	CMSVersion    string `json:"cms_version"`
	CMSDetected   bool   `json:"cms_detected"`
	CMSDeepScan   bool   `json:"deep_scan"`
	IsCloudflare  bool   `json:"is_cloudflare"`
	GeoIP         string `json:"geo_ip"`
	HTTPHeader    string `json:"http_header"`
	RobotsTxt     string `json:"robots_txt"`
	WhoisLookup   string `json:"whois_lookup"`
	CMSComponents []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"` // plugin, theme, etc.
	} `json:"components,omitempty"`
}

func (c *CMSeeKScanner) Scan(ctx context.Context, scan *models.CMSScan, config *models.CMSScanConfig) error {
	c.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	c.db.AddLog(scan.ID, "info", "Starting CMSeeK scan for "+scan.Target)

	// Create temp directory for results
	tempDir, err := os.MkdirTemp("", "cmseek-*")
	if err != nil {
		c.db.AddLog(scan.ID, "error", "Failed to create temp directory: "+err.Error())
		return err
	}
	defer os.RemoveAll(tempDir)

	// Build command
	args := []string{
		"-u", scan.Target,
		"--batch",
		"--no-banner",
		"-r", tempDir,
	}

	// Add options based on config
	if config != nil {
		if config.CMSeeKFollowRedirect {
			args = append(args, "--follow-redirect")
		}
		if config.CMSeeKRandomAgent {
			args = append(args, "--random-agent")
		}
	}

	c.db.AddLog(scan.ID, "info", "Running: cmseek "+strings.Join(args, " "))
	c.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Set timeout
	timeout := 5 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, c.cmseekPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.db.AddLog(scan.ID, "warning", "CMSeeK finished with warning: "+err.Error())
	}

	c.db.UpdateScanStatus(scan.ID, "running", 50, nil)
	c.db.AddLog(scan.ID, "info", "Parsing CMSeeK results...")

	// Try to find and parse the result JSON file
	cmsFound := 0
	techsFound := 0

	// Look for result file
	resultFiles, _ := filepath.Glob(filepath.Join(tempDir, "*", "cms.json"))
	if len(resultFiles) > 0 {
		data, err := os.ReadFile(resultFiles[0])
		if err == nil {
			var result CMSeeKResult
			if err := json.Unmarshal(data, &result); err == nil {
				cmsFound, techsFound = c.processResult(result, scan.ID)
			}
		}
	}

	// If no JSON file, parse text output
	if cmsFound == 0 {
		cmsFound, techsFound = c.parseTextOutput(string(output), scan)
	}

	c.db.UpdateScanStatus(scan.ID, "running", 90, nil)
	c.db.AddLog(scan.ID, "info", fmt.Sprintf("CMSeeK completed. Found %d CMS, %d technologies", cmsFound, techsFound))

	return nil
}

func (c *CMSeeKScanner) processResult(result CMSeeKResult, scanID uuid.UUID) (int, int) {
	cmsFound := 0
	techsFound := 0

	if result.CMSDetected && result.CMSName != "" {
		var version *string
		if result.CMSVersion != "" {
			version = &result.CMSVersion
		}

		cmsResult := &models.CMSResult{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        result.URL,
			CMSName:    result.CMSName,
			CMSVersion: version,
			Confidence: 100,
			Source:     "cmseek",
			CreatedAt:  time.Now(),
		}

		if err := c.db.SaveCMSResult(cmsResult); err == nil {
			cmsFound++
			c.db.AddLog(scanID, "info", fmt.Sprintf("Detected CMS: %s %s", result.CMSName, result.CMSVersion))
		}

		// Save as technology too
		tech := &models.Technology{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        result.URL,
			Category:   "cms",
			Name:       result.CMSName,
			Version:    version,
			Confidence: 100,
			Source:     "cmseek",
			CreatedAt:  time.Now(),
		}
		if err := c.db.SaveTechnology(tech); err == nil {
			techsFound++
		}
	}

	// Process components (plugins, themes)
	for _, comp := range result.CMSComponents {
		var version *string
		if comp.Version != "" {
			version = &comp.Version
		}

		category := "plugin"
		if comp.Type != "" {
			category = comp.Type
		}

		tech := &models.Technology{
			ID:         uuid.New(),
			ScanID:     scanID,
			URL:        result.URL,
			Category:   category,
			Name:       comp.Name,
			Version:    version,
			Confidence: 100,
			Source:     "cmseek",
			CreatedAt:  time.Now(),
		}

		if err := c.db.SaveTechnology(tech); err == nil {
			techsFound++
			c.db.AddLog(scanID, "info", fmt.Sprintf("Found %s: %s", category, comp.Name))
		}
	}

	return cmsFound, techsFound
}

func (c *CMSeeKScanner) parseTextOutput(output string, scan *models.CMSScan) (int, int) {
	cmsFound := 0
	techsFound := 0

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for CMS detection patterns
		if strings.Contains(line, "CMS Detected") || strings.Contains(line, "Detected CMS") {
			// Extract CMS name
			cmsPatterns := []string{
				"WordPress", "Drupal", "Joomla", "Magento", "PrestaShop",
				"OpenCart", "Shopify", "Ghost", "TYPO3", "MediaWiki",
				"phpBB", "vBulletin", "Moodle", "SilverStripe", "Laravel",
				"Django", "Flask", "Ruby on Rails", "ASP.NET",
			}

			for _, cms := range cmsPatterns {
				if strings.Contains(line, cms) {
					// Extract version if present
					var version *string
					// Look for version pattern like "5.9.3" or "v5.9.3"
					for _, word := range strings.Fields(line) {
						word = strings.TrimPrefix(word, "v")
						if len(word) > 0 && (word[0] >= '0' && word[0] <= '9') {
							version = &word
							break
						}
					}

					cmsResult := &models.CMSResult{
						ID:         uuid.New(),
						ScanID:     scan.ID,
						URL:        scan.Target,
						CMSName:    cms,
						CMSVersion: version,
						Confidence: 80,
						Source:     "cmseek",
						CreatedAt:  time.Now(),
					}

					if err := c.db.SaveCMSResult(cmsResult); err == nil {
						cmsFound++
						c.db.AddLog(scan.ID, "info", fmt.Sprintf("Detected CMS: %s", cms))
					}

					tech := &models.Technology{
						ID:         uuid.New(),
						ScanID:     scan.ID,
						URL:        scan.Target,
						Category:   "cms",
						Name:       cms,
						Version:    version,
						Confidence: 80,
						Source:     "cmseek",
						CreatedAt:  time.Now(),
					}
					if err := c.db.SaveTechnology(tech); err == nil {
						techsFound++
					}
					break
				}
			}
		}

		// Look for server/technology detection
		serverPatterns := map[string]string{
			"Apache":     "server",
			"nginx":      "server",
			"IIS":        "server",
			"LiteSpeed":  "server",
			"PHP":        "language",
			"Python":     "language",
			"Ruby":       "language",
			"Cloudflare": "cdn",
		}

		for pattern, category := range serverPatterns {
			if strings.Contains(line, pattern) {
				tech := &models.Technology{
					ID:         uuid.New(),
					ScanID:     scan.ID,
					URL:        scan.Target,
					Category:   category,
					Name:       pattern,
					Confidence: 70,
					Source:     "cmseek",
					CreatedAt:  time.Now(),
				}
				if err := c.db.SaveTechnology(tech); err == nil {
					techsFound++
				}
			}
		}
	}

	return cmsFound, techsFound
}

// IsAvailable checks if CMSeeK is available
func (c *CMSeeKScanner) IsAvailable() bool {
	_, err := os.Stat(c.cmseekPath)
	return err == nil
}
