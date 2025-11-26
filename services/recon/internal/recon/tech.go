package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/recon-service/internal/database"
	"github.com/security-scanner/recon-service/internal/models"
)

type TechScanner struct {
	db        *database.Database
	httpxPath string
}

func NewTechScanner(db *database.Database, httpxPath string) *TechScanner {
	return &TechScanner{
		db:        db,
		httpxPath: httpxPath,
	}
}

// HttpxResult represents the JSON output from httpx
type HttpxResult struct {
	URL         string            `json:"url"`
	StatusCode  int               `json:"status_code"`
	Title       string            `json:"title"`
	Tech        []string          `json:"tech"`
	Webserver   string            `json:"webserver"`
	ContentType string            `json:"content_type"`
	Host        string            `json:"host"`
	Port        string            `json:"port"`
	Scheme      string            `json:"scheme"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"header,omitempty"`
}

func (t *TechScanner) Scan(ctx context.Context, scan *models.ReconScan) error {
	t.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	t.db.AddLog(scan.ID, "info", "Starting technology detection for "+scan.Target)

	// Parse multiple targets (comma, newline, or space separated)
	rawTargets := strings.FieldsFunc(scan.Target, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})

	var targets []string
	for _, raw := range rawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		// Check if target already has protocol
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			targets = append(targets, raw)
		} else {
			// Try both protocols for domains without protocol
			targets = append(targets, "https://"+raw)
			targets = append(targets, "http://"+raw)
		}
	}

	if len(targets) == 0 {
		t.db.UpdateScanStatus(scan.ID, "failed", 0, nil)
		t.db.AddLog(scan.ID, "error", "No valid targets provided")
		return nil
	}

	t.db.AddLog(scan.ID, "info", fmt.Sprintf("Scanning %d target URLs", len(targets)))
	t.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	totalTargets := len(targets)
	successCount := 0

	for i, target := range targets {
		select {
		case <-ctx.Done():
			t.db.UpdateScanStatus(scan.ID, "cancelled", 0, nil)
			return ctx.Err()
		default:
		}

		t.db.AddLog(scan.ID, "info", "Probing "+target)
		progress := 10 + int(float64(i+1)/float64(totalTargets)*80)

		result, err := t.runHttpx(ctx, target)
		if err != nil {
			t.db.AddLog(scan.ID, "warning", "Failed to probe "+target+": "+err.Error())
			continue
		}

		if result != nil {
			successCount++
			// Convert technologies
			var technologies []models.Technology
			for _, tech := range result.Tech {
				technologies = append(technologies, models.Technology{
					Name:       tech,
					Category:   categorizetech(tech),
					Confidence: 100,
				})
			}

			techResult := &models.TechResult{
				ID:           uuid.New(),
				ScanID:       scan.ID,
				URL:          result.URL,
				StatusCode:   result.StatusCode,
				Technologies: technologies,
				Headers:      result.Headers,
				CreatedAt:    time.Now(),
			}

			if result.Title != "" {
				techResult.Title = &result.Title
			}
			if result.Webserver != "" {
				techResult.Server = &result.Webserver
			}
			if result.ContentType != "" {
				techResult.ContentType = &result.ContentType
			}

			if err := t.db.SaveTechResult(techResult); err != nil {
				log.Printf("Error saving tech result: %v", err)
			} else {
				t.db.AddLog(scan.ID, "info", "Found "+fmt.Sprintf("%d", len(technologies))+" technologies at "+result.URL)
			}
		}

		t.db.UpdateScanStatus(scan.ID, "running", progress, nil)
	}

	t.db.UpdateScanStatus(scan.ID, "completed", 100, nil)
	t.db.AddLog(scan.ID, "info", fmt.Sprintf("Technology detection completed. Scanned %d URLs, %d successful", totalTargets, successCount))

	return nil
}

func (t *TechScanner) runHttpx(ctx context.Context, target string) (*HttpxResult, error) {
	cmd := exec.CommandContext(ctx, t.httpxPath,
		"-u", target,
		"-silent",
		"-json",
		"-tech-detect",
		"-status-code",
		"-title",
		"-server",
		"-content-type",
		"-follow-redirects",
		"-timeout", "10",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		return &result, nil
	}

	return nil, nil
}

func categorizetech(tech string) string {
	tech = strings.ToLower(tech)

	// Web Servers
	if strings.Contains(tech, "nginx") || strings.Contains(tech, "apache") ||
		strings.Contains(tech, "iis") || strings.Contains(tech, "lighttpd") {
		return "Web Server"
	}

	// Programming Languages
	if strings.Contains(tech, "php") || strings.Contains(tech, "python") ||
		strings.Contains(tech, "ruby") || strings.Contains(tech, "java") ||
		strings.Contains(tech, "node") || strings.Contains(tech, "asp.net") {
		return "Programming Language"
	}

	// CMS
	if strings.Contains(tech, "wordpress") || strings.Contains(tech, "drupal") ||
		strings.Contains(tech, "joomla") || strings.Contains(tech, "magento") {
		return "CMS"
	}

	// Frameworks
	if strings.Contains(tech, "react") || strings.Contains(tech, "angular") ||
		strings.Contains(tech, "vue") || strings.Contains(tech, "laravel") ||
		strings.Contains(tech, "django") || strings.Contains(tech, "rails") {
		return "Framework"
	}

	// CDN
	if strings.Contains(tech, "cloudflare") || strings.Contains(tech, "akamai") ||
		strings.Contains(tech, "fastly") || strings.Contains(tech, "cdn") {
		return "CDN"
	}

	// Security
	if strings.Contains(tech, "waf") || strings.Contains(tech, "firewall") ||
		strings.Contains(tech, "security") {
		return "Security"
	}

	// Analytics
	if strings.Contains(tech, "analytics") || strings.Contains(tech, "tracking") ||
		strings.Contains(tech, "google tag") {
		return "Analytics"
	}

	// JavaScript Libraries
	if strings.Contains(tech, "jquery") || strings.Contains(tech, "bootstrap") ||
		strings.Contains(tech, "lodash") || strings.Contains(tech, "moment") {
		return "JavaScript Library"
	}

	return "Other"
}
