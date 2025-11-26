package scanner

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/web-service/internal/database"
)

// GowitnessScanner handles web screenshots with gowitness
type GowitnessScanner struct {
	db              *database.Database
	gowitnessPath   string
	screenshotsPath string
	chromePath      string
}

// GowitnessResult represents a gowitness screenshot result
type GowitnessResult struct {
	URL            string `json:"url"`
	FinalURL       string `json:"final_url"`
	ResponseCode   int    `json:"response_code"`
	Title          string `json:"title"`
	ScreenshotPath string `json:"screenshot_path"`
	ScreenshotB64  string `json:"screenshot_b64,omitempty"`
	Technologies   []string `json:"technologies,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	TLS            *TLSInfo `json:"tls,omitempty"`
}

// TLSInfo holds TLS certificate information
type TLSInfo struct {
	Protocol     string `json:"protocol"`
	CipherSuite  string `json:"cipher_suite"`
	Issuer       string `json:"issuer"`
	Subject      string `json:"subject"`
	ValidFrom    string `json:"valid_from"`
	ValidTo      string `json:"valid_to"`
}

// GowitnessConfig holds configuration for gowitness scan
type GowitnessConfig struct {
	URLs           []string `json:"urls"`            // List of URLs to screenshot
	Timeout        int      `json:"timeout"`         // Timeout per URL in seconds
	Resolution     string   `json:"resolution"`      // Screen resolution (e.g., "1920x1080")
	Delay          int      `json:"delay"`           // Delay before screenshot in ms
	UserAgent      string   `json:"user_agent"`      // Custom user agent
	FullPage       bool     `json:"full_page"`       // Capture full page
	SaveHeaders    bool     `json:"save_headers"`    // Save response headers
}

// NewGowitnessScanner creates a new gowitness scanner
func NewGowitnessScanner(db *database.Database, gowitnessPath, screenshotsPath, chromePath string) *GowitnessScanner {
	return &GowitnessScanner{
		db:              db,
		gowitnessPath:   gowitnessPath,
		screenshotsPath: screenshotsPath,
		chromePath:      chromePath,
	}
}

// ExecuteScan runs a gowitness scan
func (s *GowitnessScanner) ExecuteScan(ctx context.Context, scanID uuid.UUID, config GowitnessConfig) error {
	// Update scan status to running
	s.updateScanStatus(scanID, "running", 0)
	s.addLog(scanID, "info", fmt.Sprintf("Starting gowitness scan on %d URLs", len(config.URLs)))

	// Create scan-specific screenshot directory
	scanDir := filepath.Join(s.screenshotsPath, scanID.String())
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		s.updateScanStatus(scanID, "failed", 0)
		s.addLog(scanID, "error", fmt.Sprintf("Failed to create screenshot directory: %v", err))
		return err
	}

	// Create temp file with URLs
	urlsFile := filepath.Join("/tmp", fmt.Sprintf("urls_%s.txt", scanID.String()))
	f, err := os.Create(urlsFile)
	if err != nil {
		s.updateScanStatus(scanID, "failed", 0)
		return err
	}
	for _, url := range config.URLs {
		f.WriteString(url + "\n")
	}
	f.Close()
	defer os.Remove(urlsFile)

	// Build gowitness command (v3.x syntax)
	args := []string{
		"scan",
		"file",
		"-f", urlsFile,
		"--screenshot-path", scanDir,
		"--chrome-path", s.chromePath,
	}

	// Set timeout (gowitness v3 uses -T or --timeout)
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	args = append(args, "-T", fmt.Sprintf("%d", timeout))

	// Set resolution (gowitness v3 uses --chrome-window-x and --chrome-window-y)
	if config.Resolution != "" {
		parts := strings.Split(config.Resolution, "x")
		if len(parts) == 2 {
			args = append(args, "--chrome-window-x", parts[0], "--chrome-window-y", parts[1])
		}
	} else {
		// Default resolution
		args = append(args, "--chrome-window-x", "1920", "--chrome-window-y", "1080")
	}

	// Set delay (gowitness v3 uses --delay in seconds)
	if config.Delay > 0 {
		args = append(args, "--delay", fmt.Sprintf("%d", config.Delay))
	}

	// Set user agent (gowitness v3 uses --chrome-user-agent)
	if config.UserAgent != "" {
		args = append(args, "--chrome-user-agent", config.UserAgent)
	}

	// Full page capture (gowitness v3 uses --screenshot-fullpage)
	if config.FullPage {
		args = append(args, "--screenshot-fullpage")
	}

	// Set threads for parallel processing
	args = append(args, "-t", "4")

	s.addLog(scanID, "info", fmt.Sprintf("Executing: %s %v", s.gowitnessPath, args))

	// Execute gowitness
	cmd := exec.CommandContext(ctx, s.gowitnessPath, args...)
	cmd.Env = append(os.Environ(), "DISPLAY=:99")

	// Capture output
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		s.updateScanStatus(scanID, "failed", 0)
		s.addLog(scanID, "error", fmt.Sprintf("Failed to start gowitness: %v", err))
		return err
	}

	// Read output
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			s.addLog(scanID, "debug", scanner.Text())
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
		log.Printf("gowitness exited with: %v", err)
	}

	s.updateScanStatus(scanID, "running", 70)

	// Process screenshots
	s.addLog(scanID, "info", "Processing screenshots...")
	screenshots, err := s.processScreenshots(scanID, scanDir, config.URLs)
	if err != nil {
		s.addLog(scanID, "warning", fmt.Sprintf("Error processing screenshots: %v", err))
	}

	// Save results
	for _, result := range screenshots {
		s.saveGowitnessResult(scanID, result)
	}

	s.addLog(scanID, "info", fmt.Sprintf("Scan completed. Captured %d screenshots", len(screenshots)))
	s.updateScanStatus(scanID, "completed", 100)

	return nil
}

func (s *GowitnessScanner) processScreenshots(scanID uuid.UUID, scanDir string, urls []string) ([]GowitnessResult, error) {
	var results []GowitnessResult

	// Log directory contents for debugging
	log.Printf("Processing screenshots from directory: %s", scanDir)

	// Read screenshots from directory
	files, err := os.ReadDir(scanDir)
	if err != nil {
		log.Printf("Error reading screenshot directory: %v", err)
		return nil, err
	}

	log.Printf("Found %d files in screenshot directory", len(files))

	for _, file := range files {
		fileName := file.Name()
		log.Printf("Processing file: %s", fileName)

		// gowitness v3 uses .jpeg by default, but also check for .png
		isScreenshot := !file.IsDir() && (strings.HasSuffix(fileName, ".jpeg") ||
			strings.HasSuffix(fileName, ".jpg") ||
			strings.HasSuffix(fileName, ".png"))

		if isScreenshot {
			filePath := filepath.Join(scanDir, fileName)

			// Read screenshot and convert to base64
			data, err := os.ReadFile(filePath)
			if err != nil {
				log.Printf("Error reading file %s: %v", filePath, err)
				continue
			}

			b64 := base64.StdEncoding.EncodeToString(data)

			// gowitness v3 filename format: https-domain-port.jpeg or http-domain-port.jpeg
			// Extract URL from filename
			url := fileName
			// Remove extension
			url = strings.TrimSuffix(url, ".jpeg")
			url = strings.TrimSuffix(url, ".jpg")
			url = strings.TrimSuffix(url, ".png")

			// gowitness v3 uses format like: https-example-com-443
			// Convert back to URL format
			if strings.HasPrefix(url, "https-") {
				url = strings.TrimPrefix(url, "https-")
				// Replace last dash with port separator if it looks like a port
				parts := strings.Split(url, "-")
				if len(parts) > 1 {
					lastPart := parts[len(parts)-1]
					// Check if last part is a port number
					if _, err := fmt.Sscanf(lastPart, "%d", new(int)); err == nil && len(lastPart) <= 5 {
						host := strings.Join(parts[:len(parts)-1], ".")
						url = fmt.Sprintf("https://%s:%s", host, lastPart)
					} else {
						url = "https://" + strings.Join(parts, ".")
					}
				} else {
					url = "https://" + url
				}
			} else if strings.HasPrefix(url, "http-") {
				url = strings.TrimPrefix(url, "http-")
				parts := strings.Split(url, "-")
				if len(parts) > 1 {
					lastPart := parts[len(parts)-1]
					if _, err := fmt.Sscanf(lastPart, "%d", new(int)); err == nil && len(lastPart) <= 5 {
						host := strings.Join(parts[:len(parts)-1], ".")
						url = fmt.Sprintf("http://%s:%s", host, lastPart)
					} else {
						url = "http://" + strings.Join(parts, ".")
					}
				} else {
					url = "http://" + url
				}
			}

			// Try to match with original URLs for better accuracy
			for _, origURL := range urls {
				if strings.Contains(strings.ToLower(origURL), strings.ToLower(strings.Split(url, "://")[1][:10])) {
					url = origURL
					break
				}
			}

			result := GowitnessResult{
				URL:            url,
				ScreenshotPath: filePath,
				ScreenshotB64:  b64,
			}

			results = append(results, result)
			log.Printf("Added screenshot for URL: %s", url)
		}
	}

	return results, nil
}

func (s *GowitnessScanner) saveGowitnessResult(scanID uuid.UUID, result GowitnessResult) {
	query := `
		INSERT INTO web_scan_results (id, scan_id, tool, url, status_code, title,
			screenshot_path, screenshot_b64, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	metadata, _ := json.Marshal(map[string]interface{}{
		"final_url":    result.FinalURL,
		"technologies": result.Technologies,
		"headers":      result.Headers,
		"tls":          result.TLS,
	})

	_, err := s.db.Pool.Exec(context.Background(), query,
		uuid.New(), scanID, "gowitness", result.URL, result.ResponseCode, result.Title,
		result.ScreenshotPath, result.ScreenshotB64, metadata, time.Now())

	if err != nil {
		log.Printf("Failed to save gowitness result: %v", err)
	}
}

func (s *GowitnessScanner) updateScanStatus(scanID uuid.UUID, status string, progress int) {
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

func (s *GowitnessScanner) addLog(scanID uuid.UUID, level, message string) {
	query := `INSERT INTO web_scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	s.db.Pool.Exec(context.Background(), query, uuid.New(), scanID, level, message, time.Now())
	log.Printf("[%s] %s: %s", scanID.String()[:8], level, message)
}
