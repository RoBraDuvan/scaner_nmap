package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/api-service/internal/database"
	"github.com/security-scanner/api-service/internal/models"
)

type KiterunnerScanner struct {
	db             *database.Database
	kiterunnerPath string
	wordlistsPath  string
}

func NewKiterunnerScanner(db *database.Database, kiterunnerPath, wordlistsPath string) *KiterunnerScanner {
	return &KiterunnerScanner{
		db:             db,
		kiterunnerPath: kiterunnerPath,
		wordlistsPath:  wordlistsPath,
	}
}

// KiterunnerResult represents the JSON output from kiterunner
type KiterunnerResult struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status"`
	Length      int    `json:"length"`
	ContentType string `json:"content-type"`
	Host        string `json:"host"`
	Path        string `json:"path"`
}

func (k *KiterunnerScanner) Scan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	k.db.UpdateAPIScanStatus(scan.ID, "running", 0, nil)
	k.db.AddLog(scan.ID, "info", "Starting Kiterunner API discovery for "+scan.Target)

	// Determine wordlist - map short names to full paths
	wordlist := k.wordlistsPath + "/kiterunner/routes-large.kite"
	if config != nil && config.KiterunnerWordlist != "" {
		switch config.KiterunnerWordlist {
		case "routes-large":
			wordlist = k.wordlistsPath + "/kiterunner/routes-large.kite"
		case "routes-small":
			wordlist = k.wordlistsPath + "/kiterunner/routes-small.kite"
		default:
			// If full path provided, use it directly
			if strings.HasPrefix(config.KiterunnerWordlist, "/") {
				wordlist = config.KiterunnerWordlist
			}
		}
	}

	k.db.AddLog(scan.ID, "info", fmt.Sprintf("Using wordlist: %s", wordlist))
	k.db.UpdateAPIScanStatus(scan.ID, "running", 10, nil)

	// Build command
	args := []string{
		"scan", scan.Target,
		"-w", wordlist,
		"-o", "json",
		"--fail-status-codes", "404,400",
		"-j", "50", // concurrent connections
	}

	// Add custom headers if provided
	if config != nil && len(config.Headers) > 0 {
		for key, value := range config.Headers {
			args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
		}
	}

	k.db.AddLog(scan.ID, "info", "Running: kr "+strings.Join(args, " "))

	// Set timeout
	timeout := 10 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, k.kiterunnerPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Kiterunner may return non-zero exit even with results
		if len(output) == 0 {
			k.db.AddLog(scan.ID, "warning", "Kiterunner finished with error: "+err.Error())
		}
	}

	k.db.UpdateAPIScanStatus(scan.ID, "running", 50, nil)
	k.db.AddLog(scan.ID, "info", "Parsing Kiterunner results...")

	// Parse results
	endpointsFound := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result KiterunnerResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Try parsing as text output format
			endpoint := k.parseTextOutput(line, scan.Target)
			if endpoint != nil {
				endpoint.ScanID = scan.ID
				endpoint.Source = "kiterunner"
				if err := k.db.SaveAPIEndpoint(endpoint); err == nil {
					endpointsFound++
				}
			}
			continue
		}

		// Create endpoint from JSON result
		contentType := result.ContentType
		endpoint := &models.APIEndpoint{
			ID:          uuid.New(),
			ScanID:      scan.ID,
			URL:         result.URL,
			Method:      result.Method,
			StatusCode:  result.StatusCode,
			ContentType: &contentType,
			Length:      result.Length,
			Source:      "kiterunner",
			CreatedAt:   time.Now(),
		}

		if err := k.db.SaveAPIEndpoint(endpoint); err != nil {
			k.db.AddLog(scan.ID, "warning", "Failed to save endpoint: "+err.Error())
		} else {
			endpointsFound++
			k.db.AddLog(scan.ID, "info", fmt.Sprintf("[%d] %s %s", result.StatusCode, result.Method, result.URL))
		}
	}

	k.db.UpdateAPIScanStatus(scan.ID, "running", 90, nil)
	k.db.AddLog(scan.ID, "info", fmt.Sprintf("Kiterunner completed. Found %d API endpoints", endpointsFound))

	return nil
}

// parseTextOutput parses Kiterunner's text output format
func (k *KiterunnerScanner) parseTextOutput(line, target string) *models.APIEndpoint {
	// Example: GET     200 [    1234,    10,   3] https://example.com/api/v1/users
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil
	}

	method := parts[0]
	if method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" &&
		method != "PATCH" && method != "HEAD" && method != "OPTIONS" {
		return nil
	}

	var statusCode int
	fmt.Sscanf(parts[1], "%d", &statusCode)
	if statusCode == 0 {
		return nil
	}

	// Find URL (usually last part or after brackets)
	url := ""
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasPrefix(parts[i], "http") {
			url = parts[i]
			break
		}
	}
	if url == "" {
		return nil
	}

	return &models.APIEndpoint{
		ID:         uuid.New(),
		URL:        url,
		Method:     method,
		StatusCode: statusCode,
		CreatedAt:  time.Now(),
	}
}

// ScanWithRoutes runs Kiterunner with specific routes
func (k *KiterunnerScanner) ScanWithRoutes(ctx context.Context, scan *models.APIScan, routes []string) error {
	k.db.AddLog(scan.ID, "info", fmt.Sprintf("Scanning %d custom routes", len(routes)))

	for i, route := range routes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		progress := 10 + int(float64(i+1)/float64(len(routes))*80)
		k.db.UpdateAPIScanStatus(scan.ID, "running", progress, nil)

		fullURL := scan.Target + route

		// Probe each route
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			endpoint, err := k.probeEndpoint(ctx, fullURL, method)
			if err != nil {
				continue
			}
			if endpoint != nil && endpoint.StatusCode != 404 {
				endpoint.ScanID = scan.ID
				endpoint.Source = "kiterunner"
				k.db.SaveAPIEndpoint(endpoint)
				k.db.AddLog(scan.ID, "info", fmt.Sprintf("[%d] %s %s", endpoint.StatusCode, method, fullURL))
			}
		}
	}

	return nil
}

func (k *KiterunnerScanner) probeEndpoint(ctx context.Context, url, method string) (*models.APIEndpoint, error) {
	args := []string{
		"brute", url,
		"-X", method,
		"-o", "json",
		"--timeout", "5",
	}

	cmd := exec.CommandContext(ctx, k.kiterunnerPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var result KiterunnerResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	contentType := result.ContentType
	return &models.APIEndpoint{
		ID:          uuid.New(),
		URL:         url,
		Method:      method,
		StatusCode:  result.StatusCode,
		ContentType: &contentType,
		Length:      result.Length,
		CreatedAt:   time.Now(),
	}, nil
}
