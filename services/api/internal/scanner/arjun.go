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

type ArjunScanner struct {
	db            *database.Database
	arjunPath     string
	wordlistsPath string
}

func NewArjunScanner(db *database.Database, arjunPath, wordlistsPath string) *ArjunScanner {
	return &ArjunScanner{
		db:            db,
		arjunPath:     arjunPath,
		wordlistsPath: wordlistsPath,
	}
}

// ArjunResult represents Arjun's JSON output
type ArjunResult struct {
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

// ArjunOutput represents the complete Arjun output
type ArjunOutput map[string]ArjunURLResult

type ArjunURLResult struct {
	Method string   `json:"method"`
	Params []string `json:"params"`
}

func (a *ArjunScanner) Scan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	a.db.UpdateAPIScanStatus(scan.ID, "running", 0, nil)
	a.db.AddLog(scan.ID, "info", "Starting Arjun parameter discovery for "+scan.Target)

	// Parse targets (can be comma-separated)
	targets := strings.Split(scan.Target, ",")
	for i, t := range targets {
		targets[i] = strings.TrimSpace(t)
	}

	// Determine methods to test
	methods := []string{"GET", "POST"}
	if config != nil && len(config.ArjunMethods) > 0 {
		methods = config.ArjunMethods
	}

	totalTasks := len(targets) * len(methods)
	tasksDone := 0
	totalParams := 0

	for _, target := range targets {
		for _, method := range methods {
			select {
			case <-ctx.Done():
				a.db.UpdateAPIScanStatus(scan.ID, "cancelled", 0, nil)
				return ctx.Err()
			default:
			}

			tasksDone++
			progress := int(float64(tasksDone) / float64(totalTasks) * 80)
			a.db.UpdateAPIScanStatus(scan.ID, "running", 10+progress, nil)

			a.db.AddLog(scan.ID, "info", fmt.Sprintf("Scanning %s with method %s", target, method))

			params, err := a.scanURL(ctx, target, method, config)
			if err != nil {
				a.db.AddLog(scan.ID, "warning", fmt.Sprintf("Error scanning %s: %s", target, err.Error()))
				continue
			}

			// Save discovered parameters
			for _, param := range params {
				apiParam := &models.APIParameter{
					ID:        uuid.New(),
					ScanID:    scan.ID,
					URL:       target,
					Name:      param,
					ParamType: getParamType(method),
					Method:    method,
					CreatedAt: time.Now(),
				}

				if err := a.db.SaveAPIParameter(apiParam); err != nil {
					a.db.AddLog(scan.ID, "warning", "Failed to save parameter: "+err.Error())
				} else {
					totalParams++
					a.db.AddLog(scan.ID, "info", fmt.Sprintf("Found parameter: %s (%s %s)", param, method, target))
				}
			}
		}
	}

	a.db.UpdateAPIScanStatus(scan.ID, "running", 95, nil)
	a.db.AddLog(scan.ID, "info", fmt.Sprintf("Arjun completed. Found %d parameters across %d targets", totalParams, len(targets)))

	return nil
}

func (a *ArjunScanner) scanURL(ctx context.Context, url, method string, config *models.APIScanConfig) ([]string, error) {
	args := []string{
		"-u", url,
		"-m", method,
		"-oJ", "/dev/stdout", // Output JSON to stdout
		"--stable",
	}

	// Add custom wordlist
	if config != nil && config.ArjunWordlist != "" {
		args = append(args, "-w", config.ArjunWordlist)
	}

	// Add threads
	threads := 10
	if config != nil && config.ArjunThreads > 0 {
		threads = config.ArjunThreads
	}
	args = append(args, "-t", fmt.Sprintf("%d", threads))

	// Add headers
	if config != nil && len(config.Headers) > 0 {
		for key, value := range config.Headers {
			args = append(args, "--headers", fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Set timeout
	timeout := 5 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, a.arjunPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Arjun may return non-zero if no params found
		if len(output) == 0 {
			return nil, err
		}
	}

	// Parse output
	return a.parseOutput(string(output), url)
}

func (a *ArjunScanner) parseOutput(output, targetURL string) ([]string, error) {
	var params []string

	// Try parsing as JSON first
	var jsonOutput ArjunOutput
	if err := json.Unmarshal([]byte(output), &jsonOutput); err == nil {
		for url, result := range jsonOutput {
			if strings.Contains(targetURL, url) || strings.Contains(url, targetURL) {
				params = append(params, result.Params...)
			}
		}
		return params, nil
	}

	// Try parsing as simple JSON array
	var simpleOutput map[string][]string
	if err := json.Unmarshal([]byte(output), &simpleOutput); err == nil {
		for _, p := range simpleOutput {
			params = append(params, p...)
		}
		return params, nil
	}

	// Parse text output
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for parameter indicators
		if strings.Contains(line, "parameter") || strings.Contains(line, "param") {
			// Extract parameter name
			parts := strings.Fields(line)
			for _, part := range parts {
				// Clean parameter name
				param := strings.Trim(part, "[]():,\"'")
				if len(param) > 0 && len(param) < 50 && !strings.Contains(param, " ") {
					// Basic validation
					if isValidParamName(param) {
						params = append(params, param)
					}
				}
			}
		}

		// Handle "Found: param1, param2, param3" format
		if strings.HasPrefix(strings.ToLower(line), "found:") {
			paramsStr := strings.TrimPrefix(strings.ToLower(line), "found:")
			for _, p := range strings.Split(paramsStr, ",") {
				p = strings.TrimSpace(p)
				if isValidParamName(p) {
					params = append(params, p)
				}
			}
		}
	}

	return params, nil
}

func getParamType(method string) string {
	switch method {
	case "GET":
		return "query"
	case "POST", "PUT", "PATCH":
		return "body"
	default:
		return "query"
	}
}

func isValidParamName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}

	// Skip common non-parameter words
	skipWords := []string{"found", "parameter", "param", "url", "method", "get", "post", "put", "delete",
		"the", "and", "for", "with", "from", "http", "https", "true", "false", "null"}
	nameLower := strings.ToLower(name)
	for _, word := range skipWords {
		if nameLower == word {
			return false
		}
	}

	// Must contain alphanumeric characters
	hasAlpha := false
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			hasAlpha = true
		} else if c != '[' && c != ']' {
			return false
		}
	}

	return hasAlpha
}

// ScanEndpoints scans discovered endpoints for parameters
func (a *ArjunScanner) ScanEndpoints(ctx context.Context, scan *models.APIScan, endpoints []models.APIEndpoint, config *models.APIScanConfig) error {
	a.db.AddLog(scan.ID, "info", fmt.Sprintf("Scanning %d endpoints for parameters", len(endpoints)))

	for i, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		progress := int(float64(i+1) / float64(len(endpoints)) * 100)
		a.db.UpdateAPIScanStatus(scan.ID, "running", progress, nil)

		params, err := a.scanURL(ctx, endpoint.URL, endpoint.Method, config)
		if err != nil {
			continue
		}

		for _, param := range params {
			apiParam := &models.APIParameter{
				ID:         uuid.New(),
				ScanID:     scan.ID,
				EndpointID: &endpoint.ID,
				URL:        endpoint.URL,
				Name:       param,
				ParamType:  getParamType(endpoint.Method),
				Method:     endpoint.Method,
				CreatedAt:  time.Now(),
			}
			a.db.SaveAPIParameter(apiParam)
		}
	}

	return nil
}
