package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/web-service/internal/database"
)

// FfufScanner handles web fuzzing with ffuf
type FfufScanner struct {
	db            *database.Database
	ffufPath      string
	wordlistsPath string
}

// FfufResult represents a single ffuf finding
type FfufResult struct {
	Input       map[string]string `json:"input"`
	Position    int               `json:"position"`
	Status      int               `json:"status"`
	Length      int               `json:"length"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content-type"`
	Redirecturl string            `json:"redirectlocation"`
	ResultFile  string            `json:"resultfile"`
	URL         string            `json:"url"`
	Duration    int64             `json:"duration"`
	Host        string            `json:"host"`
}

// FfufOutput represents the full ffuf JSON output
type FfufOutput struct {
	CommandLine string       `json:"commandline"`
	Time        string       `json:"time"`
	Results     []FfufResult `json:"results"`
	Config      struct {
		URL       string `json:"url"`
		Wordlist  string `json:"wordlist"`
		Method    string `json:"method"`
		Threads   int    `json:"threads"`
		Timeout   int    `json:"timeout"`
		MatchCode string `json:"mc"`
	} `json:"config"`
}

// FfufScanConfig holds configuration for a ffuf scan
type FfufScanConfig struct {
	URL          string   `json:"url"`
	Wordlist     string   `json:"wordlist"`      // Name of wordlist (common, directory-list-small, etc.)
	Method       string   `json:"method"`        // GET, POST, etc.
	Threads      int      `json:"threads"`       // Number of threads
	Timeout      int      `json:"timeout"`       // Request timeout in seconds
	MatchCodes   []int    `json:"match_codes"`   // HTTP status codes to match
	FilterCodes  []int    `json:"filter_codes"`  // HTTP status codes to filter
	FilterSize   []int    `json:"filter_size"`   // Response sizes to filter
	Extensions   []string `json:"extensions"`    // File extensions to append
	Headers      []string `json:"headers"`       // Custom headers
	Recursion    bool     `json:"recursion"`     // Enable recursion
	RecursionDepth int    `json:"recursion_depth"`
}

// NewFfufScanner creates a new ffuf scanner
func NewFfufScanner(db *database.Database, ffufPath, wordlistsPath string) *FfufScanner {
	return &FfufScanner{
		db:            db,
		ffufPath:      ffufPath,
		wordlistsPath: wordlistsPath,
	}
}

// GetAvailableWordlists returns list of available wordlists
func (s *FfufScanner) GetAvailableWordlists() []map[string]string {
	return []map[string]string{
		{"name": "common", "file": "common.txt", "description": "Common web paths (~4700 entries)"},
		{"name": "directory-list-small", "file": "directory-list-small.txt", "description": "Directory list small (~87000 entries)"},
		{"name": "raft-medium-directories", "file": "raft-medium-directories.txt", "description": "Raft medium directories (~30000 entries)"},
		{"name": "raft-medium-files", "file": "raft-medium-files.txt", "description": "Raft medium files (~17000 entries)"},
	}
}

// ExecuteScan runs a ffuf scan
func (s *FfufScanner) ExecuteScan(ctx context.Context, scanID uuid.UUID, config FfufScanConfig) error {
	// Update scan status to running
	s.updateScanStatus(scanID, "running", 0)
	s.addLog(scanID, "info", fmt.Sprintf("Starting ffuf scan on target: %s", config.URL))

	// Determine wordlist path
	wordlistPath := filepath.Join(s.wordlistsPath, config.Wordlist+".txt")
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		// Try with .txt already in name
		wordlistPath = filepath.Join(s.wordlistsPath, config.Wordlist)
		if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
			s.updateScanStatus(scanID, "failed", 0)
			s.addLog(scanID, "error", fmt.Sprintf("Wordlist not found: %s", config.Wordlist))
			return fmt.Errorf("wordlist not found: %s", config.Wordlist)
		}
	}

	// Create temp file for JSON output
	outputFile := fmt.Sprintf("/tmp/ffuf_%s.json", scanID.String())
	defer os.Remove(outputFile)

	// Build ffuf command
	args := []string{
		"-u", config.URL,
		"-w", wordlistPath,
		"-o", outputFile,
		"-of", "json",
		"-noninteractive",
	}

	// Set method
	if config.Method != "" {
		args = append(args, "-X", config.Method)
	}

	// Set threads
	threads := config.Threads
	if threads <= 0 {
		threads = 40
	}
	args = append(args, "-t", fmt.Sprintf("%d", threads))

	// Set timeout
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	args = append(args, "-timeout", fmt.Sprintf("%d", timeout))

	// Match codes
	if len(config.MatchCodes) > 0 {
		codes := ""
		for i, c := range config.MatchCodes {
			if i > 0 {
				codes += ","
			}
			codes += fmt.Sprintf("%d", c)
		}
		args = append(args, "-mc", codes)
	}

	// Filter codes
	if len(config.FilterCodes) > 0 {
		codes := ""
		for i, c := range config.FilterCodes {
			if i > 0 {
				codes += ","
			}
			codes += fmt.Sprintf("%d", c)
		}
		args = append(args, "-fc", codes)
	}

	// Filter size
	if len(config.FilterSize) > 0 {
		sizes := ""
		for i, s := range config.FilterSize {
			if i > 0 {
				sizes += ","
			}
			sizes += fmt.Sprintf("%d", s)
		}
		args = append(args, "-fs", sizes)
	}

	// Extensions
	if len(config.Extensions) > 0 {
		exts := ""
		for i, e := range config.Extensions {
			if i > 0 {
				exts += ","
			}
			exts += e
		}
		args = append(args, "-e", exts)
	}

	// Headers
	for _, h := range config.Headers {
		args = append(args, "-H", h)
	}

	// Recursion
	if config.Recursion {
		args = append(args, "-recursion")
		if config.RecursionDepth > 0 {
			args = append(args, "-recursion-depth", fmt.Sprintf("%d", config.RecursionDepth))
		}
	}

	s.addLog(scanID, "info", fmt.Sprintf("Executing: %s %v", s.ffufPath, args))

	// Execute ffuf
	cmd := exec.CommandContext(ctx, s.ffufPath, args...)

	// Capture stderr for progress
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		s.updateScanStatus(scanID, "failed", 0)
		s.addLog(scanID, "error", fmt.Sprintf("Failed to start ffuf: %v", err))
		return err
	}

	// Read progress from stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			s.addLog(scanID, "debug", line)
		}
	}()

	// Wait for completion
	if err := cmd.Wait(); err != nil {
		// ffuf returns non-zero on no results, which is OK
		log.Printf("ffuf exited with: %v", err)
	}

	// Parse results
	s.updateScanStatus(scanID, "running", 80)

	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		s.addLog(scanID, "warning", "No results file generated (target may be unreachable)")
		s.updateScanStatus(scanID, "completed", 100)
		return nil
	}

	var output FfufOutput
	if err := json.Unmarshal(outputData, &output); err != nil {
		s.addLog(scanID, "error", fmt.Sprintf("Failed to parse ffuf output: %v", err))
		s.updateScanStatus(scanID, "failed", 100)
		return err
	}

	// Save results
	for _, result := range output.Results {
		s.saveFfufResult(scanID, result)
	}

	s.addLog(scanID, "info", fmt.Sprintf("Scan completed. Found %d results", len(output.Results)))
	s.updateScanStatus(scanID, "completed", 100)

	return nil
}

func (s *FfufScanner) saveFfufResult(scanID uuid.UUID, result FfufResult) {
	query := `
		INSERT INTO web_scan_results (id, scan_id, tool, url, status_code, content_length,
			words, lines, content_type, redirect_url, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	metadata, _ := json.Marshal(map[string]interface{}{
		"position": result.Position,
		"duration": result.Duration,
		"input":    result.Input,
		"host":     result.Host,
	})

	_, err := s.db.Pool.Exec(context.Background(), query,
		uuid.New(), scanID, "ffuf", result.URL, result.Status, result.Length,
		result.Words, result.Lines, result.ContentType, result.Redirecturl,
		metadata, time.Now())

	if err != nil {
		log.Printf("Failed to save ffuf result: %v", err)
	}
}

func (s *FfufScanner) updateScanStatus(scanID uuid.UUID, status string, progress int) {
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

func (s *FfufScanner) addLog(scanID uuid.UUID, level, message string) {
	query := `INSERT INTO web_scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	s.db.Pool.Exec(context.Background(), query, uuid.New(), scanID, level, message, time.Now())
	log.Printf("[%s] %s: %s", scanID.String()[:8], level, message)
}
