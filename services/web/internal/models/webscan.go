package models

import (
	"time"

	"github.com/google/uuid"
)

// WebScan represents a web scanning task (ffuf, gowitness, testssl)
type WebScan struct {
	ID            uuid.UUID              `json:"id"`
	Name          string                 `json:"name"`
	Target        string                 `json:"target"`
	Tool          string                 `json:"tool"`   // ffuf, gowitness, testssl
	Status        string                 `json:"status"` // pending, running, completed, failed, cancelled
	Progress      int                    `json:"progress"`
	CreatedAt     time.Time              `json:"created_at"`
	StartedAt     *time.Time             `json:"started_at,omitempty"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage  *string                `json:"error_message,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
}

// WebScanResult represents a single result from a web scan
type WebScanResult struct {
	ID             uuid.UUID              `json:"id"`
	ScanID         uuid.UUID              `json:"scan_id"`
	Tool           string                 `json:"tool"`
	URL            string                 `json:"url"`
	StatusCode     int                    `json:"status_code,omitempty"`
	ContentLength  int                    `json:"content_length,omitempty"`
	Words          int                    `json:"words,omitempty"`
	Lines          int                    `json:"lines,omitempty"`
	ContentType    string                 `json:"content_type,omitempty"`
	RedirectURL    string                 `json:"redirect_url,omitempty"`
	Title          string                 `json:"title,omitempty"`
	ScreenshotPath string                 `json:"screenshot_path,omitempty"`
	ScreenshotB64  string                 `json:"screenshot_b64,omitempty"`
	FindingID      string                 `json:"finding_id,omitempty"`
	Severity       string                 `json:"severity,omitempty"`
	FindingText    string                 `json:"finding_text,omitempty"`
	CVE            string                 `json:"cve,omitempty"`
	CWE            string                 `json:"cwe,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// WebScanLog represents a log entry for a web scan
type WebScanLog struct {
	ID        uuid.UUID `json:"id"`
	ScanID    uuid.UUID `json:"scan_id"`
	Level     string    `json:"level"` // info, warning, error, debug
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateFfufScanRequest represents the request to create a ffuf scan
type CreateFfufScanRequest struct {
	Name           string   `json:"name"`
	URL            string   `json:"url"`            // URL with FUZZ keyword
	Wordlist       string   `json:"wordlist"`       // Wordlist name
	Method         string   `json:"method"`         // HTTP method
	Threads        int      `json:"threads"`        // Number of threads
	Timeout        int      `json:"timeout"`        // Request timeout
	MatchCodes     []int    `json:"match_codes"`    // HTTP codes to match
	FilterCodes    []int    `json:"filter_codes"`   // HTTP codes to filter
	FilterSize     []int    `json:"filter_size"`    // Response sizes to filter
	Extensions     []string `json:"extensions"`     // File extensions
	Headers        []string `json:"headers"`        // Custom headers
	Recursion      bool     `json:"recursion"`      // Enable recursion
	RecursionDepth int      `json:"recursion_depth"`
}

// CreateGowintessScanRequest represents the request to create a gowitness scan
type CreateGowintessScanRequest struct {
	Name       string   `json:"name"`
	URLs       []string `json:"urls"`       // List of URLs
	Timeout    int      `json:"timeout"`    // Timeout per URL
	Resolution string   `json:"resolution"` // Screen resolution
	Delay      int      `json:"delay"`      // Delay before screenshot
	UserAgent  string   `json:"user_agent"` // Custom user agent
	FullPage   bool     `json:"full_page"`  // Capture full page
}

// CreateTestsslScanRequest represents the request to create a testssl scan
type CreateTestsslScanRequest struct {
	Name            string `json:"name"`
	Target          string `json:"target"`          // hostname:port
	Protocols       bool   `json:"protocols"`       // Check protocols
	Ciphers         bool   `json:"ciphers"`         // Check ciphers
	Vulnerabilities bool   `json:"vulnerabilities"` // Check vulnerabilities
	Headers         bool   `json:"headers"`         // Check HTTP headers
	Certificate     bool   `json:"certificate"`     // Check certificate
	Full            bool   `json:"full"`            // Full scan
	Fast            bool   `json:"fast"`            // Fast mode
	SNI             string `json:"sni"`             // Server Name Indication
	StartTLS        string `json:"starttls"`        // starttls protocol
}

// WebScanStats represents statistics for a web scan
type WebScanStats struct {
	Total          int            `json:"total"`
	ByStatusCode   map[int]int    `json:"by_status_code,omitempty"`  // ffuf
	BySeverity     map[string]int `json:"by_severity,omitempty"`     // testssl
	UniqueURLs     int            `json:"unique_urls,omitempty"`
	Screenshots    int            `json:"screenshots,omitempty"`     // gowitness
}

// WebScanTemplate represents a predefined web scan template
type WebScanTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Tool        string                 `json:"tool"` // ffuf, gowitness, testssl
	Category    string                 `json:"category"`
	Config      map[string]interface{} `json:"config"`
	IsDefault   bool                   `json:"is_default"`
}
