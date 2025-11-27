package models

import (
	"time"

	"github.com/google/uuid"
)

// CloudScan represents a cloud security scan
type CloudScan struct {
	ID           uuid.UUID         `json:"id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`     // aws, azure, gcp, docker
	ScanType     string            `json:"scan_type"`    // scoutsuite, prowler, trivy, full
	Target       string            `json:"target"`       // account, subscription, project, or image
	Status       string            `json:"status"`       // pending, running, completed, failed, cancelled
	Progress     int               `json:"progress"`
	Config       *CloudScanConfig  `json:"config,omitempty"`
	Summary      *CloudScanSummary `json:"summary,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	CompletedAt  *time.Time        `json:"completed_at,omitempty"`
}

// CloudScanConfig contains scan configuration options
type CloudScanConfig struct {
	// AWS Configuration
	AWSProfile       string   `json:"aws_profile,omitempty"`
	AWSRegions       []string `json:"aws_regions,omitempty"`
	AWSServices      []string `json:"aws_services,omitempty"`

	// Azure Configuration
	AzureSubscription string `json:"azure_subscription,omitempty"`
	AzureTenantID     string `json:"azure_tenant_id,omitempty"`

	// GCP Configuration
	GCPProject string `json:"gcp_project,omitempty"`

	// Trivy Configuration
	TrivyTarget       string   `json:"trivy_target,omitempty"`       // image name, filesystem path, or repo URL
	TrivyTargetType   string   `json:"trivy_target_type,omitempty"`  // image, fs, repo, config
	TrivySeverities   []string `json:"trivy_severities,omitempty"`   // CRITICAL, HIGH, MEDIUM, LOW
	TrivyIgnoreUnfixed bool    `json:"trivy_ignore_unfixed,omitempty"`

	// ScoutSuite Configuration
	ScoutSuiteServices []string `json:"scoutsuite_services,omitempty"`
	ScoutSuiteRules    []string `json:"scoutsuite_rules,omitempty"`

	// Prowler Configuration
	ProwlerChecks    []string `json:"prowler_checks,omitempty"`
	ProwlerCompliance string  `json:"prowler_compliance,omitempty"` // cis, pci, hipaa, etc.

	// General
	Timeout int `json:"timeout,omitempty"` // seconds
}

// CloudScanSummary contains scan summary
type CloudScanSummary struct {
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
	Passed        int `json:"passed"`
}

// CloudFinding represents a security finding
type CloudFinding struct {
	ID          uuid.UUID  `json:"id"`
	ScanID      uuid.UUID  `json:"scan_id"`
	Provider    string     `json:"provider"`
	Service     string     `json:"service"`
	Region      string     `json:"region,omitempty"`
	ResourceID  string     `json:"resource_id,omitempty"`
	ResourceARN string     `json:"resource_arn,omitempty"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Severity    string     `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Status      string     `json:"status"`   // FAIL, PASS, WARNING
	Compliance  []string   `json:"compliance,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	Source      string     `json:"source"` // scoutsuite, prowler, trivy
	RawData     string     `json:"raw_data,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// VulnerabilityResult represents a Trivy vulnerability finding
type VulnerabilityResult struct {
	ID              uuid.UUID `json:"id"`
	ScanID          uuid.UUID `json:"scan_id"`
	Target          string    `json:"target"`
	TargetType      string    `json:"target_type"`
	VulnerabilityID string    `json:"vulnerability_id"` // CVE ID
	PkgName         string    `json:"pkg_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion    string    `json:"fixed_version,omitempty"`
	Severity        string    `json:"severity"`
	Title           string    `json:"title"`
	Description     string    `json:"description,omitempty"`
	References      []string  `json:"references,omitempty"`
	CVSS            float64   `json:"cvss,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// ScanLog represents a log entry
type ScanLog struct {
	ID        uuid.UUID `json:"id"`
	ScanID    uuid.UUID `json:"scan_id"`
	Level     string    `json:"level"` // info, warning, error
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateCloudScanRequest represents the request to create a scan
type CreateCloudScanRequest struct {
	Name     string           `json:"name" binding:"required"`
	Provider string           `json:"provider" binding:"required"`
	ScanType string           `json:"scan_type" binding:"required"`
	Target   string           `json:"target"`
	Config   *CloudScanConfig `json:"config,omitempty"`
}
