package models

import (
	"time"

	"github.com/google/uuid"
)

// CMSScan represents a CMS detection scan
type CMSScan struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Target    string     `json:"target"`
	ScanType  string     `json:"scan_type"` // whatweb, cmseek, wpscan, full
	Status    string     `json:"status"`    // pending, running, completed, failed, cancelled
	Progress  int        `json:"progress"`
	Config    *CMSScanConfig `json:"config,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// CMSScanConfig holds configuration for CMS scans
type CMSScanConfig struct {
	// WhatWeb options
	WhatWebAggression int    `json:"whatweb_aggression,omitempty"` // 1-4, default 1
	WhatWebPlugins    string `json:"whatweb_plugins,omitempty"`

	// CMSeeK options
	CMSeeKFollowRedirect bool `json:"cmseek_follow_redirect,omitempty"`
	CMSeeKRandomAgent    bool `json:"cmseek_random_agent,omitempty"`

	// WPScan options
	WPScanAPIToken      string   `json:"wpscan_api_token,omitempty"`
	WPScanEnumerate     []string `json:"wpscan_enumerate,omitempty"` // vp, ap, u, etc.
	WPScanDetectionMode string   `json:"wpscan_detection_mode,omitempty"` // mixed, passive, aggressive

	// JoomScan options
	JoomScanEnumComponents bool `json:"joomscan_enum_components,omitempty"`

	// Droopescan options
	DroopescanCMS string `json:"droopescan_cms,omitempty"` // drupal, joomla, moodle, silverstripe, auto

	// General options
	Timeout int               `json:"timeout,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// CMSResult represents detected CMS information
type CMSResult struct {
	ID          uuid.UUID  `json:"id"`
	ScanID      uuid.UUID  `json:"scan_id"`
	URL         string     `json:"url"`
	CMSName     string     `json:"cms_name"`
	CMSVersion  *string    `json:"cms_version,omitempty"`
	Confidence  int        `json:"confidence"` // 0-100
	Source      string     `json:"source"`     // whatweb, cmseek, wpscan
	Details     *string    `json:"details,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Technology represents detected technology/framework
type Technology struct {
	ID          uuid.UUID  `json:"id"`
	ScanID      uuid.UUID  `json:"scan_id"`
	URL         string     `json:"url"`
	Category    string     `json:"category"`  // cms, framework, server, language, etc.
	Name        string     `json:"name"`
	Version     *string    `json:"version,omitempty"`
	Confidence  int        `json:"confidence"`
	Source      string     `json:"source"`
	CreatedAt   time.Time  `json:"created_at"`
}

// WPScanResult represents WordPress-specific scan results
type WPScanResult struct {
	ID            uuid.UUID  `json:"id"`
	ScanID        uuid.UUID  `json:"scan_id"`
	URL           string     `json:"url"`
	WPVersion     *string    `json:"wp_version,omitempty"`
	MainTheme     *string    `json:"main_theme,omitempty"`
	ThemeVersion  *string    `json:"theme_version,omitempty"`
	Plugins       []WPPlugin `json:"plugins,omitempty"`
	Users         []WPUser   `json:"users,omitempty"`
	Vulnerabilities []WPVuln `json:"vulnerabilities,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// WPPlugin represents a WordPress plugin
type WPPlugin struct {
	Name          string  `json:"name"`
	Version       *string `json:"version,omitempty"`
	LatestVersion *string `json:"latest_version,omitempty"`
	Outdated      bool    `json:"outdated"`
	Location      string  `json:"location"`
	Vulnerabilities int   `json:"vulnerabilities"`
}

// WPUser represents a WordPress user
type WPUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Source   string `json:"source"` // author-sitemap, rss, etc.
}

// WPVuln represents a WordPress vulnerability
type WPVuln struct {
	Title     string   `json:"title"`
	Type      string   `json:"type"` // XSS, SQLi, RCE, etc.
	CVE       *string  `json:"cve,omitempty"`
	CVSS      *float64 `json:"cvss,omitempty"`
	Component string   `json:"component"` // core, plugin name, theme name
	Reference string   `json:"reference,omitempty"`
}

// ScanLog represents a log entry for a scan
type ScanLog struct {
	ID        uuid.UUID `json:"id"`
	ScanID    uuid.UUID `json:"scan_id"`
	Level     string    `json:"level"` // info, warning, error
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateCMSScanRequest represents a request to create a new CMS scan
type CreateCMSScanRequest struct {
	Name     string         `json:"name" binding:"required"`
	Target   string         `json:"target" binding:"required"`
	ScanType string         `json:"scan_type" binding:"required"`
	Config   *CMSScanConfig `json:"config,omitempty"`
}
