package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
)

type WhatWebScanner struct {
	db          *database.Database
	whatwebPath string
}

func NewWhatWebScanner(db *database.Database, whatwebPath string) *WhatWebScanner {
	return &WhatWebScanner{
		db:          db,
		whatwebPath: whatwebPath,
	}
}

// WhatWebJSONResult represents the JSON output from WhatWeb
type WhatWebJSONResult struct {
	Target     string                            `json:"target"`
	HTTPStatus int                               `json:"http_status"`
	Plugins    map[string]map[string]interface{} `json:"plugins"`
}

type WhatWebHTTP struct {
	Status int    `json:"status"`
	URI    string `json:"uri"`
}

func (w *WhatWebScanner) Scan(ctx context.Context, scan *models.CMSScan, config *models.CMSScanConfig) error {
	w.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	w.db.AddLog(scan.ID, "info", "Starting WhatWeb scan for "+scan.Target)

	// Build command
	aggression := 1
	if config != nil && config.WhatWebAggression > 0 && config.WhatWebAggression <= 4 {
		aggression = config.WhatWebAggression
	}

	args := []string{
		"-a", strconv.Itoa(aggression),
		"--log-json=-", // Output JSON to stdout
		"--color=never",
		"--no-errors",
	}

	// Add custom plugins if specified
	if config != nil && config.WhatWebPlugins != "" {
		args = append(args, "--plugins", config.WhatWebPlugins)
	}

	// Add custom headers
	if config != nil && len(config.Headers) > 0 {
		for key, value := range config.Headers {
			args = append(args, "--header", fmt.Sprintf("%s:%s", key, value))
		}
	}

	args = append(args, scan.Target)

	w.db.AddLog(scan.ID, "info", "Running: whatweb "+strings.Join(args, " "))
	w.db.UpdateScanStatus(scan.ID, "running", 10, nil)

	// Set timeout
	timeout := 5 * time.Minute
	if config != nil && config.Timeout > 0 {
		timeout = time.Duration(config.Timeout) * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, w.whatwebPath, args...)

	// Capture stdout and stderr separately
	// WhatWeb has a known bug where it exits with status 1 due to IOError on close
	// The error goes to stderr, but the JSON output goes to stdout
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	output := stdout.Bytes()

	if runErr != nil {
		// Only log as warning if we got no output at all
		if len(output) == 0 {
			w.db.AddLog(scan.ID, "warning", "WhatWeb finished with error: "+runErr.Error())
			if stderr.Len() > 0 {
				w.db.AddLog(scan.ID, "warning", "Stderr: "+stderr.String())
			}
		} else {
			w.db.AddLog(scan.ID, "info", "WhatWeb finished (exit code indicates Ruby IOError on close - results may still be valid)")
		}
	}

	w.db.UpdateScanStatus(scan.ID, "running", 50, nil)
	w.db.AddLog(scan.ID, "info", "Parsing WhatWeb results...")

	// Parse JSON output
	techsFound := 0
	cmsFound := 0

	// WhatWeb JSON output can be either:
	// 1. A JSON array: [{...}, {...}]
	// 2. Individual JSON objects per line: {...}\n{...}
	// 3. Text output (non-JSON)

	outputStr := string(output)

	// First, try parsing as JSON array
	var results []WhatWebJSONResult
	if err := json.Unmarshal([]byte(outputStr), &results); err == nil {
		for _, result := range results {
			techsFound += w.processWhatWebResult(result, scan)
		}
	} else {
		// Try parsing line by line
		scanner := bufio.NewScanner(strings.NewReader(outputStr))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			// Skip error messages from Ruby
			if strings.Contains(line, "IOError") || strings.Contains(line, ".rb:") {
				continue
			}

			if !strings.HasPrefix(line, "{") && !strings.HasPrefix(line, "[") {
				// Try parsing as text output
				techs, cms := w.parseTextOutput(line, scan)
				techsFound += techs
				cmsFound += cms
				continue
			}

			var result WhatWebJSONResult
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				continue
			}
			techsFound += w.processWhatWebResult(result, scan)
		}
	}

	w.db.UpdateScanStatus(scan.ID, "running", 90, nil)
	w.db.AddLog(scan.ID, "info", fmt.Sprintf("WhatWeb completed. Found %d technologies, %d CMS", techsFound, cmsFound))

	return nil
}

// processWhatWebResult processes a single WhatWeb JSON result and saves technologies/CMS to database
func (w *WhatWebScanner) processWhatWebResult(result WhatWebJSONResult, scan *models.CMSScan) int {
	techsFound := 0

	for pluginName, pluginData := range result.Plugins {
		tech := w.processPlugin(pluginName, pluginData, scan.ID, result.Target)
		if tech != nil {
			if err := w.db.SaveTechnology(tech); err == nil {
				techsFound++
				w.db.AddLog(scan.ID, "info", fmt.Sprintf("Found %s: %s", tech.Category, tech.Name))

				// Check if this is a CMS
				if w.isCMS(pluginName) {
					cmsResult := &models.CMSResult{
						ID:         uuid.New(),
						ScanID:     scan.ID,
						URL:        result.Target,
						CMSName:    tech.Name,
						CMSVersion: tech.Version,
						Confidence: tech.Confidence,
						Source:     "whatweb",
						CreatedAt:  time.Now(),
					}
					w.db.SaveCMSResult(cmsResult)
				}
			}
		}
	}

	return techsFound
}

func (w *WhatWebScanner) processPlugin(name string, data map[string]interface{}, scanID uuid.UUID, url string) *models.Technology {
	tech := &models.Technology{
		ID:         uuid.New(),
		ScanID:     scanID,
		URL:        url,
		Category:   w.getCategory(name),
		Name:       name,
		Confidence: 100,
		Source:     "whatweb",
		CreatedAt:  time.Now(),
	}

	// Extract version if available
	// WhatWeb plugin data format: {"version": ["7.4.33"], "string": ["value"], "certainty": 100}
	if versions, ok := data["version"].([]interface{}); ok && len(versions) > 0 {
		if v, ok := versions[0].(string); ok {
			tech.Version = &v
		}
	}

	if certainty, ok := data["certainty"].(float64); ok {
		tech.Confidence = int(certainty)
	}

	// Also check for string values that might contain version info
	if strings, ok := data["string"].([]interface{}); ok {
		for _, s := range strings {
			if str, ok := s.(string); ok && w.looksLikeVersion(str) && tech.Version == nil {
				tech.Version = &str
				break
			}
		}
	}

	return tech
}

func (w *WhatWebScanner) getCategory(pluginName string) string {
	// Normalize plugin name for comparison (case-insensitive)
	lowerName := strings.ToLower(pluginName)

	// CMS plugins
	cmsPlugins := []string{
		"wordpress", "drupal", "joomla", "magento", "prestashop", "opencart",
		"shopify", "wix", "squarespace", "ghost", "typo3", "concrete5",
		"mediawiki", "phpbb", "vbulletin", "discourse", "moodle", "silverstripe",
		"expressionengine", "blogger", "tumblr", "weebly", "hugo", "jekyll",
		"hexo", "pelican", "grav", "october", "craft-cms", "processwire",
	}

	// Framework plugins
	frameworkPlugins := []string{
		"ruby-on-rails", "django", "laravel", "symfony", "asp.net", "express",
		"spring", "flask", "angular", "react", "vue", "next.js", "nuxt.js",
		"gatsby", "bootstrap", "jquery", "codeigniter", "cakephp", "yii",
	}

	// Server plugins - includes WhatWeb's HTTPServer plugin
	serverPlugins := []string{
		"apache", "nginx", "iis", "litespeed", "caddy", "tomcat", "jetty",
		"gunicorn", "httpserver", "openresty", "lighttpd", "cherokee",
	}

	// Language plugins
	languagePlugins := []string{
		"php", "python", "ruby", "java", "node.js", "perl", "x-powered-by",
	}

	// Security/Header plugins
	securityPlugins := []string{
		"x-frame-options", "x-xss-protection", "x-content-type-options",
		"strict-transport-security", "content-security-policy", "cookies",
		"uncommonheaders",
	}

	// Info plugins (metadata, not security-relevant)
	infoPlugins := []string{
		"title", "meta-author", "meta-generator", "html5", "html", "script",
		"ip", "country", "content-language", "charset", "favicon",
	}

	for _, cms := range cmsPlugins {
		if lowerName == cms || strings.Contains(lowerName, cms) {
			return "cms"
		}
	}
	for _, fw := range frameworkPlugins {
		if lowerName == fw || strings.Contains(lowerName, fw) {
			return "framework"
		}
	}
	for _, srv := range serverPlugins {
		if lowerName == srv || strings.Contains(lowerName, srv) {
			return "server"
		}
	}
	for _, lang := range languagePlugins {
		if lowerName == lang || strings.Contains(lowerName, lang) {
			return "language"
		}
	}
	for _, sec := range securityPlugins {
		if lowerName == sec || strings.Contains(lowerName, sec) {
			return "security"
		}
	}
	for _, info := range infoPlugins {
		if lowerName == info || strings.Contains(lowerName, info) {
			return "info"
		}
	}

	return "other"
}

func (w *WhatWebScanner) isCMS(pluginName string) bool {
	cmsNames := []string{
		"WordPress", "Drupal", "Joomla", "Magento", "PrestaShop", "OpenCart",
		"Shopify", "Wix", "Squarespace", "Ghost", "TYPO3", "Concrete5",
		"MediaWiki", "phpBB", "vBulletin", "Discourse", "Moodle", "SilverStripe",
		"ExpressionEngine", "Blogger", "Tumblr", "Weebly", "Hugo", "Jekyll",
		"Hexo", "Pelican", "Grav", "October", "Craft-CMS", "ProcessWire",
	}

	for _, cms := range cmsNames {
		if strings.EqualFold(pluginName, cms) {
			return true
		}
	}
	return false
}

func (w *WhatWebScanner) looksLikeVersion(s string) bool {
	versionRegex := regexp.MustCompile(`^\d+(\.\d+)+`)
	return versionRegex.MatchString(s)
}

func (w *WhatWebScanner) parseTextOutput(line string, scan *models.CMSScan) (int, int) {
	// Parse text format: URL [status] plugin[version], plugin[version]
	techsFound := 0
	cmsFound := 0

	// Extract URL and plugins
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return 0, 0
	}

	url := parts[0]
	remainder := parts[1]

	// Parse plugins from text format
	pluginRegex := regexp.MustCompile(`([A-Za-z0-9_-]+)\[([^\]]*)\]`)
	matches := pluginRegex.FindAllStringSubmatch(remainder, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			pluginName := match[1]
			var version *string
			if len(match) >= 3 && match[2] != "" {
				v := match[2]
				version = &v
			}

			tech := &models.Technology{
				ID:         uuid.New(),
				ScanID:     scan.ID,
				URL:        url,
				Category:   w.getCategory(pluginName),
				Name:       pluginName,
				Version:    version,
				Confidence: 100,
				Source:     "whatweb",
				CreatedAt:  time.Now(),
			}

			if err := w.db.SaveTechnology(tech); err == nil {
				techsFound++

				if w.isCMS(pluginName) {
					cmsResult := &models.CMSResult{
						ID:         uuid.New(),
						ScanID:     scan.ID,
						URL:        url,
						CMSName:    pluginName,
						CMSVersion: version,
						Confidence: 100,
						Source:     "whatweb",
						CreatedAt:  time.Now(),
					}
					w.db.SaveCMSResult(cmsResult)
					cmsFound++
				}
			}
		}
	}

	return techsFound, cmsFound
}
