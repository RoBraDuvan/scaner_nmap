package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/security-scanner/cms-service/internal/models"
)

type Database struct {
	db *sql.DB
}

func New(host, port, user, password, dbname string) (*Database, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	database := &Database{db: db}
	if err := database.createTables(); err != nil {
		return nil, err
	}

	return database, nil
}

func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS cms_scans (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			target TEXT NOT NULL,
			scan_type VARCHAR(50) NOT NULL,
			status VARCHAR(50) DEFAULT 'pending',
			progress INT DEFAULT 0,
			config JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cms_results (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES cms_scans(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			cms_name VARCHAR(255) NOT NULL,
			cms_version VARCHAR(100),
			confidence INT DEFAULT 0,
			source VARCHAR(50) NOT NULL,
			details TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cms_technologies (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES cms_scans(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			category VARCHAR(100) NOT NULL,
			name VARCHAR(255) NOT NULL,
			version VARCHAR(100),
			confidence INT DEFAULT 0,
			source VARCHAR(50) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cms_wpscan_results (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES cms_scans(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			wp_version VARCHAR(50),
			main_theme VARCHAR(255),
			theme_version VARCHAR(50),
			plugins JSONB,
			users JSONB,
			vulnerabilities JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cms_scan_logs (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES cms_scans(id) ON DELETE CASCADE,
			level VARCHAR(20) NOT NULL,
			message TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cms_results_scan_id ON cms_results(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cms_technologies_scan_id ON cms_technologies(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cms_wpscan_results_scan_id ON cms_wpscan_results(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cms_scan_logs_scan_id ON cms_scan_logs(scan_id)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

// Scan operations
func (d *Database) CreateScan(scan *models.CMSScan) error {
	var configJSON []byte
	var err error
	if scan.Config != nil {
		configJSON, err = json.Marshal(scan.Config)
		if err != nil {
			return err
		}
	}

	query := `INSERT INTO cms_scans (id, name, target, scan_type, status, progress, config, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err = d.db.Exec(query, scan.ID, scan.Name, scan.Target, scan.ScanType, scan.Status, scan.Progress, configJSON, scan.CreatedAt, scan.UpdatedAt)
	return err
}

func (d *Database) GetScan(id uuid.UUID) (*models.CMSScan, error) {
	query := `SELECT id, name, target, scan_type, status, progress, config, created_at, updated_at FROM cms_scans WHERE id = $1`
	row := d.db.QueryRow(query, id)

	var scan models.CMSScan
	var configJSON []byte
	err := row.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status, &scan.Progress, &configJSON, &scan.CreatedAt, &scan.UpdatedAt)
	if err != nil {
		return nil, err
	}

	if len(configJSON) > 0 {
		scan.Config = &models.CMSScanConfig{}
		json.Unmarshal(configJSON, scan.Config)
	}

	return &scan, nil
}

func (d *Database) GetAllScans() ([]models.CMSScan, error) {
	query := `SELECT id, name, target, scan_type, status, progress, config, created_at, updated_at FROM cms_scans ORDER BY created_at DESC`
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.CMSScan
	for rows.Next() {
		var scan models.CMSScan
		var configJSON []byte
		err := rows.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status, &scan.Progress, &configJSON, &scan.CreatedAt, &scan.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if len(configJSON) > 0 {
			scan.Config = &models.CMSScanConfig{}
			json.Unmarshal(configJSON, scan.Config)
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

func (d *Database) UpdateScanStatus(id uuid.UUID, status string, progress int, errorMsg *string) error {
	query := `UPDATE cms_scans SET status = $1, progress = $2, updated_at = $3 WHERE id = $4`
	_, err := d.db.Exec(query, status, progress, time.Now(), id)
	return err
}

func (d *Database) DeleteScan(id uuid.UUID) error {
	query := `DELETE FROM cms_scans WHERE id = $1`
	_, err := d.db.Exec(query, id)
	return err
}

// CMS Results operations
func (d *Database) SaveCMSResult(result *models.CMSResult) error {
	query := `INSERT INTO cms_results (id, scan_id, url, cms_name, cms_version, confidence, source, details, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := d.db.Exec(query, result.ID, result.ScanID, result.URL, result.CMSName, result.CMSVersion, result.Confidence, result.Source, result.Details, result.CreatedAt)
	return err
}

func (d *Database) GetCMSResults(scanID uuid.UUID) ([]models.CMSResult, error) {
	query := `SELECT id, scan_id, url, cms_name, cms_version, confidence, source, details, created_at FROM cms_results WHERE scan_id = $1 ORDER BY confidence DESC`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.CMSResult
	for rows.Next() {
		var result models.CMSResult
		err := rows.Scan(&result.ID, &result.ScanID, &result.URL, &result.CMSName, &result.CMSVersion, &result.Confidence, &result.Source, &result.Details, &result.CreatedAt)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// Technology operations
func (d *Database) SaveTechnology(tech *models.Technology) error {
	query := `INSERT INTO cms_technologies (id, scan_id, url, category, name, version, confidence, source, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := d.db.Exec(query, tech.ID, tech.ScanID, tech.URL, tech.Category, tech.Name, tech.Version, tech.Confidence, tech.Source, tech.CreatedAt)
	return err
}

func (d *Database) GetTechnologies(scanID uuid.UUID) ([]models.Technology, error) {
	query := `SELECT id, scan_id, url, category, name, version, confidence, source, created_at FROM cms_technologies WHERE scan_id = $1 ORDER BY category, name`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var techs []models.Technology
	for rows.Next() {
		var tech models.Technology
		err := rows.Scan(&tech.ID, &tech.ScanID, &tech.URL, &tech.Category, &tech.Name, &tech.Version, &tech.Confidence, &tech.Source, &tech.CreatedAt)
		if err != nil {
			return nil, err
		}
		techs = append(techs, tech)
	}

	return techs, nil
}

// WPScan Results operations
func (d *Database) SaveWPScanResult(result *models.WPScanResult) error {
	pluginsJSON, _ := json.Marshal(result.Plugins)
	usersJSON, _ := json.Marshal(result.Users)
	vulnsJSON, _ := json.Marshal(result.Vulnerabilities)

	query := `INSERT INTO cms_wpscan_results (id, scan_id, url, wp_version, main_theme, theme_version, plugins, users, vulnerabilities, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := d.db.Exec(query, result.ID, result.ScanID, result.URL, result.WPVersion, result.MainTheme, result.ThemeVersion, pluginsJSON, usersJSON, vulnsJSON, result.CreatedAt)
	return err
}

func (d *Database) GetWPScanResults(scanID uuid.UUID) ([]models.WPScanResult, error) {
	query := `SELECT id, scan_id, url, wp_version, main_theme, theme_version, plugins, users, vulnerabilities, created_at FROM cms_wpscan_results WHERE scan_id = $1`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.WPScanResult
	for rows.Next() {
		var result models.WPScanResult
		var pluginsJSON, usersJSON, vulnsJSON []byte
		err := rows.Scan(&result.ID, &result.ScanID, &result.URL, &result.WPVersion, &result.MainTheme, &result.ThemeVersion, &pluginsJSON, &usersJSON, &vulnsJSON, &result.CreatedAt)
		if err != nil {
			return nil, err
		}
		if len(pluginsJSON) > 0 {
			json.Unmarshal(pluginsJSON, &result.Plugins)
		}
		if len(usersJSON) > 0 {
			json.Unmarshal(usersJSON, &result.Users)
		}
		if len(vulnsJSON) > 0 {
			json.Unmarshal(vulnsJSON, &result.Vulnerabilities)
		}
		results = append(results, result)
	}

	return results, nil
}

// Log operations
func (d *Database) AddLog(scanID uuid.UUID, level, message string) error {
	query := `INSERT INTO cms_scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := d.db.Exec(query, uuid.New(), scanID, level, message, time.Now())
	return err
}

func (d *Database) GetLogs(scanID uuid.UUID) ([]models.ScanLog, error) {
	query := `SELECT id, scan_id, level, message, created_at FROM cms_scan_logs WHERE scan_id = $1 ORDER BY created_at`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.ScanLog
	for rows.Next() {
		var log models.ScanLog
		err := rows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}
