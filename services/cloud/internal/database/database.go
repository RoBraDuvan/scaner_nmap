package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/security-scanner/cloud-service/internal/models"
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
	if err := database.initSchema(); err != nil {
		return nil, err
	}

	return database, nil
}

func (d *Database) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS cloud_scans (
		id UUID PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		provider VARCHAR(50) NOT NULL,
		scan_type VARCHAR(50) NOT NULL,
		target TEXT,
		status VARCHAR(50) NOT NULL DEFAULT 'pending',
		progress INTEGER DEFAULT 0,
		config JSONB,
		summary JSONB,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		completed_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS cloud_findings (
		id UUID PRIMARY KEY,
		scan_id UUID REFERENCES cloud_scans(id) ON DELETE CASCADE,
		provider VARCHAR(50) NOT NULL,
		service VARCHAR(100),
		region VARCHAR(50),
		resource_id TEXT,
		resource_arn TEXT,
		title TEXT NOT NULL,
		description TEXT,
		severity VARCHAR(20) NOT NULL,
		status VARCHAR(20) NOT NULL,
		compliance TEXT[],
		remediation TEXT,
		source VARCHAR(50) NOT NULL,
		raw_data TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS vulnerability_results (
		id UUID PRIMARY KEY,
		scan_id UUID REFERENCES cloud_scans(id) ON DELETE CASCADE,
		target TEXT NOT NULL,
		target_type VARCHAR(50),
		vulnerability_id VARCHAR(50) NOT NULL,
		pkg_name VARCHAR(255),
		installed_version VARCHAR(100),
		fixed_version VARCHAR(100),
		severity VARCHAR(20) NOT NULL,
		title TEXT,
		description TEXT,
		"references" TEXT[],
		cvss DECIMAL(3,1),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS cloud_scan_logs (
		id UUID PRIMARY KEY,
		scan_id UUID REFERENCES cloud_scans(id) ON DELETE CASCADE,
		level VARCHAR(20) NOT NULL,
		message TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_cloud_findings_scan_id ON cloud_findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_cloud_findings_severity ON cloud_findings(severity);
	CREATE INDEX IF NOT EXISTS idx_vulnerability_results_scan_id ON vulnerability_results(scan_id);
	CREATE INDEX IF NOT EXISTS idx_cloud_scan_logs_scan_id ON cloud_scan_logs(scan_id);
	`

	_, err := d.db.Exec(schema)
	return err
}

func (d *Database) Close() error {
	return d.db.Close()
}

// Scan operations
func (d *Database) CreateScan(scan *models.CloudScan) error {
	configJSON, _ := json.Marshal(scan.Config)
	summaryJSON, _ := json.Marshal(scan.Summary)

	_, err := d.db.Exec(`
		INSERT INTO cloud_scans (id, name, provider, scan_type, target, status, progress, config, summary, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, scan.ID, scan.Name, scan.Provider, scan.ScanType, scan.Target, scan.Status, scan.Progress, configJSON, summaryJSON, scan.CreatedAt, scan.UpdatedAt)

	return err
}

func (d *Database) GetScan(id uuid.UUID) (*models.CloudScan, error) {
	var scan models.CloudScan
	var configJSON, summaryJSON []byte
	var completedAt sql.NullTime

	err := d.db.QueryRow(`
		SELECT id, name, provider, scan_type, target, status, progress, config, summary, created_at, updated_at, completed_at
		FROM cloud_scans WHERE id = $1
	`, id).Scan(&scan.ID, &scan.Name, &scan.Provider, &scan.ScanType, &scan.Target, &scan.Status, &scan.Progress, &configJSON, &summaryJSON, &scan.CreatedAt, &scan.UpdatedAt, &completedAt)

	if err != nil {
		return nil, err
	}

	if configJSON != nil {
		json.Unmarshal(configJSON, &scan.Config)
	}
	if summaryJSON != nil {
		json.Unmarshal(summaryJSON, &scan.Summary)
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	return &scan, nil
}

func (d *Database) GetAllScans() ([]models.CloudScan, error) {
	rows, err := d.db.Query(`
		SELECT id, name, provider, scan_type, target, status, progress, config, summary, created_at, updated_at, completed_at
		FROM cloud_scans ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.CloudScan
	for rows.Next() {
		var scan models.CloudScan
		var configJSON, summaryJSON []byte
		var completedAt sql.NullTime

		if err := rows.Scan(&scan.ID, &scan.Name, &scan.Provider, &scan.ScanType, &scan.Target, &scan.Status, &scan.Progress, &configJSON, &summaryJSON, &scan.CreatedAt, &scan.UpdatedAt, &completedAt); err != nil {
			continue
		}

		if configJSON != nil {
			json.Unmarshal(configJSON, &scan.Config)
		}
		if summaryJSON != nil {
			json.Unmarshal(summaryJSON, &scan.Summary)
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}

		scans = append(scans, scan)
	}

	return scans, nil
}

func (d *Database) UpdateScanStatus(id uuid.UUID, status string, progress int, summary *models.CloudScanSummary) error {
	summaryJSON, _ := json.Marshal(summary)

	var completedAt interface{}
	if status == "completed" || status == "failed" || status == "cancelled" {
		now := time.Now()
		completedAt = &now
	}

	_, err := d.db.Exec(`
		UPDATE cloud_scans SET status = $1, progress = $2, summary = $3, updated_at = $4, completed_at = $5 WHERE id = $6
	`, status, progress, summaryJSON, time.Now(), completedAt, id)

	return err
}

func (d *Database) DeleteScan(id uuid.UUID) error {
	_, err := d.db.Exec(`DELETE FROM cloud_scans WHERE id = $1`, id)
	return err
}

// Finding operations
func (d *Database) SaveFinding(finding *models.CloudFinding) error {
	_, err := d.db.Exec(`
		INSERT INTO cloud_findings (id, scan_id, provider, service, region, resource_id, resource_arn, title, description, severity, status, compliance, remediation, source, raw_data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`, finding.ID, finding.ScanID, finding.Provider, finding.Service, finding.Region, finding.ResourceID, finding.ResourceARN, finding.Title, finding.Description, finding.Severity, finding.Status, pq.Array(finding.Compliance), finding.Remediation, finding.Source, finding.RawData, finding.CreatedAt)

	return err
}

func (d *Database) GetFindings(scanID uuid.UUID) ([]models.CloudFinding, error) {
	rows, err := d.db.Query(`
		SELECT id, scan_id, provider, service, region, resource_id, resource_arn, title, description, severity, status, compliance, remediation, source, raw_data, created_at
		FROM cloud_findings WHERE scan_id = $1 ORDER BY
			CASE severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END, created_at DESC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.CloudFinding
	for rows.Next() {
		var f models.CloudFinding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Provider, &f.Service, &f.Region, &f.ResourceID, &f.ResourceARN, &f.Title, &f.Description, &f.Severity, &f.Status, pq.Array(&f.Compliance), &f.Remediation, &f.Source, &f.RawData, &f.CreatedAt); err != nil {
			continue
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// Vulnerability operations
func (d *Database) SaveVulnerability(vuln *models.VulnerabilityResult) error {
	_, err := d.db.Exec(`
		INSERT INTO vulnerability_results (id, scan_id, target, target_type, vulnerability_id, pkg_name, installed_version, fixed_version, severity, title, description, "references", cvss, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, vuln.ID, vuln.ScanID, vuln.Target, vuln.TargetType, vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion, vuln.Severity, vuln.Title, vuln.Description, vuln.References, vuln.CVSS, vuln.CreatedAt)

	return err
}

func (d *Database) GetVulnerabilities(scanID uuid.UUID) ([]models.VulnerabilityResult, error) {
	rows, err := d.db.Query(`
		SELECT id, scan_id, target, target_type, vulnerability_id, pkg_name, installed_version, fixed_version, severity, title, description, "references", cvss, created_at
		FROM vulnerability_results WHERE scan_id = $1 ORDER BY
			CASE severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END, created_at DESC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []models.VulnerabilityResult
	for rows.Next() {
		var v models.VulnerabilityResult
		if err := rows.Scan(&v.ID, &v.ScanID, &v.Target, &v.TargetType, &v.VulnerabilityID, &v.PkgName, &v.InstalledVersion, &v.FixedVersion, &v.Severity, &v.Title, &v.Description, &v.References, &v.CVSS, &v.CreatedAt); err != nil {
			continue
		}
		vulns = append(vulns, v)
	}

	return vulns, nil
}

// Log operations
func (d *Database) AddLog(scanID uuid.UUID, level, message string) error {
	_, err := d.db.Exec(`
		INSERT INTO cloud_scan_logs (id, scan_id, level, message, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, uuid.New(), scanID, level, message, time.Now())

	return err
}

func (d *Database) GetLogs(scanID uuid.UUID) ([]models.ScanLog, error) {
	rows, err := d.db.Query(`
		SELECT id, scan_id, level, message, created_at
		FROM cloud_scan_logs WHERE scan_id = $1 ORDER BY created_at ASC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.ScanLog
	for rows.Next() {
		var log models.ScanLog
		if err := rows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt); err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// Summary calculation
func (d *Database) CalculateSummary(scanID uuid.UUID) *models.CloudScanSummary {
	summary := &models.CloudScanSummary{}

	// Count findings by severity
	d.db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE scan_id = $1 AND severity = 'CRITICAL'`, scanID).Scan(&summary.Critical)
	d.db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE scan_id = $1 AND severity = 'HIGH'`, scanID).Scan(&summary.High)
	d.db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE scan_id = $1 AND severity = 'MEDIUM'`, scanID).Scan(&summary.Medium)
	d.db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE scan_id = $1 AND severity = 'LOW'`, scanID).Scan(&summary.Low)
	d.db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE scan_id = $1 AND severity = 'INFO'`, scanID).Scan(&summary.Info)
	d.db.QueryRow(`SELECT COUNT(*) FROM cloud_findings WHERE scan_id = $1 AND status = 'PASS'`, scanID).Scan(&summary.Passed)

	// Add vulnerabilities
	var vulnCritical, vulnHigh, vulnMedium, vulnLow int
	d.db.QueryRow(`SELECT COUNT(*) FROM vulnerability_results WHERE scan_id = $1 AND severity = 'CRITICAL'`, scanID).Scan(&vulnCritical)
	d.db.QueryRow(`SELECT COUNT(*) FROM vulnerability_results WHERE scan_id = $1 AND severity = 'HIGH'`, scanID).Scan(&vulnHigh)
	d.db.QueryRow(`SELECT COUNT(*) FROM vulnerability_results WHERE scan_id = $1 AND severity = 'MEDIUM'`, scanID).Scan(&vulnMedium)
	d.db.QueryRow(`SELECT COUNT(*) FROM vulnerability_results WHERE scan_id = $1 AND severity = 'LOW'`, scanID).Scan(&vulnLow)

	summary.Critical += vulnCritical
	summary.High += vulnHigh
	summary.Medium += vulnMedium
	summary.Low += vulnLow
	summary.TotalFindings = summary.Critical + summary.High + summary.Medium + summary.Low + summary.Info

	return summary
}
