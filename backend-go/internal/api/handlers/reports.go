package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
)

type ReportHandler struct {
	db *database.Database
}

func NewReportHandler(db *database.Database) *ReportHandler {
	return &ReportHandler{db: db}
}

// ScanReport represents a complete scan report
type ScanReport struct {
	Scan    models.Scan       `json:"scan"`
	Results []models.ScanResult `json:"results"`
	Logs    []models.ScanLog    `json:"logs"`
}

// GetJSONReport returns scan results in JSON format
func (h *ReportHandler) GetJSONReport(c *fiber.Ctx) error {
	scanID := c.Params("id")

	report, err := h.getScanReport(scanID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=scan_%s.json", scanID))
	c.Set("Content-Type", "application/json")

	return c.JSON(report)
}

// GetHTMLReport returns scan results as an HTML report
func (h *ReportHandler) GetHTMLReport(c *fiber.Ctx) error {
	scanID := c.Params("id")

	report, err := h.getScanReport(scanID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	htmlContent := h.generateHTMLReport(report)

	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=scan_%s.html", scanID))
	c.Set("Content-Type", "text/html")

	return c.SendString(htmlContent)
}

// GetCSVReport returns scan results as a CSV file
func (h *ReportHandler) GetCSVReport(c *fiber.Ctx) error {
	scanID := c.Params("id")

	report, err := h.getScanReport(scanID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
	}

	csvContent := h.generateCSVReport(report)

	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=scan_%s.csv", scanID))
	c.Set("Content-Type", "text/csv")

	return c.SendString(csvContent)
}

// getScanReport retrieves a complete scan report from database
func (h *ReportHandler) getScanReport(scanID string) (*ScanReport, error) {
	ctx := context.Background()

	// Get scan
	scanQuery := `
		SELECT id, name, target, scan_type, status, progress, created_at, started_at, completed_at, error_message
		FROM scans WHERE id = $1
	`
	var scan models.Scan
	err := h.db.Pool.QueryRow(ctx, scanQuery, scanID).Scan(
		&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status,
		&scan.Progress, &scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt, &scan.ErrorMessage,
	)
	if err != nil {
		return nil, err
	}

	// Get results
	resultsQuery := `
		SELECT id, scan_id, host, hostname, state, ports, os_detection, services, mac_address, mac_vendor, created_at
		FROM scan_results WHERE scan_id = $1
	`
	rows, err := h.db.Pool.Query(ctx, resultsQuery, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := []models.ScanResult{}
	for rows.Next() {
		var result models.ScanResult
		err := rows.Scan(&result.ID, &result.ScanID, &result.Host, &result.Hostname, &result.State,
			&result.Ports, &result.OSDetection, &result.Services, &result.MacAddress, &result.MacVendor, &result.CreatedAt)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	// Get logs
	logsQuery := `
		SELECT id, scan_id, level, message, created_at
		FROM scan_logs WHERE scan_id = $1 ORDER BY created_at ASC
	`
	logRows, err := h.db.Pool.Query(ctx, logsQuery, scanID)
	if err != nil {
		return nil, err
	}
	defer logRows.Close()

	logs := []models.ScanLog{}
	for logRows.Next() {
		var log models.ScanLog
		err := logRows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return &ScanReport{
		Scan:    scan,
		Results: results,
		Logs:    logs,
	}, nil
}

// generateHTMLReport creates an HTML report from scan data
func (h *ReportHandler) generateHTMLReport(report *ScanReport) string {
	const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scanner Report - {{.Scan.Name}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .meta { display: flex; gap: 20px; flex-wrap: wrap; font-size: 14px; opacity: 0.9; }
        .section { background: white; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
        .section-header { background: #f9fafb; padding: 15px 20px; border-bottom: 1px solid #e5e7eb; font-weight: 600; font-size: 18px; }
        .section-body { padding: 20px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .badge-completed { background: #dcfce7; color: #166534; }
        .badge-failed { background: #fecaca; color: #991b1b; }
        .badge-running { background: #dbeafe; color: #1e40af; }
        .host-card { border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 15px; }
        .host-header { background: #f3f4f6; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; }
        .host-body { padding: 16px; }
        .ports-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .ports-table th, .ports-table td { padding: 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        .ports-table th { background: #f9fafb; font-weight: 600; }
        .port-open { color: #166534; }
        .port-closed { color: #991b1b; }
        .footer { text-align: center; color: #6b7280; font-size: 14px; margin-top: 30px; padding: 20px; border-top: 1px solid #e5e7eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ {{.Scan.Name}}</h1>
        <div class="meta">
            <span><strong>Target:</strong> {{.Scan.Target}}</span>
            <span><strong>Type:</strong> {{.Scan.ScanType}}</span>
            <span><strong>Status:</strong> <span class="badge badge-{{.Scan.Status}}">{{.Scan.Status}}</span></span>
            <span><strong>Created:</strong> {{.Scan.CreatedAt.Format "2006-01-02 15:04:05"}}</span>
        </div>
    </div>

    <div class="section">
        <div class="section-header">📊 Summary</div>
        <div class="section-body">
            <p><strong>Total Hosts Found:</strong> {{len .Results}}</p>
            <p><strong>Scan Duration:</strong> {{if .Scan.CompletedAt}}{{.Duration}}{{else}}In Progress{{end}}</p>
        </div>
    </div>

    <div class="section">
        <div class="section-header">🖥️ Discovered Hosts ({{len .Results}})</div>
        <div class="section-body">
            {{range .Results}}
            <div class="host-card">
                <div class="host-header">
                    <span><strong>{{.Host}}</strong>{{if .Hostname}} ({{.Hostname}}){{end}}</span>
                    <span class="badge badge-{{if eq .State "up"}}completed{{else}}failed{{end}}">{{.State}}</span>
                </div>
                <div class="host-body">
                    {{if .MacAddress}}<p><strong>MAC:</strong> {{.MacAddress}}{{if .MacVendor}} - {{.MacVendor}}{{end}}</p>{{end}}
                    {{if .Ports}}
                    <table class="ports-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Ports}}
                            <tr>
                                <td>{{.Port}}</td>
                                <td>{{.Protocol}}</td>
                                <td class="port-{{.State}}">{{.State}}</td>
                                <td>{{.Service}}</td>
                                <td>{{.Product}} {{.Version}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                    {{else}}
                    <p>No open ports detected</p>
                    {{end}}
                </div>
            </div>
            {{else}}
            <p>No hosts discovered</p>
            {{end}}
        </div>
    </div>

    <div class="footer">
        <p>Generated by Security Scanner on {{.GeneratedAt}}</p>
    </div>
</body>
</html>`

	// Calculate duration
	var duration string
	if report.Scan.CompletedAt != nil && report.Scan.StartedAt != nil {
		d := report.Scan.CompletedAt.Sub(*report.Scan.StartedAt)
		duration = d.String()
	} else {
		duration = "N/A"
	}

	data := struct {
		Scan        models.Scan
		Results     []models.ScanResult
		Duration    string
		GeneratedAt string
	}{
		Scan:        report.Scan,
		Results:     report.Results,
		Duration:    duration,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Sprintf("<html><body>Error generating report: %v</body></html>", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("<html><body>Error generating report: %v</body></html>", err)
	}

	return buf.String()
}

// generateCSVReport creates a CSV report from scan data
func (h *ReportHandler) generateCSVReport(report *ScanReport) string {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	writer.Write([]string{"Host", "Hostname", "State", "MAC Address", "MAC Vendor", "Port", "Protocol", "Port State", "Service", "Product", "Version"})

	for _, result := range report.Results {
		hostname := ""
		if result.Hostname != nil {
			hostname = *result.Hostname
		}
		macAddress := ""
		if result.MacAddress != nil {
			macAddress = *result.MacAddress
		}
		macVendor := ""
		if result.MacVendor != nil {
			macVendor = *result.MacVendor
		}

		if len(result.Ports) == 0 {
			// Host with no ports
			writer.Write([]string{result.Host, hostname, result.State, macAddress, macVendor, "", "", "", "", "", ""})
		} else {
			// Write a row for each port
			for _, port := range result.Ports {
				writer.Write([]string{
					result.Host,
					hostname,
					result.State,
					macAddress,
					macVendor,
					fmt.Sprintf("%d", port.Port),
					port.Protocol,
					port.State,
					port.Service,
					port.Product,
					port.Version,
				})
			}
		}
	}

	writer.Flush()
	return buf.String()
}

// Ensure uuid is used (for type compatibility)
var _ = uuid.UUID{}
// Ensure json is used
var _ = json.Marshal
