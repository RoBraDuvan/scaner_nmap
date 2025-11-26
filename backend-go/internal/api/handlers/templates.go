package handlers

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
)

type TemplateHandler struct {
	db *database.Database
}

func NewTemplateHandler(db *database.Database) *TemplateHandler {
	return &TemplateHandler{db: db}
}

// ListTemplates returns all templates
func (h *TemplateHandler) ListTemplates(c *fiber.Ctx) error {
	query := `
		SELECT id, name, description, scan_type, nmap_arguments, configuration, is_default, created_at
		FROM scan_templates
		ORDER BY is_default DESC, name ASC
	`

	rows, err := h.db.Pool.Query(context.Background(), query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch templates"})
	}
	defer rows.Close()

	templates := []models.ScanTemplate{}
	for rows.Next() {
		var template models.ScanTemplate
		err := rows.Scan(&template.ID, &template.Name, &template.Description, &template.ScanType,
			&template.NmapArguments, &template.Configuration, &template.IsDefault, &template.CreatedAt)
		if err != nil {
			continue
		}
		templates = append(templates, template)
	}

	return c.JSON(templates)
}

// GetTemplate returns a specific template
func (h *TemplateHandler) GetTemplate(c *fiber.Ctx) error {
	templateID := c.Params("id")

	query := `
		SELECT id, name, description, scan_type, nmap_arguments, configuration, is_default, created_at
		FROM scan_templates
		WHERE id = $1
	`

	var template models.ScanTemplate
	err := h.db.Pool.QueryRow(context.Background(), query, templateID).Scan(
		&template.ID, &template.Name, &template.Description, &template.ScanType,
		&template.NmapArguments, &template.Configuration, &template.IsDefault, &template.CreatedAt,
	)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	return c.JSON(template)
}

// CreateTemplate creates a new template
func (h *TemplateHandler) CreateTemplate(c *fiber.Ctx) error {
	var req models.CreateTemplateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Name == "" || req.ScanType == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name and scan_type are required"})
	}

	// Check if template with same name exists
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM scan_templates WHERE name = $1)`
	h.db.Pool.QueryRow(context.Background(), checkQuery, req.Name).Scan(&exists)

	if exists {
		return c.Status(400).JSON(fiber.Map{"error": "Template with this name already exists"})
	}

	templateID := uuid.New()
	query := `
		INSERT INTO scan_templates (id, name, description, scan_type, nmap_arguments, configuration, is_default, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, name, description, scan_type, nmap_arguments, configuration, is_default, created_at
	`

	var template models.ScanTemplate
	err := h.db.Pool.QueryRow(context.Background(), query,
		templateID, req.Name, req.Description, req.ScanType, req.NmapArguments, req.Configuration, req.IsDefault, time.Now(),
	).Scan(&template.ID, &template.Name, &template.Description, &template.ScanType,
		&template.NmapArguments, &template.Configuration, &template.IsDefault, &template.CreatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create template"})
	}

	return c.Status(201).JSON(template)
}

// UpdateTemplate updates an existing template
func (h *TemplateHandler) UpdateTemplate(c *fiber.Ctx) error {
	templateID := c.Params("id")

	var req models.CreateTemplateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	query := `
		UPDATE scan_templates
		SET name = COALESCE(NULLIF($1, ''), name),
		    description = $2,
		    scan_type = COALESCE(NULLIF($3, ''), scan_type),
		    nmap_arguments = $4,
		    configuration = $5,
		    is_default = $6
		WHERE id = $7
		RETURNING id, name, description, scan_type, nmap_arguments, configuration, is_default, created_at
	`

	var template models.ScanTemplate
	err := h.db.Pool.QueryRow(context.Background(), query,
		req.Name, req.Description, req.ScanType, req.NmapArguments, req.Configuration, req.IsDefault, templateID,
	).Scan(&template.ID, &template.Name, &template.Description, &template.ScanType,
		&template.NmapArguments, &template.Configuration, &template.IsDefault, &template.CreatedAt)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	return c.JSON(template)
}

// DeleteTemplate deletes a template
func (h *TemplateHandler) DeleteTemplate(c *fiber.Ctx) error {
	templateID := c.Params("id")

	query := `DELETE FROM scan_templates WHERE id = $1`
	result, err := h.db.Pool.Exec(context.Background(), query, templateID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete template"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	return c.JSON(fiber.Map{"message": "Template deleted successfully"})
}

// BuiltinTemplate represents a predefined scan template
type BuiltinTemplate struct {
	ScanType    string `json:"scan_type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Arguments   string `json:"arguments"`
}

// ListBuiltinTemplates returns predefined Nmap scan templates
func (h *TemplateHandler) ListBuiltinTemplates(c *fiber.Ctx) error {
	templates := []BuiltinTemplate{
		{ScanType: "quick", Name: "Quick Scan", Description: "Fast scan of the most common 100 ports", Arguments: "-F -T4"},
		{ScanType: "full", Name: "Full Port Scan", Description: "Comprehensive scan of all 65535 ports", Arguments: "-p- -T4"},
		{ScanType: "udp", Name: "UDP Scan", Description: "Scan common UDP ports", Arguments: "-sU --top-ports 100 -T4"},
		{ScanType: "discovery", Name: "Host Discovery", Description: "Discover active hosts in network (ping sweep)", Arguments: "-sn -PE -PP -PM --dns-servers 8.8.8.8,1.1.1.1 -T4"},
		{ScanType: "local_network", Name: "Local Network Scan", Description: "Complete local network scan with MAC vendor identification", Arguments: "-sn -PR --dns-servers 8.8.8.8,1.1.1.1 -T4"},
		{ScanType: "web_server", Name: "Web Server Scan", Description: "Scan web servers (HTTP/HTTPS) with service detection", Arguments: "-p 80,443,8080,8443,3000,5000,8000 -sV --script http-title,http-methods,http-headers -T4"},
		{ScanType: "db_server", Name: "Database Server Scan", Description: "Scan common database ports with version detection", Arguments: "-p 3306,5432,1433,1521,27017,6379,5984,9200,11211 -sV -T4"},
		{ScanType: "mail_server", Name: "Mail Server Scan", Description: "Scan mail servers (SMTP, POP3, IMAP)", Arguments: "-p 25,110,143,465,587,993,995 -sV --script smtp-commands,pop3-capabilities,imap-capabilities -T4"},
		{ScanType: "ftp_ssh_server", Name: "FTP/SSH Server Scan", Description: "Scan file transfer and remote access services", Arguments: "-p 20,21,22,23,990,2121,2222 -sV --script ftp-anon,ssh-auth-methods -T4"},
		{ScanType: "dns_server", Name: "DNS Server Scan", Description: "Scan DNS servers and detect configuration", Arguments: "-p 53 -sU -sV --script dns-nsid,dns-recursion -T4"},
		{ScanType: "service", Name: "Service Version Detection", Description: "Detect service versions and OS", Arguments: "-sV -O -T4"},
		{ScanType: "vulnerability", Name: "Vulnerability Scan", Description: "Scan with NSE vulnerability scripts", Arguments: "-sV --script vuln -T4"},
		{ScanType: "security_audit", Name: "Security Audit", Description: "Complete security audit with SSL/TLS checks", Arguments: "-p- -sV --script ssl-cert,ssl-enum-ciphers,ssh-auth-methods -T4"},
		{ScanType: "stealth", Name: "Stealth Scan", Description: "SYN stealth scan with minimal footprint", Arguments: "-sS -T2 -f"},
		{ScanType: "aggressive", Name: "Aggressive Scan", Description: "Aggressive scan with OS detection, version, scripts and traceroute", Arguments: "-A -T4"},
	}

	return c.JSON(templates)
}

// VulnTemplate represents a vulnerability scan template
type VulnTemplate struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Category       string   `json:"category"`
	NucleiTags     []string `json:"nuclei_tags"`
	SeverityFilter []string `json:"severity_filter"`
	IsDefault      bool     `json:"is_default"`
}

// ListVulnerabilityTemplates returns predefined Nuclei vulnerability scan templates
func (h *TemplateHandler) ListVulnerabilityTemplates(c *fiber.Ctx) error {
	query := `
		SELECT id, name, description, category, nuclei_tags, severity_filter, is_default
		FROM vulnerability_templates
		ORDER BY is_default DESC, category, name
	`

	rows, err := h.db.Pool.Query(context.Background(), query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch vulnerability templates"})
	}
	defer rows.Close()

	templates := []VulnTemplate{}
	for rows.Next() {
		var template VulnTemplate
		err := rows.Scan(&template.ID, &template.Name, &template.Description, &template.Category,
			&template.NucleiTags, &template.SeverityFilter, &template.IsDefault)
		if err != nil {
			continue
		}
		templates = append(templates, template)
	}

	return c.JSON(templates)
}
