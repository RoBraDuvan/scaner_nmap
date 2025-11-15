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
