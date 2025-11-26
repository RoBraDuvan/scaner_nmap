package recon

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/security-scanner/recon-service/internal/database"
	"github.com/security-scanner/recon-service/internal/models"
)

type WhoisScanner struct {
	db *database.Database
}

func NewWhoisScanner(db *database.Database) *WhoisScanner {
	return &WhoisScanner{db: db}
}

func (w *WhoisScanner) Scan(ctx context.Context, scan *models.ReconScan) error {
	w.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	w.db.AddLog(scan.ID, "info", "Starting WHOIS lookup for "+scan.Target)

	// Perform WHOIS lookup
	w.db.UpdateScanStatus(scan.ID, "running", 30, nil)
	rawWhois, err := whois.Whois(scan.Target)
	if err != nil {
		errMsg := err.Error()
		w.db.UpdateScanStatus(scan.ID, "failed", 0, &errMsg)
		w.db.AddLog(scan.ID, "error", "WHOIS lookup failed: "+errMsg)
		return err
	}

	w.db.AddLog(scan.ID, "info", "WHOIS data retrieved, parsing...")
	w.db.UpdateScanStatus(scan.ID, "running", 60, nil)

	// Parse WHOIS data
	parsed, err := whoisparser.Parse(rawWhois)

	result := &models.WhoisResult{
		ID:        uuid.New(),
		ScanID:    scan.ID,
		Domain:    scan.Target,
		RawData:   rawWhois,
		CreatedAt: time.Now(),
	}

	if err == nil {
		// Successfully parsed
		if parsed.Registrar != nil {
			result.Registrar = &parsed.Registrar.Name
		}
		if parsed.Domain != nil {
			result.CreationDate = &parsed.Domain.CreatedDate
			result.ExpirationDate = &parsed.Domain.ExpirationDate
			result.UpdatedDate = &parsed.Domain.UpdatedDate
			result.NameServers = parsed.Domain.NameServers
			result.Status = parsed.Domain.Status
		}
		if parsed.Registrant != nil {
			result.Registrant = &models.Contact{
				Name:         strPtr(parsed.Registrant.Name),
				Organization: strPtr(parsed.Registrant.Organization),
				Email:        strPtr(parsed.Registrant.Email),
				Phone:        strPtr(parsed.Registrant.Phone),
				Country:      strPtr(parsed.Registrant.Country),
				State:        strPtr(parsed.Registrant.Province),
				City:         strPtr(parsed.Registrant.City),
			}
		}
		if parsed.Administrative != nil {
			result.Admin = &models.Contact{
				Name:         strPtr(parsed.Administrative.Name),
				Organization: strPtr(parsed.Administrative.Organization),
				Email:        strPtr(parsed.Administrative.Email),
				Phone:        strPtr(parsed.Administrative.Phone),
			}
		}
		if parsed.Technical != nil {
			result.Tech = &models.Contact{
				Name:         strPtr(parsed.Technical.Name),
				Organization: strPtr(parsed.Technical.Organization),
				Email:        strPtr(parsed.Technical.Email),
				Phone:        strPtr(parsed.Technical.Phone),
			}
		}
	} else {
		w.db.AddLog(scan.ID, "warning", "Could not parse WHOIS data fully: "+err.Error())
	}

	// Save result
	w.db.UpdateScanStatus(scan.ID, "running", 90, nil)
	if err := w.db.SaveWhoisResult(result); err != nil {
		errMsg := err.Error()
		w.db.UpdateScanStatus(scan.ID, "failed", 0, &errMsg)
		return err
	}

	w.db.UpdateScanStatus(scan.ID, "completed", 100, nil)
	w.db.AddLog(scan.ID, "info", "WHOIS lookup completed successfully")

	return nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
