package recon

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/recon-service/internal/database"
	"github.com/security-scanner/recon-service/internal/models"
)

type DNSScanner struct {
	db *database.Database
}

func NewDNSScanner(db *database.Database) *DNSScanner {
	return &DNSScanner{db: db}
}

func (d *DNSScanner) Scan(ctx context.Context, scan *models.ReconScan) error {
	d.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	d.db.AddLog(scan.ID, "info", "Starting DNS records lookup for "+scan.Target)

	result := &models.DNSResult{
		ID:        uuid.New(),
		ScanID:    scan.ID,
		Domain:    scan.Target,
		CreatedAt: time.Now(),
	}

	// A Records
	d.db.AddLog(scan.ID, "info", "Looking up A records...")
	d.db.UpdateScanStatus(scan.ID, "running", 15, nil)
	aRecords, err := net.LookupHost(scan.Target)
	if err == nil {
		for _, ip := range aRecords {
			if net.ParseIP(ip).To4() != nil {
				result.A = append(result.A, ip)
			} else {
				result.AAAA = append(result.AAAA, ip)
			}
		}
	}

	// CNAME Records
	d.db.AddLog(scan.ID, "info", "Looking up CNAME records...")
	d.db.UpdateScanStatus(scan.ID, "running", 30, nil)
	cname, err := net.LookupCNAME(scan.Target)
	if err == nil && cname != scan.Target+"." {
		result.CNAME = append(result.CNAME, cname)
	}

	// MX Records
	d.db.AddLog(scan.ID, "info", "Looking up MX records...")
	d.db.UpdateScanStatus(scan.ID, "running", 45, nil)
	mxRecords, err := net.LookupMX(scan.Target)
	if err == nil {
		for _, mx := range mxRecords {
			result.MX = append(result.MX, models.MXRecord{
				Host:     mx.Host,
				Priority: int(mx.Pref),
			})
		}
	}

	// NS Records
	d.db.AddLog(scan.ID, "info", "Looking up NS records...")
	d.db.UpdateScanStatus(scan.ID, "running", 60, nil)
	nsRecords, err := net.LookupNS(scan.Target)
	if err == nil {
		for _, ns := range nsRecords {
			result.NS = append(result.NS, ns.Host)
		}
	}

	// TXT Records
	d.db.AddLog(scan.ID, "info", "Looking up TXT records...")
	d.db.UpdateScanStatus(scan.ID, "running", 75, nil)
	txtRecords, err := net.LookupTXT(scan.Target)
	if err == nil {
		result.TXT = txtRecords
	}

	// SOA Record (using custom resolver if available)
	d.db.AddLog(scan.ID, "info", "Looking up SOA record...")
	d.db.UpdateScanStatus(scan.ID, "running", 85, nil)
	// Note: Go's standard library doesn't have direct SOA lookup
	// We would need a DNS library like miekg/dns for full SOA support
	// For now, we'll skip SOA or use external tool

	// Save result
	d.db.UpdateScanStatus(scan.ID, "running", 95, nil)
	if err := d.db.SaveDNSResult(result); err != nil {
		errMsg := err.Error()
		d.db.UpdateScanStatus(scan.ID, "failed", 0, &errMsg)
		return err
	}

	d.db.UpdateScanStatus(scan.ID, "completed", 100, nil)
	d.db.AddLog(scan.ID, "info", "DNS lookup completed successfully")

	return nil
}
