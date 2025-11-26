package models

import (
	"time"

	"github.com/google/uuid"
)

// ReconScan represents a reconnaissance scan
type ReconScan struct {
	ID           uuid.UUID              `json:"id"`
	Name         string                 `json:"name"`
	Target       string                 `json:"target"`
	ScanType     string                 `json:"scan_type"` // subdomain, whois, dns, tech
	Status       string                 `json:"status"`    // pending, running, completed, failed, cancelled
	Progress     int                    `json:"progress"`
	CreatedAt    time.Time              `json:"created_at"`
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	Options      map[string]interface{} `json:"options,omitempty"`
}

// SubdomainResult represents a discovered subdomain
type SubdomainResult struct {
	ID        uuid.UUID  `json:"id"`
	ScanID    uuid.UUID  `json:"scan_id"`
	Subdomain string     `json:"subdomain"`
	IP        *string    `json:"ip,omitempty"`
	Source    string     `json:"source"` // subfinder, amass, etc.
	IsAlive   bool       `json:"is_alive"`
	CreatedAt time.Time  `json:"created_at"`
}

// WhoisResult represents WHOIS lookup results
type WhoisResult struct {
	ID              uuid.UUID  `json:"id"`
	ScanID          uuid.UUID  `json:"scan_id"`
	Domain          string     `json:"domain"`
	Registrar       *string    `json:"registrar,omitempty"`
	CreationDate    *string    `json:"creation_date,omitempty"`
	ExpirationDate  *string    `json:"expiration_date,omitempty"`
	UpdatedDate     *string    `json:"updated_date,omitempty"`
	NameServers     []string   `json:"name_servers,omitempty"`
	Status          []string   `json:"status,omitempty"`
	Registrant      *Contact   `json:"registrant,omitempty"`
	Admin           *Contact   `json:"admin,omitempty"`
	Tech            *Contact   `json:"tech,omitempty"`
	RawData         string     `json:"raw_data,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Contact represents contact information in WHOIS
type Contact struct {
	Name         *string `json:"name,omitempty"`
	Organization *string `json:"organization,omitempty"`
	Email        *string `json:"email,omitempty"`
	Phone        *string `json:"phone,omitempty"`
	Country      *string `json:"country,omitempty"`
	State        *string `json:"state,omitempty"`
	City         *string `json:"city,omitempty"`
}

// DNSResult represents DNS records for a domain
type DNSResult struct {
	ID        uuid.UUID   `json:"id"`
	ScanID    uuid.UUID   `json:"scan_id"`
	Domain    string      `json:"domain"`
	A         []string    `json:"a,omitempty"`
	AAAA      []string    `json:"aaaa,omitempty"`
	CNAME     []string    `json:"cname,omitempty"`
	MX        []MXRecord  `json:"mx,omitempty"`
	NS        []string    `json:"ns,omitempty"`
	TXT       []string    `json:"txt,omitempty"`
	SOA       *SOARecord  `json:"soa,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
}

// MXRecord represents an MX DNS record
type MXRecord struct {
	Host     string `json:"host"`
	Priority int    `json:"priority"`
}

// SOARecord represents an SOA DNS record
type SOARecord struct {
	PrimaryNS  string `json:"primary_ns"`
	Email      string `json:"email"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinTTL     uint32 `json:"min_ttl"`
}

// TechResult represents technology detection results
type TechResult struct {
	ID           uuid.UUID     `json:"id"`
	ScanID       uuid.UUID     `json:"scan_id"`
	URL          string        `json:"url"`
	StatusCode   int           `json:"status_code"`
	Title        *string       `json:"title,omitempty"`
	Technologies []Technology  `json:"technologies,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Server       *string       `json:"server,omitempty"`
	ContentType  *string       `json:"content_type,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
}

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    *string  `json:"version,omitempty"`
	Confidence int      `json:"confidence"`
}

// ReconLog represents a log entry for a recon scan
type ReconLog struct {
	ID        uuid.UUID `json:"id"`
	ScanID    uuid.UUID `json:"scan_id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// Request structs
type CreateReconRequest struct {
	Name     string                 `json:"name"`
	Target   string                 `json:"target"`
	ScanType string                 `json:"scan_type"`
	Options  map[string]interface{} `json:"options,omitempty"`
}
