package models

import (
	"time"

	"github.com/google/uuid"
)

type Scan struct {
	ID           uuid.UUID              `json:"id"`
	Name         string                 `json:"name"`
	Target       string                 `json:"target"`
	ScanType     string                 `json:"scan_type"`
	Status       string                 `json:"status"`
	Progress     int                    `json:"progress"`
	CreatedAt    time.Time              `json:"created_at"`
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
}

type ScanResult struct {
	ID          uuid.UUID              `json:"id"`
	ScanID      uuid.UUID              `json:"scan_id"`
	Host        string                 `json:"host"`
	Hostname    *string                `json:"hostname,omitempty"`
	State       string                 `json:"state"`
	Ports       []Port                 `json:"ports"`
	OSDetection map[string]interface{} `json:"os_detection,omitempty"`
	Services    []string               `json:"services"`
	MacAddress  *string                `json:"mac_address,omitempty"`
	MacVendor   *string                `json:"mac_vendor,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

type Port struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service"`
	Version   string `json:"version,omitempty"`
	Product   string `json:"product,omitempty"`
	ExtraInfo string `json:"extrainfo,omitempty"`
}

type ScanLog struct {
	ID        uuid.UUID `json:"id"`
	ScanID    uuid.UUID `json:"scan_id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type ScanTemplate struct {
	ID            uuid.UUID              `json:"id"`
	Name          string                 `json:"name"`
	Description   *string                `json:"description,omitempty"`
	ScanType      string                 `json:"scan_type"`
	NmapArguments *string                `json:"nmap_arguments,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
	IsDefault     bool                   `json:"is_default"`
	CreatedAt     time.Time              `json:"created_at"`
}

type CreateScanRequest struct {
	Name          string                 `json:"name"`
	Target        string                 `json:"target"`
	ScanType      string                 `json:"scan_type"`
	NmapArguments *string                `json:"nmap_arguments,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
}

type CreateTemplateRequest struct {
	Name          string                 `json:"name"`
	Description   *string                `json:"description,omitempty"`
	ScanType      string                 `json:"scan_type"`
	NmapArguments *string                `json:"nmap_arguments,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
	IsDefault     bool                   `json:"is_default"`
}
