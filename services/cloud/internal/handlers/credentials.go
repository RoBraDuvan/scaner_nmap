package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// CredentialStatus represents the status of cloud credentials
type CredentialStatus struct {
	Provider    string `json:"provider"`
	Configured  bool   `json:"configured"`
	ProfileName string `json:"profile_name,omitempty"`
	Region      string `json:"region,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

// AWSCredentialsRequest represents AWS credentials upload
type AWSCredentialsRequest struct {
	AccessKeyID     string `json:"access_key_id" binding:"required"`
	SecretAccessKey string `json:"secret_access_key" binding:"required"`
	Region          string `json:"region"`
	ProfileName     string `json:"profile_name"`
}

// GCPCredentialsRequest represents GCP credentials upload
type GCPCredentialsRequest struct {
	ServiceAccountJSON string `json:"service_account_json" binding:"required"`
	ProjectID          string `json:"project_id"`
}

// AzureCredentialsRequest represents Azure credentials
type AzureCredentialsRequest struct {
	TenantID       string `json:"tenant_id" binding:"required"`
	ClientID       string `json:"client_id" binding:"required"`
	ClientSecret   string `json:"client_secret" binding:"required"`
	SubscriptionID string `json:"subscription_id"`
}

// GetCredentialsStatus returns the status of all cloud credentials
func (h *Handler) GetCredentialsStatus(c *gin.Context) {
	statuses := []CredentialStatus{
		checkAWSCredentials(),
		checkGCPCredentials(),
		checkAzureCredentials(),
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials": statuses,
	})
}

// GetAWSCredentialsStatus returns AWS credentials status
func (h *Handler) GetAWSCredentialsStatus(c *gin.Context) {
	status := checkAWSCredentials()
	c.JSON(http.StatusOK, status)
}

// SetAWSCredentials sets AWS credentials
func (h *Handler) SetAWSCredentials(c *gin.Context) {
	var req AWSCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	profileName := req.ProfileName
	if profileName == "" {
		profileName = "default"
	}

	region := req.Region
	if region == "" {
		region = "us-east-1"
	}

	// Create AWS credentials file
	awsDir := "/root/.aws"
	if err := os.MkdirAll(awsDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create AWS directory"})
		return
	}

	// Write credentials file
	credentialsContent := fmt.Sprintf("[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
		profileName, req.AccessKeyID, req.SecretAccessKey)

	credentialsPath := filepath.Join(awsDir, "credentials")
	if err := os.WriteFile(credentialsPath, []byte(credentialsContent), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write credentials"})
		return
	}

	// Write config file
	configContent := fmt.Sprintf("[%s]\nregion = %s\noutput = json\n",
		profileName, region)
	if profileName != "default" {
		configContent = fmt.Sprintf("[profile %s]\nregion = %s\noutput = json\n",
			profileName, region)
	}

	configPath := filepath.Join(awsDir, "config")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write config"})
		return
	}

	// Verify credentials
	status := checkAWSCredentials()
	if !status.Configured {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Credentials saved but validation failed: " + status.Message})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "AWS credentials configured successfully",
		"status":  status,
	})
}

// DeleteAWSCredentials removes AWS credentials
func (h *Handler) DeleteAWSCredentials(c *gin.Context) {
	awsDir := "/root/.aws"
	os.Remove(filepath.Join(awsDir, "credentials"))
	os.Remove(filepath.Join(awsDir, "config"))

	c.JSON(http.StatusOK, gin.H{"message": "AWS credentials removed"})
}

// GetGCPCredentialsStatus returns GCP credentials status
func (h *Handler) GetGCPCredentialsStatus(c *gin.Context) {
	status := checkGCPCredentials()
	c.JSON(http.StatusOK, status)
}

// SetGCPCredentials sets GCP credentials
func (h *Handler) SetGCPCredentials(c *gin.Context) {
	var req GCPCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(req.ServiceAccountJSON), &jsonData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Create GCP config directory
	gcpDir := "/root/.config/gcloud"
	if err := os.MkdirAll(gcpDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create GCP directory"})
		return
	}

	// Write service account file
	credPath := filepath.Join(gcpDir, "application_default_credentials.json")
	if err := os.WriteFile(credPath, []byte(req.ServiceAccountJSON), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write credentials"})
		return
	}

	// Set project ID if provided
	if req.ProjectID != "" {
		projectPath := filepath.Join(gcpDir, "project_id")
		os.WriteFile(projectPath, []byte(req.ProjectID), 0600)
	}

	status := checkGCPCredentials()
	c.JSON(http.StatusOK, gin.H{
		"message": "GCP credentials configured successfully",
		"status":  status,
	})
}

// UploadGCPCredentials handles file upload for GCP service account
func (h *Handler) UploadGCPCredentials(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer src.Close()

	// Read content
	content, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	// Validate JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal(content, &jsonData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Create GCP config directory
	gcpDir := "/root/.config/gcloud"
	if err := os.MkdirAll(gcpDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create GCP directory"})
		return
	}

	// Write service account file
	credPath := filepath.Join(gcpDir, "application_default_credentials.json")
	if err := os.WriteFile(credPath, content, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write credentials"})
		return
	}

	status := checkGCPCredentials()
	c.JSON(http.StatusOK, gin.H{
		"message": "GCP credentials uploaded successfully",
		"status":  status,
	})
}

// DeleteGCPCredentials removes GCP credentials
func (h *Handler) DeleteGCPCredentials(c *gin.Context) {
	gcpDir := "/root/.config/gcloud"
	os.Remove(filepath.Join(gcpDir, "application_default_credentials.json"))
	os.Remove(filepath.Join(gcpDir, "project_id"))

	c.JSON(http.StatusOK, gin.H{"message": "GCP credentials removed"})
}

// GetAzureCredentialsStatus returns Azure credentials status
func (h *Handler) GetAzureCredentialsStatus(c *gin.Context) {
	status := checkAzureCredentials()
	c.JSON(http.StatusOK, status)
}

// SetAzureCredentials sets Azure credentials
func (h *Handler) SetAzureCredentials(c *gin.Context) {
	var req AzureCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create Azure config directory
	azureDir := "/root/.azure"
	if err := os.MkdirAll(azureDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Azure directory"})
		return
	}

	// Write Azure credentials as environment config
	configContent := fmt.Sprintf(`{
  "tenant_id": "%s",
  "client_id": "%s",
  "client_secret": "%s",
  "subscription_id": "%s"
}`, req.TenantID, req.ClientID, req.ClientSecret, req.SubscriptionID)

	credPath := filepath.Join(azureDir, "credentials.json")
	if err := os.WriteFile(credPath, []byte(configContent), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write credentials"})
		return
	}

	// Also set environment variables file for tools to source
	envContent := fmt.Sprintf(`export AZURE_TENANT_ID="%s"
export AZURE_CLIENT_ID="%s"
export AZURE_CLIENT_SECRET="%s"
export AZURE_SUBSCRIPTION_ID="%s"
`, req.TenantID, req.ClientID, req.ClientSecret, req.SubscriptionID)

	envPath := filepath.Join(azureDir, "env")
	os.WriteFile(envPath, []byte(envContent), 0600)

	status := checkAzureCredentials()
	c.JSON(http.StatusOK, gin.H{
		"message": "Azure credentials configured successfully",
		"status":  status,
	})
}

// DeleteAzureCredentials removes Azure credentials
func (h *Handler) DeleteAzureCredentials(c *gin.Context) {
	azureDir := "/root/.azure"
	os.Remove(filepath.Join(azureDir, "credentials.json"))
	os.Remove(filepath.Join(azureDir, "env"))

	c.JSON(http.StatusOK, gin.H{"message": "Azure credentials removed"})
}

// Helper functions to check credentials

func checkAWSCredentials() CredentialStatus {
	status := CredentialStatus{
		Provider:   "aws",
		Configured: false,
	}

	// Check if credentials file exists
	credPath := "/root/.aws/credentials"
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		status.Message = "No credentials file found"
		return status
	}

	// Try to get caller identity
	cmd := exec.Command("aws", "sts", "get-caller-identity", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		status.Message = "Credentials exist but validation failed"
		status.Configured = false
		return status
	}

	var identity map[string]string
	if err := json.Unmarshal(output, &identity); err == nil {
		status.AccountID = identity["Account"]
	}

	// Get region from config
	configPath := "/root/.aws/config"
	if content, err := os.ReadFile(configPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "region") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					status.Region = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	status.Configured = true
	status.ProfileName = "default"
	status.Message = "Credentials configured and validated"
	return status
}

func checkGCPCredentials() CredentialStatus {
	status := CredentialStatus{
		Provider:   "gcp",
		Configured: false,
	}

	// Check if credentials file exists
	credPath := "/root/.config/gcloud/application_default_credentials.json"
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		status.Message = "No credentials file found"
		return status
	}

	// Read and parse credentials
	content, err := os.ReadFile(credPath)
	if err != nil {
		status.Message = "Failed to read credentials file"
		return status
	}

	var creds map[string]interface{}
	if err := json.Unmarshal(content, &creds); err != nil {
		status.Message = "Invalid credentials format"
		return status
	}

	// Extract project ID if available
	if projectID, ok := creds["project_id"].(string); ok {
		status.ProjectID = projectID
	}

	// Check for project_id file
	if projectID, err := os.ReadFile("/root/.config/gcloud/project_id"); err == nil {
		status.ProjectID = strings.TrimSpace(string(projectID))
	}

	status.Configured = true
	status.Message = "Credentials file found"
	return status
}

func checkAzureCredentials() CredentialStatus {
	status := CredentialStatus{
		Provider:   "azure",
		Configured: false,
	}

	// Check if credentials file exists
	credPath := "/root/.azure/credentials.json"
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		status.Message = "No credentials file found"
		return status
	}

	// Read and parse credentials
	content, err := os.ReadFile(credPath)
	if err != nil {
		status.Message = "Failed to read credentials file"
		return status
	}

	var creds map[string]string
	if err := json.Unmarshal(content, &creds); err != nil {
		status.Message = "Invalid credentials format"
		return status
	}

	status.TenantID = creds["tenant_id"]
	status.Configured = true
	status.Message = "Credentials file found"
	return status
}
