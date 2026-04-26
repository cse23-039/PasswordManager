package admin

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// DeploymentInfo contains system deployment information
type DeploymentInfo struct {
	OS          string          `json:"os"`
	Arch        string          `json:"arch"`
	GoVersion   string          `json:"go_version"`
	AppVersion  string          `json:"app_version"`
	Environment string          `json:"environment"`
	Features    map[string]bool `json:"features"`
}

// GetDeploymentInfo returns current deployment information
func GetDeploymentInfo() *DeploymentInfo {
	return &DeploymentInfo{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		AppVersion:  "1.0.0",
		Environment: getEnvironment(),
		Features: map[string]bool{
			"local_vault":     true,
			"aes256_gcm":      true,
			"argon2id":        true,
			"totp_mfa":        true,
			"rbac":            true,
			"audit_logging":   true,
			"hmac_tamper_det": true,
			"clipboard_clear": true,
			"session_mgmt":    true,
		},
	}
}

func getEnvironment() string {
	env := os.Getenv("APP_ENV")
	if env == "" {
		return "production"
	}
	return env
}

// FormatDeploymentInfo formats deployment info as a readable string
func FormatDeploymentInfo(info *DeploymentInfo) string {
	var b strings.Builder

	b.WriteString("=== Deployment Information ===\n")
	b.WriteString(fmt.Sprintf("OS: %s/%s\n", info.OS, info.Arch))
	b.WriteString(fmt.Sprintf("Go Version: %s\n", info.GoVersion))
	b.WriteString(fmt.Sprintf("App Version: %s\n", info.AppVersion))
	b.WriteString(fmt.Sprintf("Environment: %s\n", info.Environment))
	b.WriteString("\nEnabled Features:\n")
	for feature, enabled := range info.Features {
		status := "disabled"
		if enabled {
			status = "enabled"
		}
		b.WriteString(fmt.Sprintf("  - %s: %s\n", feature, status))
	}

	return b.String()
}
