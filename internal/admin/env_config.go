package admin

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// EnvConfig handles environment-based configuration
// Allows overriding defaults via environment variables
type EnvConfig struct {
	// Database (for future PostgreSQL support)
	DatabaseURL  string
	DatabaseHost string
	DatabasePort int
	DatabaseName string
	DatabaseUser string

	// Application
	AppPort   int
	AppEnv    string
	LogLevel  string
	VaultPath string

	// Security
	SessionTimeoutMinutes int
	MaxLoginAttempts      int
	LockoutMinutes        int
	MFARequired           bool

	// TLS
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
}

// LoadEnvConfig loads configuration from environment variables
func LoadEnvConfig() *EnvConfig {
	config := &EnvConfig{
		// Defaults
		AppPort:               8443,
		AppEnv:                "production",
		LogLevel:              "info",
		VaultPath:             "vault.pwm",
		SessionTimeoutMinutes: 15,
		MaxLoginAttempts:      5,
		LockoutMinutes:        30,
		MFARequired:           false,
		TLSEnabled:            false,
		DatabasePort:          5432,
		DatabaseName:          "password_manager",
	}

	// Override with environment variables
	if v := os.Getenv("DATABASE_URL"); v != "" {
		config.DatabaseURL = v
	}
	if v := os.Getenv("DB_HOST"); v != "" {
		config.DatabaseHost = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			config.DatabasePort = port
		}
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		config.DatabaseName = v
	}
	if v := os.Getenv("DB_USER"); v != "" {
		config.DatabaseUser = v
	}
	if v := os.Getenv("APP_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			config.AppPort = port
		}
	}
	if v := os.Getenv("APP_ENV"); v != "" {
		config.AppEnv = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		config.LogLevel = v
	}
	if v := os.Getenv("VAULT_PATH"); v != "" {
		config.VaultPath = v
	}
	if v := os.Getenv("SESSION_TIMEOUT_MINUTES"); v != "" {
		if mins, err := strconv.Atoi(v); err == nil {
			config.SessionTimeoutMinutes = mins
		}
	}
	if v := os.Getenv("MAX_LOGIN_ATTEMPTS"); v != "" {
		if attempts, err := strconv.Atoi(v); err == nil {
			config.MaxLoginAttempts = attempts
		}
	}
	if v := os.Getenv("LOCKOUT_MINUTES"); v != "" {
		if mins, err := strconv.Atoi(v); err == nil {
			config.LockoutMinutes = mins
		}
	}
	if v := os.Getenv("MFA_REQUIRED"); v != "" {
		config.MFARequired = v == "true" || v == "1"
	}
	if v := os.Getenv("TLS_ENABLED"); v != "" {
		config.TLSEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("TLS_CERT_FILE"); v != "" {
		config.TLSCertFile = v
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		config.TLSKeyFile = v
	}

	return config
}

// GetSessionTimeout returns the session timeout as a Duration
func (c *EnvConfig) GetSessionTimeout() time.Duration {
	return time.Duration(c.SessionTimeoutMinutes) * time.Minute
}

// GetLockoutDuration returns the lockout duration
func (c *EnvConfig) GetLockoutDuration() time.Duration {
	return time.Duration(c.LockoutMinutes) * time.Minute
}

// Validate checks if the configuration is valid
func (c *EnvConfig) Validate() []string {
	var errors []string

	if c.AppPort < 1 || c.AppPort > 65535 {
		errors = append(errors, fmt.Sprintf("invalid port: %d", c.AppPort))
	}
	if c.SessionTimeoutMinutes < 1 {
		errors = append(errors, "session timeout must be at least 1 minute")
	}
	if c.MaxLoginAttempts < 1 {
		errors = append(errors, "max login attempts must be at least 1")
	}
	if c.TLSEnabled {
		if c.TLSCertFile == "" {
			errors = append(errors, "TLS cert file required when TLS is enabled")
		}
		if c.TLSKeyFile == "" {
			errors = append(errors, "TLS key file required when TLS is enabled")
		}
	}

	return errors
}
