package auth

import "time"

// AuthConfig holds authentication configuration settings
// Requirement 3.1: The system shall enforce strong password policies
type AuthConfig struct {
	// Password requirements
	PasswordMinLength    int  `json:"password_min_length"`
	RequireUppercase     bool `json:"require_uppercase"`
	RequireLowercase     bool `json:"require_lowercase"`
	RequireDigits        bool `json:"require_digits"`
	RequireSpecialChars  bool `json:"require_special_chars"`
	PasswordExpiryDays   int  `json:"password_expiry_days"`
	PasswordHistoryCount int  `json:"password_history_count"`

	// MFA settings
	MFARequired        bool `json:"mfa_required"`
	MFAGracePeriodDays int  `json:"mfa_grace_period_days"`

	// Session settings
	SessionTimeoutMins  int `json:"session_timeout_mins"`
	MaxConcurrentLogins int `json:"max_concurrent_logins"`

	// Lockout settings
	MaxFailedAttempts   int           `json:"max_failed_attempts"`
	LockoutDuration     time.Duration `json:"lockout_duration"`
	LockoutDurationMins int           `json:"lockout_duration_mins"`

	// Audit
	AuditRetentionDays int `json:"audit_retention_days"`
}

// GetAuthConfig returns the default authentication configuration
func GetAuthConfig() *AuthConfig {
	return &AuthConfig{
		PasswordMinLength:    12,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireDigits:        true,
		RequireSpecialChars:  true,
		PasswordExpiryDays:   90,
		PasswordHistoryCount: 5,

		MFARequired:        false,
		MFAGracePeriodDays: 7,

		SessionTimeoutMins:  30,
		MaxConcurrentLogins: 1,

		MaxFailedAttempts:   5,
		LockoutDuration:     30 * time.Minute,
		LockoutDurationMins: 30,

		AuditRetentionDays: 365,
	}
}

// UpdateConfig updates configuration values (for admin use)
func (cfg *AuthConfig) UpdateConfig(updates map[string]interface{}) {
	if v, ok := updates["password_min_length"]; ok {
		if val, ok := v.(int); ok {
			cfg.PasswordMinLength = val
		}
	}
	if v, ok := updates["max_failed_attempts"]; ok {
		if val, ok := v.(int); ok {
			cfg.MaxFailedAttempts = val
		}
	}
	if v, ok := updates["session_timeout_mins"]; ok {
		if val, ok := v.(int); ok {
			cfg.SessionTimeoutMins = val
		}
	}
	if v, ok := updates["lockout_duration_mins"]; ok {
		if val, ok := v.(int); ok {
			cfg.LockoutDurationMins = val
			cfg.LockoutDuration = time.Duration(val) * time.Minute
		}
	}
	if v, ok := updates["mfa_required"]; ok {
		if val, ok := v.(bool); ok {
			cfg.MFARequired = val
		}
	}
}
