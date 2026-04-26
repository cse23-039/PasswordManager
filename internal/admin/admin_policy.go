package admin

import (
	"fmt"
	"password-manager/internal/audit"
	"password-manager/internal/auth"
	"password-manager/internal/models"
	"sync"
	"time"
)

// PolicyEnforcer manages security policies
// Requirement 3.5: Administrators shall be able to manage security policies
type PolicyEnforcer struct {
	mu     sync.RWMutex
	policy *SecurityPolicy
	logger *audit.AuditLogger
}

// SecurityPolicy defines security configuration
type SecurityPolicy struct {
	// Password policy
	MinPasswordLength    int           `json:"min_password_length"`
	RequireUppercase     bool          `json:"require_uppercase"`
	RequireLowercase     bool          `json:"require_lowercase"`
	RequireDigits        bool          `json:"require_digits"`
	RequireSpecialChars  bool          `json:"require_special_chars"`
	PasswordExpiry       time.Duration `json:"password_expiry"`
	PasswordHistoryCount int           `json:"password_history_count"`

	// Session policy
	SessionTimeout    time.Duration `json:"session_timeout"`
	MaxSessionTime    time.Duration `json:"max_session_time"`
	MaxConcurrentSess int           `json:"max_concurrent_sessions"`

	// Lockout policy
	MaxLoginAttempts int           `json:"max_login_attempts"`
	LockoutDuration  time.Duration `json:"lockout_duration"`

	// MFA policy
	MFARequired  bool `json:"mfa_required"`
	MFAForAdmins bool `json:"mfa_for_admins"`

	// Audit policy
	AuditRetentionDays int  `json:"audit_retention_days"`
	AuditAllAccess     bool `json:"audit_all_access"`

	// Updated tracking
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// DefaultSecurityPolicy returns the default security policy
func DefaultSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		MinPasswordLength:    12,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireDigits:        true,
		RequireSpecialChars:  true,
		PasswordExpiry:       90 * 24 * time.Hour, // 90 days
		PasswordHistoryCount: 5,
		SessionTimeout:       15 * time.Minute,
		MaxSessionTime:       8 * time.Hour,
		MaxConcurrentSess:    3,
		MaxLoginAttempts:     5,
		LockoutDuration:      30 * time.Minute,
		MFARequired:          true,
		MFAForAdmins:         true,
		AuditRetentionDays:   90,
		AuditAllAccess:       true,
		UpdatedAt:            time.Now(),
	}
}

// NewPolicyEnforcer creates a new policy enforcer with default settings
func NewPolicyEnforcer(logger *audit.AuditLogger) *PolicyEnforcer {
	return &PolicyEnforcer{
		policy: DefaultSecurityPolicy(),
		logger: logger,
	}
}

// GetPolicy returns the current security policy
func (pe *PolicyEnforcer) GetPolicy() *SecurityPolicy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	// Return a copy
	policyCopy := *pe.policy
	return &policyCopy
}

// UpdatePolicy updates the security policy
func (pe *PolicyEnforcer) UpdatePolicy(policy *SecurityPolicy, updatedBy string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if policy.MinPasswordLength < 8 {
		return fmt.Errorf("minimum password length cannot be less than 8")
	}
	if policy.MaxLoginAttempts < 1 {
		return fmt.Errorf("max login attempts must be at least 1")
	}
	if policy.SessionTimeout < time.Minute {
		return fmt.Errorf("session timeout must be at least 1 minute")
	}

	policy.UpdatedAt = time.Now()
	policy.UpdatedBy = updatedBy
	pe.policy = policy

	if pe.logger != nil {
		pe.logger.LogAdminChange(updatedBy, audit.ActionPolicyChange, "security_policy", "policy updated")
	}

	return nil
}

// UpdatePasswordPolicy updates password-related policy settings
func (pe *PolicyEnforcer) UpdatePasswordPolicy(minLength int, requireUpper, requireLower, requireDigits, requireSpecial bool, updatedBy string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if minLength < 8 {
		return fmt.Errorf("minimum password length cannot be less than 8")
	}

	pe.policy.MinPasswordLength = minLength
	pe.policy.RequireUppercase = requireUpper
	pe.policy.RequireLowercase = requireLower
	pe.policy.RequireDigits = requireDigits
	pe.policy.RequireSpecialChars = requireSpecial
	pe.policy.UpdatedAt = time.Now()
	pe.policy.UpdatedBy = updatedBy

	if pe.logger != nil {
		pe.logger.LogAdminChange(updatedBy, audit.ActionPolicyChange, "password_policy",
			fmt.Sprintf("min_length=%d", minLength))
	}

	return nil
}

// UpdateSessionPolicy updates session-related policy settings
func (pe *PolicyEnforcer) UpdateSessionPolicy(timeout, maxSession time.Duration, maxConcurrent int, updatedBy string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if timeout < time.Minute {
		return fmt.Errorf("session timeout must be at least 1 minute")
	}

	pe.policy.SessionTimeout = timeout
	pe.policy.MaxSessionTime = maxSession
	pe.policy.MaxConcurrentSess = maxConcurrent
	pe.policy.UpdatedAt = time.Now()
	pe.policy.UpdatedBy = updatedBy

	if pe.logger != nil {
		pe.logger.LogAdminChange(updatedBy, audit.ActionPolicyChange, "session_policy",
			fmt.Sprintf("timeout=%v, max_session=%v", timeout, maxSession))
	}

	return nil
}

// UpdateLockoutPolicy updates lockout-related policy settings
func (pe *PolicyEnforcer) UpdateLockoutPolicy(maxAttempts int, lockoutDuration time.Duration, updatedBy string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if maxAttempts < 1 {
		return fmt.Errorf("max login attempts must be at least 1")
	}

	pe.policy.MaxLoginAttempts = maxAttempts
	pe.policy.LockoutDuration = lockoutDuration
	pe.policy.UpdatedAt = time.Now()
	pe.policy.UpdatedBy = updatedBy

	if pe.logger != nil {
		pe.logger.LogAdminChange(updatedBy, audit.ActionPolicyChange, "lockout_policy",
			fmt.Sprintf("max_attempts=%d, lockout_duration=%v", maxAttempts, lockoutDuration))
	}

	return nil
}

// EnforcePasswordPolicy validates a password against the current policy
func (pe *PolicyEnforcer) EnforcePasswordPolicy(password string) []string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return auth.ValidatePasswordPolicy(password, pe.policy.MinPasswordLength)
}

// ShouldRequireMFA checks if MFA is required for a user
func (pe *PolicyEnforcer) ShouldRequireMFA(user *models.User) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.policy.MFARequired {
		return true
	}
	if pe.policy.MFAForAdmins && (user.Role == models.RoleAdministrator || user.Role == models.RoleSecurityOfficer) {
		return true
	}
	return false
}

// IsAccountLocked checks if an account should be locked based on failed attempts
func (pe *PolicyEnforcer) IsAccountLocked(failedAttempts int, lockedUntil time.Time) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if failedAttempts >= pe.policy.MaxLoginAttempts {
		if time.Now().Before(lockedUntil) {
			return true
		}
	}
	return false
}

// GetLockoutDuration returns the current lockout duration
func (pe *PolicyEnforcer) GetLockoutDuration() time.Duration {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.policy.LockoutDuration
}

// GetMaxLoginAttempts returns the max login attempts setting
func (pe *PolicyEnforcer) GetMaxLoginAttempts() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.policy.MaxLoginAttempts
}
