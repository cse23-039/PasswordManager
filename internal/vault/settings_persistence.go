// Package vault provides persistent storage for all vault settings and admin state
package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"password-manager/internal/auth"
	"password-manager/internal/models"
)

// VaultSettingsID is the special ID for vault settings entry
const VaultSettingsID = "__VAULT_SETTINGS__"

// VaultSettings stores all configuration and admin state in the vault
type VaultSettings struct {
	// Security Policy
	SecurityPolicy *PersistentSecurityPolicy `json:"security_policy"`

	// Session Settings
	SessionSettings *PersistentSessionSettings `json:"session_settings"`

	// Access Control State
	AccessState *PersistentAccessState `json:"access_state"`

	// Permissions (for extensibility)
	UserPermissions []string `json:"user_permissions"`

	// Custom RBAC role → permission overrides (empty = use compiled defaults)
	RolePermissions map[string][]string `json:"role_permissions,omitempty"`

	// Vault Access Key — optional shared passphrase required after login.
	// Hashed with Argon2id so the raw key is never stored on disk.
	VaultAccessKeyHash []byte `json:"vault_access_key_hash,omitempty"`
	VaultAccessKeySalt []byte `json:"vault_access_key_salt,omitempty"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PersistentSecurityPolicy stores security policy settings
type PersistentSecurityPolicy struct {
	// Password requirements
	MinPasswordLength    int  `json:"min_password_length"`
	RequireUppercase     bool `json:"require_uppercase"`
	RequireLowercase     bool `json:"require_lowercase"`
	RequireNumbers       bool `json:"require_numbers"`
	RequireSpecialChars  bool `json:"require_special_chars"`
	PasswordExpiryDays   int  `json:"password_expiry_days"`
	PasswordHistoryCount int  `json:"password_history_count"`

	// MFA requirements
	MFARequired        bool `json:"mfa_required"`
	MFAGracePeriodDays int  `json:"mfa_grace_period_days"`

	// Session management
	SessionTimeoutMins    int `json:"session_timeout_mins"`
	MaxFailedAttempts     int `json:"max_failed_attempts"`
	LockoutDurationMins   int `json:"lockout_duration_mins"`
	InactivityTimeoutMin  int `json:"inactivity_timeout_min"`
	MaxConcurrentSessions int `json:"max_concurrent_sessions"` // 0 = unlimited

	// Audit settings
	AuditRetentionDays int    `json:"audit_retention_days"`
	AuditDetailLevel   string `json:"audit_detail_level"`

	UpdatedAt time.Time `json:"updated_at"`
}

// PersistentSessionSettings stores session configuration
type PersistentSessionSettings struct {
	SessionTimeoutMins    int  `json:"session_timeout_mins"`
	InactivityTimeoutMins int  `json:"inactivity_timeout_mins"`
	AutoLockEnabled       bool `json:"auto_lock_enabled"`
	AutoLockDelayMins     int  `json:"auto_lock_delay_mins"`
	RememberLastLogin     bool `json:"remember_last_login"`
}

// PersistentAccessState stores access control state
type PersistentAccessState struct {
	IsAccessRevoked   bool       `json:"is_access_revoked"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevokedReason     string     `json:"revoked_reason,omitempty"`
	RevokedUntil      *time.Time `json:"revoked_until,omitempty"`
	LastSessionID     string     `json:"last_session_id,omitempty"`
	LastSessionStart  *time.Time `json:"last_session_start,omitempty"`
	TotalLoginCount   int        `json:"total_login_count"`
	SuccessfulLogins  int        `json:"successful_logins"`
	FailedLogins      int        `json:"failed_logins"`
	LastFailedLoginAt *time.Time `json:"last_failed_login_at,omitempty"`
}

// NewDefaultVaultSettings creates default vault settings
func NewDefaultVaultSettings() *VaultSettings {
	now := time.Now()
	return &VaultSettings{
		SecurityPolicy: &PersistentSecurityPolicy{
			MinPasswordLength:     12,
			RequireUppercase:      true,
			RequireLowercase:      true,
			RequireNumbers:        true,
			RequireSpecialChars:   true,
			PasswordExpiryDays:    90,
			PasswordHistoryCount:  5,
			MFARequired:           true,
			MFAGracePeriodDays:    7,
			SessionTimeoutMins:    30,
			MaxFailedAttempts:     5,
			LockoutDurationMins:   15,
			InactivityTimeoutMin:  10,
			MaxConcurrentSessions: 3,
			AuditRetentionDays:    365,
			AuditDetailLevel:      "detailed",
			UpdatedAt:             now,
		},
		SessionSettings: &PersistentSessionSettings{
			SessionTimeoutMins:    30,
			InactivityTimeoutMins: 10,
			AutoLockEnabled:       true,
			AutoLockDelayMins:     5,
			RememberLastLogin:     false,
		},
		AccessState: &PersistentAccessState{
			IsAccessRevoked:  false,
			TotalLoginCount:  0,
			SuccessfulLogins: 0,
			FailedLogins:     0,
		},
		UserPermissions: []string{
			"manage_own_secrets",
			"view_own_secrets",
			"export_vault",
			"import_vault",
			"change_password",
			"manage_mfa",
			"view_audit_logs",
			"create_backup",
			"restore_backup",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ============================================
// VaultWithUser Settings Methods
// ============================================

// GetSettings returns the vault settings (loads from vault if needed)
func (v *VaultWithUser) GetSettings() (*VaultSettings, error) {
	if !v.Vault.IsUnlocked() {
		return nil, fmt.Errorf("vault is locked")
	}

	v.Vault.mu.RLock()
	defer v.Vault.mu.RUnlock()

	settingsEntry, exists := v.Vault.entries[VaultSettingsID]
	if !exists {
		// Return default settings if not configured
		return NewDefaultVaultSettings(), nil
	}

	var settings VaultSettings
	if err := json.Unmarshal([]byte(settingsEntry.Notes), &settings); err != nil {
		return nil, fmt.Errorf("failed to parse vault settings: %w", err)
	}

	return &settings, nil
}

// SaveSettings saves vault settings to the vault
func (v *VaultWithUser) SaveSettings(settings *VaultSettings) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault is locked")
	}

	settings.UpdatedAt = time.Now()

	settingsData, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to serialize settings: %w", err)
	}

	settingsEntry := &SecretData{
		ID:       VaultSettingsID,
		Name:     "__VAULT_SETTINGS__",
		Category: "__SYSTEM__",
		Notes:    string(settingsData),
	}

	v.Vault.mu.Lock()
	v.Vault.entries[VaultSettingsID] = settingsEntry
	v.Vault.dirty = true
	v.Vault.mu.Unlock()

	return v.Vault.saveToFile()
}

// ============================================
// Vault Access Key Methods
// ============================================

// HasVaultAccessKey returns true if a vault access key has been configured by an admin.
// When true, every user must enter the key after login before viewing any secrets.
func (v *VaultWithUser) HasVaultAccessKey() bool {
	settings, err := v.GetSettings()
	if err != nil || settings == nil {
		return false
	}
	return len(settings.VaultAccessKeyHash) > 0
}

// SetVaultAccessKey hashes and stores a new vault access key in the vault settings.
// Must be called while the vault is unlocked. Key must be at least 8 characters.
func (v *VaultWithUser) SetVaultAccessKey(key string) error {
	if len(key) < 8 {
		return fmt.Errorf("vault access key must be at least 8 characters")
	}
	settings, err := v.GetSettings()
	if err != nil || settings == nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}
	salt := make([]byte, SaltLength)
	if _, err2 := rand.Read(salt); err2 != nil {
		return fmt.Errorf("failed to generate salt: %w", err2)
	}
	settings.VaultAccessKeyHash = hashUserPassword(key, salt)
	settings.VaultAccessKeySalt = salt
	settings.UpdatedAt = time.Now()
	return v.SaveSettings(settings)
}

// VerifyVaultAccessKey checks the supplied key against the stored hash.
// Returns (true, nil) on match, (false, nil) on mismatch, or (false, err) on failure.
// If no vault access key has been set, always returns (true, nil).
func (v *VaultWithUser) VerifyVaultAccessKey(key string) (bool, error) {
	settings, err := v.GetSettings()
	if err != nil || settings == nil {
		return false, fmt.Errorf("failed to load settings")
	}
	if len(settings.VaultAccessKeyHash) == 0 {
		return true, nil // no key configured — open to all logged-in users
	}
	expected := hashUserPassword(key, settings.VaultAccessKeySalt)
	return hmac.Equal(expected, settings.VaultAccessKeyHash), nil
}

// ClearVaultAccessKey removes the vault access key requirement entirely.
func (v *VaultWithUser) ClearVaultAccessKey() error {
	settings, err := v.GetSettings()
	if err != nil || settings == nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}
	settings.VaultAccessKeyHash = nil
	settings.VaultAccessKeySalt = nil
	settings.UpdatedAt = time.Now()
	return v.SaveSettings(settings)
}

// ============================================
// Security Policy Methods
// ============================================

// GetSecurityPolicy returns the security policy from vault
func (v *VaultWithUser) GetSecurityPolicy() (*PersistentSecurityPolicy, error) {
	settings, err := v.GetSettings()
	if err != nil {
		return nil, err
	}
	return settings.SecurityPolicy, nil
}

// UpdateSecurityPolicy updates the security policy in vault
func (v *VaultWithUser) UpdateSecurityPolicy(policy *PersistentSecurityPolicy) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	policy.UpdatedAt = time.Now()
	settings.SecurityPolicy = policy

	// Log the change
	if v.userProfile != nil {
		v.auditLog.LogEvent(v.userProfile.Username, AuditEventPolicyChange,
			AuditCategoryAdmin, "Security policy updated", AuditResultSuccess)
	}

	if err := v.SaveSettings(settings); err != nil {
		return err
	}

	// Enforce audit retention immediately: prune entries older than the new limit.
	if policy.AuditRetentionDays > 0 {
		v.auditLog.PruneOldEntries(policy.AuditRetentionDays)
	}
	return nil
}

// ============================================
// Session Settings Methods
// ============================================

// GetSessionSettings returns session settings from vault
func (v *VaultWithUser) GetSessionSettings() (*PersistentSessionSettings, error) {
	settings, err := v.GetSettings()
	if err != nil {
		return nil, err
	}
	return settings.SessionSettings, nil
}

// UpdateSessionSettings updates session settings in vault
func (v *VaultWithUser) UpdateSessionSettings(sessionSettings *PersistentSessionSettings) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	settings.SessionSettings = sessionSettings
	return v.SaveSettings(settings)
}

// ============================================
// Access State Methods
// ============================================

// GetAccessState returns access state from vault
func (v *VaultWithUser) GetAccessState() (*PersistentAccessState, error) {
	settings, err := v.GetSettings()
	if err != nil {
		return nil, err
	}
	return settings.AccessState, nil
}

// UpdateAccessState updates access state in vault
func (v *VaultWithUser) UpdateAccessState(accessState *PersistentAccessState) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	settings.AccessState = accessState
	return v.SaveSettings(settings)
}

// RevokeVaultAccess revokes access and persists the state
func (v *VaultWithUser) RevokeVaultAccess(reason string, duration *time.Duration) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	now := time.Now()
	settings.AccessState.IsAccessRevoked = true
	settings.AccessState.RevokedAt = &now
	settings.AccessState.RevokedReason = reason

	if duration != nil {
		until := now.Add(*duration)
		settings.AccessState.RevokedUntil = &until
	}

	// Log revocation
	username := ""
	if v.userProfile != nil {
		username = v.userProfile.Username
	}
	v.auditLog.LogAccessRevoke("system", username, reason)

	return v.SaveSettings(settings)
}

// RestoreVaultAccess restores revoked access
func (v *VaultWithUser) RestoreVaultAccess() error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	settings.AccessState.IsAccessRevoked = false
	settings.AccessState.RevokedAt = nil
	settings.AccessState.RevokedReason = ""
	settings.AccessState.RevokedUntil = nil

	return v.SaveSettings(settings)
}

// IsAccessRevoked checks if vault access is revoked
func (v *VaultWithUser) IsAccessRevoked() (bool, string, *time.Time) {
	settings, err := v.GetSettings()
	if err != nil {
		return false, "", nil
	}

	if !settings.AccessState.IsAccessRevoked {
		return false, "", nil
	}

	// Check if temporary revocation has expired
	if settings.AccessState.RevokedUntil != nil {
		if time.Now().After(*settings.AccessState.RevokedUntil) {
			// Revocation has expired; do not perform any writes here. Caller
			// may choose to restore access explicitly if desired.
			return false, "", nil
		}
	}

	return true, settings.AccessState.RevokedReason, settings.AccessState.RevokedUntil
}

// RecordLoginAttempt records a login attempt in persistent storage
func (v *VaultWithUser) RecordLoginAttempt(success bool) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	settings.AccessState.TotalLoginCount++
	if success {
		settings.AccessState.SuccessfulLogins++
	} else {
		settings.AccessState.FailedLogins++
		now := time.Now()
		settings.AccessState.LastFailedLoginAt = &now
	}

	return v.SaveSettings(settings)
}

// RecordSessionStart records session start in persistent storage
func (v *VaultWithUser) RecordSessionStart(sessionID string) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	now := time.Now()
	settings.AccessState.LastSessionID = sessionID
	settings.AccessState.LastSessionStart = &now

	return v.SaveSettings(settings)
}

// ============================================
// Permission Methods
// ============================================

// GetUserPermissions returns user permissions from vault
func (v *VaultWithUser) GetUserPermissions() ([]string, error) {
	settings, err := v.GetSettings()
	if err != nil {
		return nil, err
	}
	return settings.UserPermissions, nil
}

// HasPermission checks if the logged-in user has a specific permission via RBAC.
func (v *VaultWithUser) HasPermission(permission string) bool {
	role := v.GetRole()
	if role == "" {
		return false
	}
	u := &models.User{Role: role}
	return auth.HasPermission(u, permission)
}

// AddPermission adds a permission to the user
func (v *VaultWithUser) AddPermission(permission string) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	// Check if already has permission
	for _, p := range settings.UserPermissions {
		if p == permission {
			return nil // Already has it
		}
	}

	settings.UserPermissions = append(settings.UserPermissions, permission)
	return v.SaveSettings(settings)
}

// RemovePermission removes a permission from the user
func (v *VaultWithUser) RemovePermission(permission string) error {
	settings, err := v.GetSettings()
	if err != nil {
		return err
	}

	for i, p := range settings.UserPermissions {
		if p == permission {
			settings.UserPermissions = append(settings.UserPermissions[:i], settings.UserPermissions[i+1:]...)
			break
		}
	}

	return v.SaveSettings(settings)
}

// ============================================
// Policy Validation Methods
// ============================================

// ValidatePasswordAgainstVaultPolicy validates password against stored policy.
// When the vault is locked (e.g. during first-admin registration) it falls back
// to the built-in defaults so callers always get meaningful validation.
func (v *VaultWithUser) ValidatePasswordAgainstVaultPolicy(password string) (bool, []string) {
	policy, err := v.GetSecurityPolicy()
	if err != nil || policy == nil {
		// Vault locked or no settings yet — validate against built-in defaults
		policy = NewDefaultVaultSettings().SecurityPolicy
	}

	var errors []string

	if len(password) < policy.MinPasswordLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters", policy.MinPasswordLength))
	}

	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		errors = append(errors, "password must contain uppercase letter")
	}
	if policy.RequireLowercase && !hasLower {
		errors = append(errors, "password must contain lowercase letter")
	}
	if policy.RequireNumbers && !hasDigit {
		errors = append(errors, "password must contain number")
	}
	if policy.RequireSpecialChars && !hasSpecial {
		errors = append(errors, "password must contain special character")
	}

	return len(errors) == 0, errors
}

// CheckMFARequirement checks if MFA is required by policy.
// When MFAGracePeriodDays > 0 and the account is younger than the grace period,
// MFA is treated as not yet required even if the policy mandates it.
func (v *VaultWithUser) CheckMFARequirement() (required bool, enabled bool) {
	policy, err := v.GetSecurityPolicy()
	if err != nil {
		return false, false
	}

	required = policy.MFARequired
	enabled = v.userProfile != nil && v.userProfile.MFAEnabled

	// Grace period: if the user was created recently enough, defer the MFA requirement.
	if required && !enabled && v.userProfile != nil && policy.MFAGracePeriodDays > 0 {
		daysSinceCreation := int(time.Since(v.userProfile.CreatedAt).Hours() / 24)
		if daysSinceCreation < policy.MFAGracePeriodDays {
			required = false
		}
	}

	return required, enabled
}

// CheckPasswordExpiry checks if password has expired based on policy
func (v *VaultWithUser) CheckPasswordExpiry() (expired bool, daysUntilExpiry int) {
	policy, err := v.GetSecurityPolicy()
	if err != nil {
		return false, 0
	}

	if v.userProfile == nil || v.userProfile.PasswordChangeAt == nil {
		return false, policy.PasswordExpiryDays
	}

	expiryDate := v.userProfile.PasswordChangeAt.AddDate(0, 0, policy.PasswordExpiryDays)
	daysUntilExpiry = int(time.Until(expiryDate).Hours() / 24)

	if daysUntilExpiry < 0 {
		return true, 0
	}

	return false, daysUntilExpiry
}

// GetSessionTimeout returns the session timeout from stored policy
func (v *VaultWithUser) GetSessionTimeout() time.Duration {
	policy, err := v.GetSecurityPolicy()
	if err != nil {
		return 30 * time.Minute // Default
	}
	return time.Duration(policy.SessionTimeoutMins) * time.Minute
}

// GetInactivityTimeout returns the inactivity timeout from stored policy
func (v *VaultWithUser) GetInactivityTimeout() time.Duration {
	policy, err := v.GetSecurityPolicy()
	if err != nil {
		return 10 * time.Minute // Default
	}
	return time.Duration(policy.InactivityTimeoutMin) * time.Minute
}

// GetLockoutSettings returns lockout configuration from stored policy
func (v *VaultWithUser) GetLockoutSettings() (maxAttempts int, lockoutDuration time.Duration) {
	policy, err := v.GetSecurityPolicy()
	if err != nil {
		return 5, 15 * time.Minute // Defaults
	}
	return policy.MaxFailedAttempts, time.Duration(policy.LockoutDurationMins) * time.Minute
}

// ============================================
// Role Permissions Methods
// ============================================

// GetRolePermissionsConfig returns the stored role→permission mapping.
// Returns nil map (not an error) when no overrides have been saved yet.
func (v *VaultWithUser) GetRolePermissionsConfig() (map[string][]string, error) {
	settings, err := v.GetSettings()
	if err != nil {
		return nil, err
	}
	if settings.RolePermissions == nil {
		// Return a deep copy of the current runtime map (compiled defaults)
		return auth.DefaultRolePermissions(), nil
	}
	// Deep-copy to avoid callers mutating stored state
	out := make(map[string][]string, len(settings.RolePermissions))
	for role, perms := range settings.RolePermissions {
		cp := make([]string, len(perms))
		copy(cp, perms)
		out[role] = cp
	}
	return out, nil
}

// UpdateRolePermissionsConfig saves new role→permission overrides to the vault
// and immediately applies them to the in-process auth.RolePermissions map.
func (v *VaultWithUser) UpdateRolePermissionsConfig(perms map[string][]string) error {
	if v.userProfile == nil {
		return fmt.Errorf("authentication required")
	}
	if !v.HasPermission(auth.CanManagePolicy) {
		return fmt.Errorf("permission denied: missing %s", auth.CanManagePolicy)
	}

	settings, err := v.GetSettings()
	if err != nil {
		return err
	}
	settings.RolePermissions = perms
	if err := v.SaveSettings(settings); err != nil {
		return err
	}
	// Apply immediately so checks in the same session see the new rules
	auth.ApplyRolePermissions(perms)

	if v.userProfile != nil {
		v.auditLog.LogEvent(v.userProfile.Username, AuditEventPolicyChange,
			AuditCategoryAdmin, "Role permissions updated", AuditResultSuccess)
	}
	return nil
}

// ApplyStoredRolePermissions loads any persisted role permission overrides from
// the vault and applies them to the in-process auth.RolePermissions map.
// Safe to call after every successful login so the runtime map stays in sync.
func (v *VaultWithUser) ApplyStoredRolePermissions() {
	settings, err := v.GetSettings()
	if err != nil || settings.RolePermissions == nil {
		return
	}
	auth.ApplyRolePermissions(settings.RolePermissions)
}
