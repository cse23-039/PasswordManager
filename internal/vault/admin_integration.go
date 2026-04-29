// Package vault provides administrative integration for vault management
package vault

import (
	"fmt"
	"os"
	"password-manager/internal/auth"
	"path/filepath"
	"strings"
	"time"
)

// VaultAdmin provides administrative functions for vault management
type VaultAdmin struct {
	vault     *VaultWithUser
	backupDir string
}

func (va *VaultAdmin) currentUsername() string {
	if !va.vault.Vault.IsUnlocked() {
		return ""
	}
	if profile, err := va.vault.GetUserProfile(); err == nil {
		return profile.Username
	}
	return ""
}

func (va *VaultAdmin) requireBackupPermission(permission string) error {
	if !va.vault.Vault.IsUnlocked() {
		return fmt.Errorf("vault must be unlocked")
	}
	if !va.vault.HasPermission(permission) {
		return fmt.Errorf("permission denied: missing %s", permission)
	}
	return nil
}

func (va *VaultAdmin) requireAnyBackupPermission(permissions ...string) error {
	if !va.vault.Vault.IsUnlocked() {
		return fmt.Errorf("vault must be unlocked")
	}
	for _, permission := range permissions {
		if va.vault.HasPermission(permission) {
			return nil
		}
	}
	return fmt.Errorf("permission denied: missing one of [%s]", strings.Join(permissions, ", "))
}

// BackupInfo contains information about a vault backup
type BackupInfo struct {
	ID          string    `json:"id"`
	FilePath    string    `json:"file_path"`
	CreatedAt   time.Time `json:"created_at"`
	Size        int64     `json:"size"`
	Description string    `json:"description"`
}

// NewVaultAdmin creates an admin interface for the vault
func NewVaultAdmin(vault *VaultWithUser) *VaultAdmin {
	// Store backups alongside the vault file so they share the same location
	// that the user already knows about (e.g. %APPDATA%/PasswordManager/backups).
	backupDir := filepath.Join(filepath.Dir(vault.Vault.filePath), "backups")
	return &VaultAdmin{
		vault:     vault,
		backupDir: backupDir,
	}
}

// ============================================
// BACKUP & RESTORE OPERATIONS
// ============================================

// CreateBackup creates an encrypted backup of the vault
func (va *VaultAdmin) CreateBackup(description string) (*BackupInfo, error) {
	if err := va.requireBackupPermission(auth.CanBackupVault); err != nil {
		return nil, err
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(va.backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename
	timestamp := time.Now().Format("20060102_150405")
	backupID := fmt.Sprintf("backup_%s", timestamp)
	backupPath := filepath.Join(va.backupDir, backupID+".pwm.bak")

	// Export vault
	if err := va.vault.Vault.ExportVault(backupPath); err != nil {
		return nil, fmt.Errorf("failed to create backup: %w", err)
	}

	// Get file size
	info, err := os.Stat(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup info: %w", err)
	}

	// Log backup operation
	username := va.currentUsername()
	va.vault.auditLog.LogVaultOperation(username, AuditEventVaultBackup,
		fmt.Sprintf("Backup created: %s", backupID), true)

	return &BackupInfo{
		ID:          backupID,
		FilePath:    backupPath,
		CreatedAt:   time.Now(),
		Size:        info.Size(),
		Description: description,
	}, nil
}

// ListBackups returns all available backups
func (va *VaultAdmin) ListBackups() ([]*BackupInfo, error) {
	if err := va.requireAnyBackupPermission(auth.CanBackupVault, auth.CanRestoreVault); err != nil {
		return nil, err
	}

	var backups []*BackupInfo

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(va.backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	files, err := os.ReadDir(va.backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".bak" {
			fullPath := filepath.Join(va.backupDir, file.Name())
			info, err := file.Info()
			if err != nil {
				continue
			}

			backups = append(backups, &BackupInfo{
				ID:        file.Name()[:len(file.Name())-8], // Remove .pwm.bak
				FilePath:  fullPath,
				CreatedAt: info.ModTime(),
				Size:      info.Size(),
			})
		}
	}

	return backups, nil
}

// RestoreBackup restores the vault from a backup
// NOTE: This will overwrite the current vault!
func (va *VaultAdmin) RestoreBackup(backupID, targetPath string) error {
	if err := va.requireBackupPermission(auth.CanRestoreVault); err != nil {
		return err
	}

	expectedTarget := filepath.Clean(va.vault.Vault.GetFilePath())
	requestedTarget := filepath.Clean(targetPath)
	if requestedTarget != expectedTarget {
		return fmt.Errorf("invalid restore target path")
	}

	// Log restore attempt
	username := va.currentUsername()

	backupPath := filepath.Join(va.backupDir, backupID+".pwm.bak")
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			fmt.Sprintf("Restore failed: backup not found %s", backupID), false)
		return fmt.Errorf("backup not found: %s", backupID)
	}

	// Read backup data and validate format before overwriting live vault.
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			fmt.Sprintf("Restore failed: backup not found %s", backupID), false)
		return fmt.Errorf("backup not found: %s", backupID)
	}

	// Read backup into memory first so we can validate before touching anything.
	data, err := os.ReadFile(backupPath)
	if err != nil {
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			"Restore failed: could not read backup", false)
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Reject backups that are not in V2 (AES-256-GCM) format.
	if len(data) <= len(vaultMagicV2) || string(data[:len(vaultMagicV2)]) != vaultMagicV2 {
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			"Restore failed: backup is not V2 encrypted format", false)
		return fmt.Errorf("backup uses an insecure legacy format and cannot be restored; re-save it with the current version first")
	}

	// Validate the backup parses correctly.
	if _, err := readVaultFile(backupPath); err != nil {
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			"Restore failed: backup file format invalid or corrupted", false)
		return fmt.Errorf("backup file invalid: %w", err)
	}

	// Safety copy: preserve the current live vault before overwriting it.
	safetyPath := targetPath + ".pre-restore.bak"
	if existing, readErr := os.ReadFile(targetPath); readErr == nil {
		_ = os.WriteFile(safetyPath, existing, 0600)
	}

	// Write to target atomically: write to temp then rename.
	tmp := targetPath + ".restore.tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			"Restore failed: could not write temp vault", false)
		return fmt.Errorf("failed to write temp vault: %w", err)
	}
	if err := os.Rename(tmp, targetPath); err != nil {
		_ = os.Remove(tmp)
		va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
			"Restore failed: could not move restored vault into place", false)
		return fmt.Errorf("failed to restore vault: %w", err)
	}

	va.vault.auditLog.LogVaultOperation(username, AuditEventVaultRestore,
		fmt.Sprintf("Vault restored from %s", backupID), true)

	return nil
}

// DeleteBackup removes a backup file
func (va *VaultAdmin) DeleteBackup(backupID string) error {
	if err := va.requireBackupPermission(auth.CanRestoreVault); err != nil {
		return err
	}

	backupPath := filepath.Join(va.backupDir, backupID+".pwm.bak")
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupID)
	}

	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("failed to delete backup: %w", err)
	}

	// Log deletion
	username := va.currentUsername()
	va.vault.auditLog.LogAdminChange(username, "DELETE_BACKUP", "", backupID)

	return nil
}

// ============================================
// ACCESS CONTROL
// ============================================

// RevokeAccess immediately revokes access by locking the vault
func (va *VaultAdmin) RevokeAccess(reason string) error {
	username := ""
	if va.vault.Vault.IsUnlocked() {
		if profile, err := va.vault.GetUserProfile(); err == nil {
			username = profile.Username
		}
	}

	// Log revocation
	va.vault.auditLog.LogAccessRevoke("admin", username, reason)

	// Lock the vault
	return va.vault.Vault.Lock()
}

// IsAccountLocked checks if the vault account is locked
func (va *VaultAdmin) IsAccountLocked() (bool, *time.Time) {
	if va.vault.userProfile == nil {
		return false, nil
	}

	if va.vault.userProfile.LockoutUntil != nil {
		if time.Now().Before(*va.vault.userProfile.LockoutUntil) {
			return true, va.vault.userProfile.LockoutUntil
		}
	}
	return false, nil
}

// UnlockAccount manually unlocks a locked account
func (va *VaultAdmin) UnlockAccount() error {
	if va.vault.userProfile == nil {
		return fmt.Errorf("no user profile loaded")
	}

	va.vault.userProfile.FailedAttempts = 0
	va.vault.userProfile.LockoutUntil = nil

	// Log unlock
	username := va.vault.userProfile.Username
	va.vault.auditLog.LogAdminChange("admin", "UNLOCK_ACCOUNT", username, "Account unlocked manually")

	return va.vault.saveUserProfile()
}

// ============================================
// AUDIT & COMPLIANCE
// ============================================

// GetAuditStats returns audit log statistics
func (va *VaultAdmin) GetAuditStats() map[string]interface{} {
	return va.vault.auditLog.GetStats()
}

// GetFailedLoginAttempts returns failed login entries
func (va *VaultAdmin) GetFailedLoginAttempts() []*VaultAuditEntry {
	return va.vault.auditLog.GetFailedLogins()
}

// GetSecurityEvents returns security-related audit entries
func (va *VaultAdmin) GetSecurityEvents() []*VaultAuditEntry {
	return va.vault.auditLog.GetSecurityEvents()
}

// GetAdminEvents returns administrative audit entries
func (va *VaultAdmin) GetAdminEvents() []*VaultAuditEntry {
	return va.vault.auditLog.GetAdminEvents()
}

// VerifyAuditIntegrity checks all audit entries for tampering
func (va *VaultAdmin) VerifyAuditIntegrity() (verified, tampered, unverifiable int) {
	return va.vault.auditLog.VerifyAllIntegrity()
}

// ExportAuditForSIEM exports audit logs for SIEM integration
func (va *VaultAdmin) ExportAuditForSIEM(format string) (string, error) {
	return va.vault.ExportAuditLog(format)
}

// GetAuditEntriesSince returns audit entries since a specific time
func (va *VaultAdmin) GetAuditEntriesSince(since time.Time) []*VaultAuditEntry {
	return va.vault.auditLog.GetEntriesSince(since)
}

// GenerateComplianceReport generates a compliance report
func (va *VaultAdmin) GenerateComplianceReport() map[string]interface{} {
	stats := va.vault.auditLog.GetStats()
	verified, tampered, unverifiable := va.vault.auditLog.VerifyAllIntegrity()

	report := map[string]interface{}{
		"report_date": time.Now(),
		"audit_stats": stats,
		"integrity_check": map[string]int{
			"verified":     verified,
			"tampered":     tampered,
			"unverifiable": unverifiable,
		},
		"compliance_status": "compliant",
	}

	// Mark non-compliant if tampering detected
	if tampered > 0 {
		report["compliance_status"] = "non_compliant"
		report["compliance_issues"] = []string{"Tampered audit logs detected"}
	}

	return report
}

// ============================================
// POLICY MANAGEMENT (uses persisted vault settings)
// ============================================

// GetSecurityPolicyFromVault returns the security policy from vault storage
func (va *VaultAdmin) GetSecurityPolicyFromVault() (*PersistentSecurityPolicy, error) {
	return va.vault.GetSecurityPolicy()
}

// UpdateSecurityPolicyInVault updates and persists the security policy
func (va *VaultAdmin) UpdateSecurityPolicyInVault(policy *PersistentSecurityPolicy) error {
	return va.vault.UpdateSecurityPolicy(policy)
}

// ValidatePasswordAgainstPolicy checks if password meets policy (uses persisted policy)
func (va *VaultAdmin) ValidatePasswordAgainstPolicy(password string, policy *PersistentSecurityPolicy) (bool, []string) {
	var errors []string

	if len(password) < policy.MinPasswordLength {
		errors = append(errors, fmt.Sprintf("Password must be at least %d characters", policy.MinPasswordLength))
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
		errors = append(errors, "Password must contain uppercase letter")
	}
	if policy.RequireLowercase && !hasLower {
		errors = append(errors, "Password must contain lowercase letter")
	}
	if policy.RequireNumbers && !hasDigit {
		errors = append(errors, "Password must contain number")
	}
	if policy.RequireSpecialChars && !hasSpecial {
		errors = append(errors, "Password must contain special character")
	}

	return len(errors) == 0, errors
}

// CheckMFAComplianceFromVault checks if MFA settings meet persisted policy
func (va *VaultAdmin) CheckMFAComplianceFromVault() (bool, string) {
	required, enabled := va.vault.CheckMFARequirement()
	if required && !enabled {
		return false, "MFA is required by policy"
	}
	return true, ""
}

// CheckPasswordExpiryFromVault checks if password has expired based on persisted policy
func (va *VaultAdmin) CheckPasswordExpiryFromVault() (bool, int) {
	return va.vault.CheckPasswordExpiry()
}

// GetAccessStateFromVault returns the persisted access state
func (va *VaultAdmin) GetAccessStateFromVault() (*PersistentAccessState, error) {
	return va.vault.GetAccessState()
}

// GetSessionSettingsFromVault returns the persisted session settings
func (va *VaultAdmin) GetSessionSettingsFromVault() (*PersistentSessionSettings, error) {
	return va.vault.GetSessionSettings()
}

// UpdateSessionSettingsInVault updates and persists session settings
func (va *VaultAdmin) UpdateSessionSettingsInVault(settings *PersistentSessionSettings) error {
	return va.vault.UpdateSessionSettings(settings)
}

// GetAllVaultSettings returns all persisted vault settings
func (va *VaultAdmin) GetAllVaultSettings() (*VaultSettings, error) {
	return va.vault.GetSettings()
}

// ============================================
// VAULT STATISTICS
// ============================================

// GetVaultStats returns vault statistics
func (va *VaultAdmin) GetVaultStats() (map[string]interface{}, error) {
	return va.vault.Vault.GetStats()
}
