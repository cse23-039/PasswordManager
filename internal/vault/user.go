// Package vault provides user management for local vault
package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"runtime/debug"

	"golang.org/x/crypto/argon2"

	"password-manager/internal/auth"
	"password-manager/internal/models"
)

// Sentinel login errors – used by the UI to show specific messages.
var (
	ErrUserNotFound    = errors.New("user does not exist")
	ErrInvalidPassword = errors.New("invalid password")
	ErrPasswordExpired = errors.New("password expired")
)

// UserProfile stores user information in the vault
type UserProfile struct {
	Username         string     `json:"username"`
	PasswordHash     []byte     `json:"password_hash"`
	PasswordSalt     []byte     `json:"password_salt"`
	Email            string     `json:"email,omitempty"`
	Role             string     `json:"role"`
	MFAEnabled       bool       `json:"mfa_enabled"`
	MFASecret        string     `json:"mfa_secret,omitempty"`
	TOTPVerified     bool       `json:"totp_verified"`
	CreatedAt        time.Time  `json:"created_at"`
	LastLogin        time.Time  `json:"last_login,omitempty"`
	FailedAttempts   int        `json:"failed_attempts"`
	LockoutUntil     *time.Time `json:"lockout_until,omitempty"`
	PasswordChangeAt *time.Time `json:"password_change_at,omitempty"`
}

// VaultWithUser extends Vault with single-user authentication
// For a local password manager, there's typically one user per vault
type VaultWithUser struct {
	*Vault
	userProfile *UserProfile
	auditLog    *VaultAuditLog
	// path to a process lock file created on startup; removed on logout
	lockFilePath string
	// protected state during interactive login when MFA is pending
	pendingMu sync.Mutex
	// pendingMFASecret holds the decrypted TOTP secret for the user currently
	// awaiting enrollment or verification in the interactive UI. It is kept
	// in memory only for the duration of the login flow and cleared after use.
	pendingMFASecret string
	// per-user locks to protect TOTP counter updates and related user-record mutations
	totpLocks   map[string]*sync.Mutex
	totpLocksMu sync.Mutex
}

// NewVaultWithUser creates a vault with user management
func NewVaultWithUser(filePath string) *VaultWithUser {
	baseVault := NewVault(filePath)

	// Create audit log alongside vault file, sharing the vault's app seed so
	// the audit file uses the same per-vault companion-file key.
	auditPath := filePath + ".audit"
	auditLog := NewVaultAuditLog(VaultAuditConfig{
		FilePath:   auditPath,
		Vault:      baseVault,
		AutoSave:   true,
		MaxEntries: 100000,
	})

	v := &VaultWithUser{
		Vault:     baseVault,
		auditLog:  auditLog,
		totpLocks: make(map[string]*sync.Mutex),
	}
	// Lockfile behaviour: if a prior lockfile exists the previous shutdown
	// was likely unclean; in that case reset stale session counters.
	lockPath := filePath + ".lock"
	if _, err := os.Stat(lockPath); err == nil {
		// previous lock exists — likely crash; clear stale session counters
		v.resetSessionCounts()
		// Record an audit event so administrators see ungraceful shutdowns.
		v.auditLog.LogEvent("system", "STARTUP", AuditCategoryVaultOps, "stale lockfile detected; reset session counters", AuditResultSuccess)
	}
	// Create or update lockfile for this process
	_ = os.WriteFile(lockPath, []byte("locked"), 0600)
	v.lockFilePath = lockPath
	return v
}

// GetRole returns the role of the currently logged-in user.
// Returns RoleAdministrator for legacy profiles that pre-date role assignment.
func (v *VaultWithUser) GetRole() string {
	if v.userProfile == nil {
		return ""
	}
	if uf, err := v.readUsersFile(); err == nil {
		if _, rec, ok := resolveUsername(uf, v.userProfile.Username); ok && rec != nil && rec.Role != "" {
			if v.userProfile.Role != rec.Role {
				v.userProfile.Role = rec.Role
			}
			// ensure in-memory username matches stored canonical entry
			v.userProfile.Username = rec.Username
			return rec.Role
		}
	}
	if v.userProfile.Role == "" {
		return models.RoleAdministrator // backward-compat: single-user vault owner is admin
	}
	return v.userProfile.Role
}

// ── Audit log accessors + exports (for admin dashboard) ────────────────────

// ExportAuditJSON exports the audit log as indented JSON bytes.
func (v *VaultWithUser) ExportAuditJSON() ([]byte, error) {
	return v.auditLog.ExportJSON()
}

// ExportAuditCSV exports the audit log as a CSV string.
func (v *VaultWithUser) ExportAuditCSV() string {
	return v.auditLog.ExportCSV()
}

// ExportAuditTXT returns a plain-text export of the audit log.
func (v *VaultWithUser) ExportAuditTXT() string {
	return v.auditLog.ExportTXT()
}

// ExportAuditCEF exports the audit log in Common Event Format.
func (v *VaultWithUser) ExportAuditCEF() string {
	return v.auditLog.ExportCEF()
}

// GetStatsByUser returns stats scoped to the current user's secrets.
// Admins additionally get the vault-wide total for reference.
func (v *VaultWithUser) GetStatsByUser() (map[string]interface{}, error) {
	baseStats, err := v.Vault.GetStats()
	if err != nil {
		return nil, err
	}
	if v.userProfile == nil {
		return baseStats, nil
	}
	currentUser := v.userProfile.Username
	// Count only secrets explicitly created by this user.
	// Unstamped secrets (created before owner-tracking was added) are
	// shown in "Total in vault" only — they are NOT attributed to any user.
	my := 0
	if all, e := v.Vault.ListSecrets(); e == nil {
		for _, s := range all {
			if s.CreatedBy == currentUser {
				my++
			}
		}
	}
	baseStats["my_entries"] = my
	baseStats["current_user"] = currentUser
	return baseStats, nil
}

// GetAuditStats returns summary statistics about the audit log.
func (v *VaultWithUser) GetAuditStats() map[string]interface{} {
	if v.userProfile == nil || !v.HasPermission(auth.CanViewAuditLogs) {
		return map[string]interface{}{}
	}
	return v.auditLog.GetStats()
}

// GetAllAuditEntries returns all audit log entries, newest first.
func (v *VaultWithUser) GetAllAuditEntries() []*VaultAuditEntry {
	if v.userProfile == nil || !v.HasPermission(auth.CanViewAuditLogs) {
		return nil
	}
	return v.auditLog.GetAllEntriesNewestFirst()
}

// GetAuditEntriesByEvent returns entries matching a specific event type, newest first.
func (v *VaultWithUser) GetAuditEntriesByEvent(event string) []*VaultAuditEntry {
	if v.userProfile == nil || !v.HasPermission(auth.CanViewAuditLogs) {
		return nil
	}
	return v.auditLog.GetEntriesByEvent(event) // already newest-first via index
}

// GetAuditEntriesByCategory returns entries matching a category, newest first.
func (v *VaultWithUser) GetAuditEntriesByCategory(cat string) []*VaultAuditEntry {
	if v.userProfile == nil || !v.HasPermission(auth.CanViewAuditLogs) {
		return nil
	}
	return v.auditLog.GetEntriesByCategory(cat) // already newest-first via index
}

// VerifyChainIntegrity checks that the audit log forms an unbroken HMAC chain.
// Returns false if any entry was deleted, inserted, reordered, or tampered with.
func (v *VaultWithUser) VerifyChainIntegrity() bool {
	return v.auditLog.VerifyChainIntegrity()
}

// VerifyAllIntegrity verifies the HMAC checksum of every audit entry.
// Returns (verified, tampered, unverifiable) counts.
func (v *VaultWithUser) VerifyAllIntegrity() (verified, tampered, unverifiable int) {
	return v.auditLog.VerifyAllIntegrity()
}

// CheckVaultTampered returns true if the vault .pwm file has been modified
// externally (i.e. not by this running app instance).
func (v *VaultWithUser) CheckVaultTampered() bool {
	return v.Vault.CheckExternalModification()
}

// SetupNewVault creates a new vault with user credentials
func (v *VaultWithUser) SetupNewVault(username, password, email string) error {
	// Validate inputs
	if len(username) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	// Check password strength
	if err := validatePasswordStrength(password); err != nil {
		return err
	}

	// Create base vault
	if err := v.Vault.Create(password); err != nil {
		return err
	}

	// Generate salt for user password
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash user password (separate from vault key derivation)
	passwordHash := hashUserPassword(password, salt)

	now := time.Now()
	v.userProfile = &UserProfile{
		Username:         username,
		PasswordHash:     passwordHash,
		PasswordSalt:     salt,
		Email:            email,
		Role:             models.RoleAdministrator, // vault creator is the Administrator
		MFAEnabled:       false,
		CreatedAt:        now,
		PasswordChangeAt: &now,
	}

	// Store user profile in vault as a special entry
	if err := v.saveUserProfile(); err != nil {
		return err
	}

	// Initialize default vault settings
	defaultSettings := NewDefaultVaultSettings()
	if err := v.SaveSettings(defaultSettings); err != nil {
		return fmt.Errorf("failed to save default settings: %w", err)
	}

	// Initialize audit log with HMAC key
	v.auditLog.SetHMACKey(v.Vault.hmacKey)
	v.auditLog.LogVaultOperation(username, AuditEventVaultCreate, "New vault created", true)

	// Persist admin to the multi-user store so the new login path works
	if err := v.saveAdminToUsersFile(username, password, email); err != nil {
		return fmt.Errorf("failed to save admin to users file: %w", err)
	}

	return nil
}

// authenticatePassword performs core password + lockout + revocation checks.
// On success the vault is unlocked and userProfile is loaded; the caller must
// finalise the login (call finalizeLogin) after any additional checks such as MFA.
// On any failure the vault is locked and an error is returned.
func (v *VaultWithUser) authenticatePassword(username, password, ipAddress string) error {
	if err := v.Vault.Unlock(password); err != nil {
		v.auditLog.LogLogin(username, false, "vault unlock failed", ipAddress)
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	v.auditLog.SetHMACKey(v.Vault.hmacKey)

	if err := v.loadUserProfile(); err != nil {
		v.auditLog.LogLogin(username, false, "profile load failed", ipAddress)
		v.Vault.Lock()
		return fmt.Errorf("failed to load user profile: %w", err)
	}

	if v.userProfile.LockoutUntil != nil && time.Now().Before(*v.userProfile.LockoutUntil) {
		v.auditLog.LogLogin(username, false, "account locked", ipAddress)
		v.Vault.Lock()
		return fmt.Errorf("account locked until %s", v.userProfile.LockoutUntil.Format(time.RFC3339))
	}

	if revoked, reason, until := v.IsAccessRevoked(); revoked {
		v.auditLog.LogLogin(username, false, "access revoked: "+reason, ipAddress)
		v.Vault.Lock()
		if until != nil {
			return fmt.Errorf("access revoked until %s: %s", until.Format(time.RFC3339), reason)
		}
		return fmt.Errorf("access revoked: %s", reason)
	}

	if v.userProfile.Username != username {
		v.auditLog.LogLogin(username, false, "invalid credentials", ipAddress)
		// Do NOT increment the stored failed-attempt counter for the real user
		// when a login attempt for a different username occurs. This prevents
		// attackers from causing account lockouts for valid users by attempting
		// login with other usernames.
		v.Vault.Lock()
		return ErrUserNotFound
	}

	expectedHash := hashUserPassword(password, v.userProfile.PasswordSalt)
	if !secureCompare(expectedHash, v.userProfile.PasswordHash) {
		v.auditLog.LogLogin(username, false, "invalid credentials", ipAddress)
		v.recordFailedAttempt()
		v.Vault.Lock()
		return ErrInvalidPassword
	}

	return nil
}

// finalizeLogin completes a successful login: resets failure counters, records
// the last-login timestamp, persists the profile, and emits an audit success event.
func (v *VaultWithUser) finalizeLogin(username, ipAddress string) error {
	// Enforce password expiry based on persisted security policy so UI cannot
	// bypass expiry checks by taking alternative login paths.
	settings, serr := v.GetSecurityPolicy()
	if serr == nil && settings != nil && settings.PasswordExpiryDays > 0 && v.userProfile.PasswordChangeAt != nil {
		expiry := v.userProfile.PasswordChangeAt.Add(time.Duration(settings.PasswordExpiryDays) * 24 * time.Hour)
		if time.Now().After(expiry) {
			return ErrPasswordExpired
		}
	}

	v.userProfile.FailedAttempts = 0
	v.userProfile.LockoutUntil = nil
	v.userProfile.LastLogin = time.Now()
	if err := v.saveUserProfile(); err != nil {
		return fmt.Errorf("failed to persist login state: %w", err)
	}
	v.RecordLoginAttempt(true)
	v.auditLog.LogLogin(username, true, "", ipAddress)
	// Apply any persisted RBAC permission overrides so the runtime map is in sync
	v.ApplyStoredRolePermissions()
	// Argon2 key derivation allocates ~64 MB; release it back to the OS immediately.
	debug.FreeOSMemory()
	return nil
}

// Login authenticates and unlocks the vault using password only.
// Uses the multi-user store when available (new path), otherwise falls back to
// the legacy single-user path for backward compatibility.
// If MFA is enabled this returns an error directing the caller to use LoginWithMFA.
func (v *VaultWithUser) Login(username, password, ipAddress string) error {
	if v.UsersFileExists() {
		// Multi-user path
		if err := v.loginMultiUser(username, password, ipAddress); err != nil {
			return err
		}
		// MFA enforcement (Req 3.1)
		required, _ := v.CheckMFARequirement()
		// Check the persistent users record for wrapped secret/enrollment state.
		uf, rerr := v.readUsersFile()
		if rerr != nil {
			// Roll back any session-side effects from loginMultiUser to avoid
			// leaking active session counts (which can lead to lockout DoS).
			v.decrementActiveSessionCount(username)
			v.userProfile = nil
			_ = v.Vault.Lock()
			return rerr
		}
		_, rec, ok := resolveUsername(uf, username)
		if !ok || rec == nil {
			v.decrementActiveSessionCount(username)
			return fmt.Errorf("user not found")
		}
		if required || rec.MFAEnabled {
			// Enrollment only for first-time users who are not yet verified.
			if !rec.TOTPVerified {
				v.decrementActiveSessionCount(username)
				return fmt.Errorf("MFA setup required: please scan the QR code to enroll")
			}

			// Fail safe if WrappedMFASecret missing (admin must fix user record)
			hasWrapped := len(rec.WrappedMFASecret) > 0
			if !hasWrapped {
				v.decrementActiveSessionCount(username)
				return fmt.Errorf("MFA configuration error: missing authenticator secret; contact administrator")
			}

			// Decrypt wrapped secret (vault must be unlocked) and preserve briefly.
			if !v.Vault.IsUnlocked() {
				v.decrementActiveSessionCount(username)
				return fmt.Errorf("MFA required: vault must be unalocked to validate codes")
			}
			secret, uerr := unwrapMFAWithKey(v.Vault.encryptionKey, rec.WrappedMFASecret)
			if uerr != nil || secret == "" {
				v.decrementActiveSessionCount(username)
				return fmt.Errorf("failed to access MFA secret: %v", uerr)
			}
			v.pendingMu.Lock()
			v.pendingMFASecret = secret
			v.pendingMu.Unlock()
			v.decrementActiveSessionCount(username)
			return fmt.Errorf("MFA required: please enter your 6-digit authenticator code")
		}
		return nil
	}

	// Legacy single-user path (pre-existing vaults without a .users file)
	if err := v.authenticatePassword(username, password, ipAddress); err != nil {
		return err
	}
	if v.userProfile.MFAEnabled {
		v.userProfile = nil
		v.Vault.Lock()
		return fmt.Errorf("MFA required: please enter your 6-digit authenticator code")
	}
	if err := v.finalizeLogin(username, ipAddress); err != nil {
		return err
	}
	return nil
}

// LoginWithMFA authenticates with password and a TOTP code (RFC 6238).
func (v *VaultWithUser) LoginWithMFA(username, password, totpCode, ipAddress string) error {
	if v.UsersFileExists() {
		// Multi-user path: if a prior Login() call already unlocked the vault
		// and populated userProfile, skip calling loginMultiUser again to avoid
		// double-incrementing active sessions. Otherwise perform the full
		// authentication/unlock sequence.
		if !(v.Vault.IsUnlocked() && v.userProfile != nil && strings.EqualFold(v.userProfile.Username, username)) {
			if err := v.loginMultiUser(username, password, ipAddress); err != nil {
				return err
			}
		} else {
			// Check concurrent session limit (was missing in skipped path)
			if policy, pErr := v.GetSecurityPolicy(); pErr == nil && policy != nil && policy.MaxConcurrentSessions > 0 {
				uf, uErr := v.readUsersFile()
				if uErr == nil {
					_, rec, ok := resolveUsername(uf, username)
					if ok && rec != nil && rec.ActiveSessionCount >= policy.MaxConcurrentSessions {
						v.userProfile = nil
						_ = v.Vault.Lock()
						return fmt.Errorf("concurrent session limit reached (%d/%d active) — close an existing session and try again",
							rec.ActiveSessionCount, policy.MaxConcurrentSessions)
					}
				}
			}
			// Restore the session count since loginMultiUser was skipped
			v.incrementActiveSessionCount(username)
		}

		// Enforce MFA either when user has enabled it, or when the policy requires it.
		required, _ := v.CheckMFARequirement()
		uf, rerr := v.readUsersFile()
		if rerr != nil {
			return rerr
		}
		_, rec, ok := resolveUsername(uf, username)
		if !ok || rec == nil {
			return rerr
		}
		if required || rec.MFAEnabled {
			// Enrollment only for first-time / unverified users.
			if !rec.TOTPVerified {
				v.decrementActiveSessionCount(username)
				v.userProfile = nil
				v.Vault.Lock()
				return fmt.Errorf("MFA setup required: please scan the QR code to enroll")
			}

			// Fail safe if WrappedMFASecret missing (admin must fix user record)
			hasWrapped := len(rec.WrappedMFASecret) > 0
			if !hasWrapped {
				v.decrementActiveSessionCount(username)
				v.userProfile = nil
				v.Vault.Lock()
				return fmt.Errorf("MFA configuration error: missing authenticator secret; contact administrator")
			}

			if totpCode == "" {
				v.decrementActiveSessionCount(username)
				v.userProfile = nil
				v.Vault.Lock()
				return fmt.Errorf("MFA required: please enter your 6-digit authenticator code")
			}
			if !v.Vault.IsUnlocked() {
				v.decrementActiveSessionCount(username)
				v.userProfile = nil
				v.Vault.Lock()
				return fmt.Errorf("MFA required: vault must be unlocked to validate codes")
			}
			secret, uerr := unwrapMFAWithKey(v.Vault.encryptionKey, rec.WrappedMFASecret)
			if uerr != nil || secret == "" {
				v.decrementActiveSessionCount(username)
				v.auditLog.LogLogin(username, false, "invalid MFA setup", ipAddress)
				v.userProfile = nil
				v.Vault.Lock()
				return fmt.Errorf("invalid MFA configuration")
			}
			if !v.validateTOTPForUser(username, secret, totpCode) {
				v.decrementActiveSessionCount(username)
				v.auditLog.LogLogin(username, false, "invalid MFA code", ipAddress)
				v.recordMultiUserFailedAttempt(username)
				v.userProfile = nil
				v.Vault.Lock()
				return fmt.Errorf("invalid MFA code")
			}
		}
		// On success the caller will proceed; finalizeLogin will be invoked
		// by the higher-level flow once the interactive MFA step completes.
		if err := v.finalizeLogin(username, ipAddress); err != nil {
			return err
		}
		return nil
	}

	// Legacy path
	if err := v.authenticatePassword(username, password, ipAddress); err != nil {
		return err
	}
	if v.userProfile.MFAEnabled {
		// Legacy single-user MFA: only allow if a pending secret exists (generated during this session)
		v.pendingMu.Lock()
		secret := v.pendingMFASecret
		v.pendingMu.Unlock()
		if secret == "" {
			return fmt.Errorf("MFA required but secret unavailable; complete enrollment or use multi-user store")
		}
		if totpCode == "" {
			v.Vault.Lock()
			return fmt.Errorf("MFA required: please enter your 6-digit authenticator code")
		}
		if !v.validateTOTPForUser(username, secret, totpCode) {
			v.auditLog.LogLogin(username, false, "invalid MFA code", ipAddress)
			v.recordFailedAttempt()
			v.Vault.Lock()
			return fmt.Errorf("invalid MFA code")
		}
		// clear pending secret after use
		v.pendingMu.Lock()
		v.pendingMFASecret = ""
		v.pendingMu.Unlock()
	}
	if err := v.finalizeLogin(username, ipAddress); err != nil {
		return err
	}
	return nil
}

// Logout decrements the active-session counter for the current user, locks the vault,
// and clears the in-memory user profile.
// Requirement 3.6: Sessions shall be invalidated after logout.
func (v *VaultWithUser) Logout() error {
	if v.userProfile != nil {
		username := v.userProfile.Username
		v.decrementActiveSessionCount(username)
		v.auditLog.LogLogout(username)
		v.auditLog.LogAdminChange(username, "LOGOUT", "session", "user logged out")
	}
	v.userProfile = nil
	v.pendingMu.Lock()
	v.pendingMFASecret = ""
	v.pendingMu.Unlock()
	err := v.Vault.Lock()
	// Remove lockfile if present
	if v.lockFilePath != "" {
		_ = os.Remove(v.lockFilePath)
		v.lockFilePath = ""
	}
	return err
}

// IsMFARequired returns whether MFA is required for login
func (v *VaultWithUser) IsMFARequired() bool {
	return v.userProfile != nil && v.userProfile.MFAEnabled
}

// GetPendingMFASecret returns the decrypted TOTP secret preserved after a
// password verification step when the account requires MFA enrollment or
// verification. The secret is returned only once and cleared from memory to
// minimize exposure.
func (v *VaultWithUser) GetPendingMFASecret() (string, bool) {
	v.pendingMu.Lock()
	defer v.pendingMu.Unlock()
	if v.pendingMFASecret == "" {
		return "", false
	}
	s := v.pendingMFASecret
	v.pendingMFASecret = ""
	return s, true
}

// getUserLock returns a mutex for the given canonical username, creating it if necessary.
func (v *VaultWithUser) getUserLock(username string) *sync.Mutex {
	key := strings.ToLower(strings.TrimSpace(username))
	v.totpLocksMu.Lock()
	defer v.totpLocksMu.Unlock()
	m, ok := v.totpLocks[key]
	if !ok {
		m = &sync.Mutex{}
		v.totpLocks[key] = m
	}
	return m
}

// EnableMFA generates a new RFC 6238-compatible TOTP secret and stores it.
// The secret is base32-encoded and compatible with standard authenticator apps.
// MFA is not yet active until VerifyAndActivateMFA succeeds.
func (v *VaultWithUser) EnableMFA() (secret string, err error) {
	if !v.Vault.IsUnlocked() {
		return "", fmt.Errorf("vault is locked")
	}

	// Generate a base32 TOTP secret compatible with RFC 6238 authenticator apps
	secret, err = auth.GenerateMFASecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	// Preserve the generated secret only in pending state until verification.
	v.pendingMu.Lock()
	v.pendingMFASecret = secret
	v.pendingMu.Unlock()
	v.userProfile.TOTPVerified = false
	// Persist the enabled flag so UI knows enrollment is in progress.
	v.userProfile.MFAEnabled = true
	if err := v.saveUserProfile(); err != nil {
		return "", err
	}

	return secret, nil
}

// VerifyAndActivateMFA verifies TOTP code and activates MFA
func (v *VaultWithUser) VerifyAndActivateMFA(code string) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault is locked")
	}
	// Use the pending secret generated during EnableMFA; it must exist.
	v.pendingMu.Lock()
	secret := v.pendingMFASecret
	v.pendingMu.Unlock()
	if secret == "" {
		return fmt.Errorf("MFA not set up - call EnableMFA first")
	}
	if !auth.ValidateTOTP(secret, code) {
		return fmt.Errorf("invalid TOTP code")
	}

	// Mark verified in the in-memory profile first so saveUserProfile/FlushUserProfile
	// can wrap and persist the secret into the users file correctly.
	v.userProfile.MFAEnabled = true
	v.userProfile.TOTPVerified = true

	// saveUserProfile calls FlushUserProfile which wraps pendingMFASecret
	// and stores it in the users file as WrappedMFASecret — it must be called
	// BEFORE we clear pendingMFASecret.
	if err := v.saveUserProfile(); err != nil {
		return fmt.Errorf("failed to save MFA state: %w", err)
	}

	// Only clear the pending secret after it has been successfully persisted.
	v.pendingMu.Lock()
	v.pendingMFASecret = ""
	v.pendingMu.Unlock()

	v.auditLog.LogMFAChange(v.userProfile.Username, true)
	return nil
}

// DisableMFA disables MFA (requires password confirmation)
func (v *VaultWithUser) DisableMFA(password string) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault is locked")
	}

	// Verify password
	expectedHash := hashUserPassword(password, v.userProfile.PasswordSalt)
	if !secureCompare(expectedHash, v.userProfile.PasswordHash) {
		return fmt.Errorf("invalid password")
	}

	v.userProfile.MFAEnabled = false
	v.userProfile.TOTPVerified = false
	// Also remove any wrapped secret from persistent users file via Flush

	// Log MFA deactivation
	v.auditLog.LogMFAChange(v.userProfile.Username, false)

	return v.saveUserProfile()
}

// ChangePassword changes the user's personal password.
// In multi-user mode: updates users file only (no vault re-key, so other users are unaffected).
// In legacy single-user mode: also re-derives the vault encryption key.
func (v *VaultWithUser) ChangePassword(currentPassword, newPassword string) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault is locked")
	}

	if ok, errs := v.ValidatePasswordAgainstVaultPolicy(newPassword); !ok {
		v.auditLog.LogPasswordChange(v.userProfile.Username, false)
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	// Verify current password
	expectedHash := hashUserPassword(currentPassword, v.userProfile.PasswordSalt)
	if !secureCompare(expectedHash, v.userProfile.PasswordHash) {
		v.auditLog.LogPasswordChange(v.userProfile.Username, false)
		return fmt.Errorf("current password is incorrect")
	}

	newSalt := make([]byte, SaltLength)
	if _, err := rand.Read(newSalt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	if v.UsersFileExists() {
		// Multi-user path: update users file only, re-wrap vault keys
		uf, err := v.readUsersFile()
		if err != nil {
			return err
		}
		key, rec, ok := resolveUsername(uf, v.userProfile.Username)
		if !ok {
			return fmt.Errorf("user record not found")
		}

		// Check password reuse against current and historical entries
		// Compute against current stored salt
		newMatchesCurrent := secureCompare(hashUserPassword(newPassword, rec.PasswordSalt), rec.PasswordHash)
		if newMatchesCurrent {
			return fmt.Errorf("new password must not match current password")
		}
		// Check against history entries
		for _, he := range rec.PasswordHistory {
			if secureCompare(hashUserPassword(newPassword, he.Salt), he.Hash) {
				return fmt.Errorf("new password must not match recent passwords")
			}
		}

		wrapped, err := wrapVaultKeys(newPassword, v.Vault.encryptionKey, v.Vault.hmacKey)
		if err != nil {
			return fmt.Errorf("failed to re-wrap vault keys: %w", err)
		}

		// Before overwriting, append the previous password to history
		now := time.Now()
		prevEntry := PasswordHistoryEntry{
			Hash:      rec.PasswordHash,
			Salt:      rec.PasswordSalt,
			ChangedAt: now,
			Reason:    "password_change",
		}
		rec.PasswordHistory = append(rec.PasswordHistory, prevEntry)

		// Cap history to policy limit
		limit := 5
		if policy, pErr := v.GetSecurityPolicy(); pErr == nil && policy != nil && policy.PasswordHistoryCount > 0 {
			limit = policy.PasswordHistoryCount
		}
		if len(rec.PasswordHistory) > limit {
			// keep the most recent `limit` entries
			start := len(rec.PasswordHistory) - limit
			rec.PasswordHistory = rec.PasswordHistory[start:]
		}

		rec.PasswordHash = hashUserPassword(newPassword, newSalt)
		rec.PasswordSalt = newSalt
		rec.PasswordChangeAt = &now
		rec.WrappedVaultKeys = wrapped
		uf.Users[key] = rec
		if err := v.writeUsersFile(uf); err != nil {
			return err
		}
	} else {
		// Legacy path: re-key vault too
		if err := v.Vault.ChangeMasterPassword(currentPassword, newPassword); err != nil {
			v.auditLog.LogPasswordChange(v.userProfile.Username, false)
			return err
		}
	}

	v.userProfile.PasswordHash = hashUserPassword(newPassword, newSalt)
	v.userProfile.PasswordSalt = newSalt
	now := time.Now()
	v.userProfile.PasswordChangeAt = &now
	v.auditLog.SetHMACKey(v.Vault.hmacKey)
	v.auditLog.LogPasswordChange(v.userProfile.Username, true)
	if err := v.saveUserProfile(); err != nil {
		return err
	}

	// Invalidate session (Req 3.6)
	return v.Vault.Lock()
}

func (v *VaultWithUser) checkSecretPermission(permission string) error {
	if v.userProfile == nil {
		return fmt.Errorf("authentication required")
	}
	if !v.HasPermission(permission) {
		return fmt.Errorf("permission denied: missing %s", permission)
	}
	return nil
}

func (v *VaultWithUser) currentUsername() string {
	if v.userProfile == nil {
		return ""
	}
	return strings.TrimSpace(v.userProfile.Username)
}

func (v *VaultWithUser) isSecretOwner(secret *SecretData) bool {
	if secret == nil {
		return false
	}
	owner := strings.TrimSpace(secret.CreatedBy)
	if owner == "" {
		return false
	}
	return strings.EqualFold(owner, v.currentUsername())
}

// Legacy (unstamped) secrets are only readable/mutable by admins to prevent
// cross-user exposure in migrated vaults where CreatedBy is missing.
func (v *VaultWithUser) canAccessLegacySecret(secret *SecretData) bool {
	if secret == nil || strings.TrimSpace(secret.CreatedBy) != "" {
		return false
	}
	return v.userProfile != nil && v.HasPermission(auth.CanViewUsers)
}

func (v *VaultWithUser) hasSharedReadAccess(secretID string) bool {
	if v.userProfile == nil {
		return false
	}
	sm := NewSharedCredentialManager(v)
	return sm.CheckAccess(v.userProfile.Username, secretID, false, false) == nil
}

func (v *VaultWithUser) hasSharedMutationAccess(secretID string, needDelete bool) bool {
	if v.userProfile == nil {
		return false
	}
	sm := NewSharedCredentialManager(v)
	return sm.CheckAccess(v.userProfile.Username, secretID, true, needDelete) == nil
}

func (v *VaultWithUser) canReadSecret(secret *SecretData) bool {
	if secret == nil {
		return false
	}
	if secret.Category == "__SYSTEM__" {
		return false
	}
	if v.isSecretOwner(secret) {
		return true
	}
	if v.canAccessLegacySecret(secret) {
		return true
	}
	return v.hasSharedReadAccess(secret.ID)
}

func (v *VaultWithUser) canMutateSecret(secret *SecretData, needDelete bool) bool {
	if secret == nil {
		return false
	}
	if secret.Category == "__SYSTEM__" {
		return false
	}
	if v.isSecretOwner(secret) {
		if needDelete {
			return v.HasPermission(auth.CanDeleteSecret)
		}
		return v.HasPermission(auth.CanEditSecret)
	}
	if v.canAccessLegacySecret(secret) {
		if needDelete {
			return v.HasPermission(auth.CanDeleteSecret)
		}
		return v.HasPermission(auth.CanEditSecret)
	}
	return v.hasSharedMutationAccess(secret.ID, needDelete)
}

// AddSecret creates a secret and enforces RBAC checks in backend.
func (v *VaultWithUser) AddSecret(secret *SecretData) error {
	if secret == nil {
		return fmt.Errorf("secret is nil")
	}
	// Prevent unprivileged creation of internal/system entries which may
	// contain sensitive metadata (shares, settings, etc.). Only callers with
	// administrative rights should create `__SYSTEM__` entries.
	if secret.Category == "__SYSTEM__" {
		if err := v.checkSecretPermission(auth.CanManagePolicy); err != nil {
			return fmt.Errorf("permission denied: cannot create system entries")
		}
	} else {
		if err := v.checkSecretPermission(auth.CanCreateSecret); err != nil {
			return err
		}
		if v.userProfile != nil && secret.CreatedBy == "" {
			secret.CreatedBy = v.userProfile.Username
		}
	}
	return v.Vault.AddSecret(secret)
}

// UpdateSecret saves a modified secret and enforces the PasswordHistoryCount policy:
// the stored history slice is trimmed to the configured limit after every update.
func (v *VaultWithUser) UpdateSecret(secret *SecretData) error {
	if secret == nil {
		return fmt.Errorf("secret is nil")
	}
	// Validate existence and permissions before performing an atomic update.
	existing, err := v.Vault.getSecret(secret.ID)
	if err != nil {
		return err
	}
	if !v.canMutateSecret(existing, false) {
		return fmt.Errorf("permission denied: cannot update secret '%s'", secret.ID)
	}
	// Keep ownership immutable through update paths.
	secret.CreatedBy = existing.CreatedBy

	// If the password value changed, ensure caller has rotate permission.
	if existing.Password != secret.Password {
		if err := v.checkSecretPermission(auth.CanRotateSecret); err != nil {
			return err
		}
	}
	// Delegate to Vault.UpdateSecret which performs the atomic update, history
	// handling and persists the vault. This avoids duplicated logic and
	// double-saving from both layers.
	return v.Vault.UpdateSecret(secret)
}

// DeleteSecret removes a secret and enforces RBAC checks in backend.
func (v *VaultWithUser) DeleteSecret(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("secret ID is required")
	}
	secret, err := v.Vault.getSecret(id)
	if err != nil {
		return err
	}
	if !v.canMutateSecret(secret, true) {
		return fmt.Errorf("permission denied: cannot delete secret '%s'", id)
	}
	return v.Vault.DeleteSecret(id)
}

// ListSecrets returns secret metadata and enforces RBAC view checks in backend.
func (v *VaultWithUser) ListSecrets() ([]*SecretData, error) {
	if err := v.checkSecretPermission(auth.CanViewSecrets); err != nil {
		return nil, err
	}
	secrets, err := v.Vault.ListSecrets()
	if err != nil {
		return nil, err
	}
	filtered := make([]*SecretData, 0, len(secrets))
	for _, s := range secrets {
		if v.canReadSecret(s) {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

// SearchSecrets performs a search with RBAC view checks in backend.
func (v *VaultWithUser) SearchSecrets(query string, category string, tags []string) ([]*SecretData, error) {
	if err := v.checkSecretPermission(auth.CanViewSecrets); err != nil {
		return nil, err
	}
	secrets, err := v.Vault.SearchSecrets(query, category, tags)
	if err != nil {
		return nil, err
	}
	filtered := make([]*SecretData, 0, len(secrets))
	for _, s := range secrets {
		if v.canReadSecret(s) {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

// ExportVault enforces RBAC export checks in backend.
func (v *VaultWithUser) ExportVault(exportPath string) error {
	if err := v.checkSecretPermission(auth.CanExportData); err != nil {
		return err
	}
	return v.Vault.ExportVault(exportPath)
}

// ImportVault enforces RBAC import checks in backend.
func (v *VaultWithUser) ImportVault(importPath, importPassword string) (int, error) {
	if err := v.checkSecretPermission(auth.CanImportData); err != nil {
		return 0, err
	}
	return v.Vault.ImportVault(importPath, importPassword)
}

// GetUserProfile returns the current user profile (without sensitive data)
func (v *VaultWithUser) GetUserProfile() (*UserProfile, error) {
	if !v.Vault.IsUnlocked() {
		return nil, fmt.Errorf("vault is locked")
	}
	if v.userProfile == nil {
		return nil, fmt.Errorf("no user profile loaded")
	}

	// Return copy without sensitive data
	return &UserProfile{
		Username:         v.userProfile.Username,
		Email:            v.userProfile.Email,
		MFAEnabled:       v.userProfile.MFAEnabled,
		TOTPVerified:     v.userProfile.TOTPVerified,
		CreatedAt:        v.userProfile.CreatedAt,
		LastLogin:        v.userProfile.LastLogin,
		PasswordChangeAt: v.userProfile.PasswordChangeAt,
	}, nil
}

// UpdateEmail updates the user's email
func (v *VaultWithUser) UpdateEmail(email string) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault is locked")
	}

	v.userProfile.Email = email
	return v.saveUserProfile()
}

// GetAuditLog returns the audit log for this vault
func (v *VaultWithUser) GetAuditLog() *VaultAuditLog {
	return v.auditLog
}

// GetAuditEntries returns all audit entries (convenience method)
func (v *VaultWithUser) GetAuditEntries() []*VaultAuditEntry {
	return v.auditLog.GetAllEntries()
}

// ExportAuditLog exports the audit log in the specified format
func (v *VaultWithUser) ExportAuditLog(format string) (string, error) {
	if v.userProfile == nil {
		return "", fmt.Errorf("authentication required")
	}
	if err := v.requirePermission(v.userProfile.Username, auth.CanExportData); err != nil {
		return "", err
	}
	switch format {
	case "json":
		data, err := v.auditLog.ExportJSON()
		return string(data), err
	case "csv":
		return v.auditLog.ExportCSV(), nil
	case "cef":
		return v.auditLog.ExportCEF(), nil
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}

// ============================================
// AUDITED SECRET OPERATIONS
// ============================================

// AddSecretAudited adds a secret with audit logging
func (v *VaultWithUser) AddSecretAudited(secret *SecretData) error {
	// Stamp creator so per-user stats/filtering work correctly.
	username := v.currentUsername()
	if secret.CreatedBy == "" && username != "" {
		secret.CreatedBy = username
	}
	if err := v.AddSecret(secret); err != nil {
		return err
	}
	v.auditLog.LogSecretCreate(username, secret.ID, secret.Name)
	return nil
}

// GetSecretAudited retrieves a secret with audit logging
func (v *VaultWithUser) GetSecretAudited(id string) (*SecretData, error) {
	if err := v.checkSecretPermission(auth.CanViewSecrets); err != nil {
		return nil, err
	}
	secret, err := v.Vault.getSecret(id)
	if err != nil {
		return nil, err
	}
	if !v.canReadSecret(secret) {
		return nil, fmt.Errorf("permission denied: cannot access secret '%s'", id)
	}
	v.auditLog.LogSecretRead(v.currentUsername(), secret.ID, secret.Name)
	return secret, nil
}

// GetPasswordHistoryAudited returns the password history for a secret with access checks and audit logging.
func (v *VaultWithUser) GetPasswordHistoryAudited(id string) ([]PasswordHistoryEntry, error) {
	if err := v.checkSecretPermission(auth.CanViewSecrets); err != nil {
		return nil, err
	}
	secret, err := v.Vault.getSecret(id)
	if err != nil {
		return nil, err
	}
	if !v.canReadSecret(secret) {
		return nil, fmt.Errorf("permission denied: cannot access secret '%s'", id)
	}
	// Log the read of history as sensitive access
	v.auditLog.LogSecretRead(v.currentUsername(), secret.ID, secret.Name)
	history := make([]PasswordHistoryEntry, len(secret.PasswordHistory))
	copy(history, secret.PasswordHistory)
	return history, nil
}

// GetPasswordHistory enforces access checks and returns history (shadows Vault.GetPasswordHistory).
func (v *VaultWithUser) GetPasswordHistory(id string) ([]PasswordHistoryEntry, error) {
	return v.GetPasswordHistoryAudited(id)
}

// GetSecretByNameAudited retrieves a secret by name with audit logging
func (v *VaultWithUser) GetSecretByNameAudited(name string) (*SecretData, error) {
	if err := v.checkSecretPermission(auth.CanViewSecrets); err != nil {
		return nil, err
	}
	secrets, err := v.Vault.ListSecrets()
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets {
		if secret.Name == name && v.canReadSecret(secret) {
			v.auditLog.LogSecretRead(v.currentUsername(), secret.ID, secret.Name)
			return secret, nil
		}
	}
	return nil, fmt.Errorf("secret with name %s not found", name)
}

// UpdateSecretAudited updates a secret with audit logging
func (v *VaultWithUser) UpdateSecretAudited(secret *SecretData) error {
	if err := v.UpdateSecret(secret); err != nil {
		return err
	}
	v.auditLog.LogSecretUpdate(v.currentUsername(), secret.ID, secret.Name, "details")
	return nil
}

// DeleteSecretAudited removes a secret with audit logging
func (v *VaultWithUser) DeleteSecretAudited(id string) error {
	// Get secret name before deletion for logging
	secret, err := v.GetSecretAudited(id)
	secretName := ""
	if err == nil {
		secretName = secret.Name
	}

	if err := v.DeleteSecret(id); err != nil {
		return err
	}
	v.auditLog.LogSecretDelete(v.currentUsername(), id, secretName)
	return nil
}

// ListSecretsAudited lists all secrets (logging bulk access)
func (v *VaultWithUser) ListSecretsAudited() ([]*SecretData, error) {
	secrets, err := v.ListSecrets()
	if err != nil {
		return nil, err
	}
	// Log bulk listing as a single event
	v.auditLog.LogEvent(v.currentUsername(), AuditEventSecretRead, AuditCategorySecret,
		fmt.Sprintf("Listed %d secrets", len(secrets)), AuditResultSuccess)
	return secrets, nil
}

// ExportVaultAudited exports the vault with audit logging
func (v *VaultWithUser) ExportVaultAudited(exportPath string) error {
	if err := v.ExportVault(exportPath); err != nil {
		v.auditLog.LogVaultOperation(v.currentUsername(), AuditEventVaultExport, "Export failed", false)
		return err
	}
	v.auditLog.LogVaultOperation(v.currentUsername(), AuditEventVaultExport, "Vault exported to "+exportPath, true)
	return nil
}

// ImportVaultAudited imports from another vault with audit logging
func (v *VaultWithUser) ImportVaultAudited(importPath, importPassword string) (int, error) {
	count, err := v.ImportVault(importPath, importPassword)
	if err != nil {
		v.auditLog.LogVaultOperation(v.currentUsername(), AuditEventVaultImport, "Import failed", false)
		return 0, err
	}
	v.auditLog.LogVaultOperation(v.currentUsername(), AuditEventVaultImport,
		fmt.Sprintf("Imported %d secrets from %s", count, importPath), true)
	return count, nil
}

// ============================================
// INTERNAL FUNCTIONS
// ============================================

// UserProfileSecretID is the special ID for user profile entry
const UserProfileSecretID = "__USER_PROFILE__"

// saveUserProfile saves user profile as a special vault entry AND syncs to users file.
func (v *VaultWithUser) saveUserProfile() error {
	// Serialize a safe view of the user profile (do NOT include secrets or hashes)
	safe := struct {
		Username         string     `json:"username"`
		Email            string     `json:"email,omitempty"`
		Role             string     `json:"role"`
		MFAEnabled       bool       `json:"mfa_enabled"`
		TOTPVerified     bool       `json:"totp_verified"`
		CreatedAt        time.Time  `json:"created_at"`
		LastLogin        time.Time  `json:"last_login,omitempty"`
		PasswordChangeAt *time.Time `json:"password_change_at,omitempty"`
	}{
		Username:         v.userProfile.Username,
		Email:            v.userProfile.Email,
		Role:             v.userProfile.Role,
		MFAEnabled:       v.userProfile.MFAEnabled,
		TOTPVerified:     v.userProfile.TOTPVerified,
		CreatedAt:        v.userProfile.CreatedAt,
		LastLogin:        v.userProfile.LastLogin,
		PasswordChangeAt: v.userProfile.PasswordChangeAt,
	}

	// Serialize safe view
	profileData := &SecretData{
		ID:       UserProfileSecretID,
		Name:     "__USER_PROFILE__",
		Category: "__SYSTEM__",
		Notes:    string(mustMarshalJSON(safe)),
	}

	if _, err := v.Vault.getSecret(UserProfileSecretID); err == nil {
		if err := v.Vault.UpdateSecret(profileData); err != nil {
			return err
		}
	} else {
		if err := v.Vault.AddSecret(profileData); err != nil {
			return err
		}
	}

	// Also sync to users file so multi-user login reflects MFA / lockout changes
	if err := v.FlushUserProfile(); err != nil {
		return fmt.Errorf("failed to flush user profile to users file: %w", err)
	}
	return nil
}

// loadUserProfile loads user profile from vault
func (v *VaultWithUser) loadUserProfile() error {
	v.Vault.mu.RLock()
	defer v.Vault.mu.RUnlock()

	profileEntry, exists := v.Vault.entries[UserProfileSecretID]
	if !exists {
		return fmt.Errorf("user profile not found in vault")
	}

	var profile UserProfile
	if err := mustUnmarshalJSON([]byte(profileEntry.Notes), &profile); err != nil {
		return fmt.Errorf("failed to parse user profile: %w", err)
	}

	v.userProfile = &profile
	return nil
}

// recordFailedAttempt records a failed login attempt (legacy single-user path)
func (v *VaultWithUser) recordFailedAttempt() {
	if v.userProfile == nil {
		return
	}

	v.userProfile.FailedAttempts++

	// Get lockout settings from persisted policy
	maxAttempts, lockoutDuration := v.GetLockoutSettings()

	// Lock account after max failed attempts
	if v.userProfile.FailedAttempts >= maxAttempts {
		lockoutTime := time.Now().Add(lockoutDuration)
		v.userProfile.LockoutUntil = &lockoutTime
	}

	if err := v.saveUserProfile(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to persist user profile after failed attempt: %v\n", err)
	}

	// Record failed attempt in persistent storage
	v.RecordLoginAttempt(false)
}

// recordMultiUserFailedAttempt increments the failed-attempt counter in the users file.
func (v *VaultWithUser) recordMultiUserFailedAttempt(username string) {
	uf, err := v.readUsersFile()
	if err != nil {
		return
	}
	key, rec, ok := resolveUsername(uf, username)
	if !ok {
		return
	}
	// Protect per-user updates with a per-user lock to avoid races when
	// multiple concurrent login attempts update counters.
	m := v.getUserLock(key)
	m.Lock()
	defer m.Unlock()
	rec.FailedAttempts++
	maxAttempts, lockoutDuration := v.GetLockoutSettings()
	if rec.FailedAttempts >= maxAttempts {
		until := time.Now().Add(lockoutDuration)
		rec.LockoutUntil = &until
	}
	uf.Users[key] = rec
	_ = v.writeUsersFile(uf)
}

// hashUserPassword hashes password using Argon2id
func hashUserPassword(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)
}

// validatePasswordStrength checks password complexity
func validatePasswordStrength(password string) error {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

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

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// validateTOTPForUser validates a TOTP code for a given username and persists
// the last-used counter to protect against replay across restarts.
func (v *VaultWithUser) validateTOTPForUser(username, secret, code string) bool {
	if secret == "" || username == "" {
		return false
	}

	// Normalize input similarly to auth.ValidateTOTP
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	secret = strings.ToUpper(strings.TrimSpace(secret))

	cfg := auth.DefaultMFAConfig()
	now := time.Now()
	counterNow := uint64(now.Unix() / int64(cfg.Period))

	// Use a per-user lock to avoid races on the stored last counter.
	m := v.getUserLock(username)
	m.Lock()
	defer m.Unlock()

	// Load user's persisted last counter and check/update atomically.
	uf, err := v.readUsersFile()
	if err != nil {
		return false
	}
	key, rec, ok := resolveUsername(uf, username)
	var last uint64
	if ok {
		last = rec.LastTOTPCounter
	}

	for i := -cfg.Skew; i <= cfg.Skew; i++ {
		if i < 0 && uint64(-i) > counterNow {
			continue // underflow guard
		}
		candidate := counterNow + uint64(i)
		t := time.Unix(int64(candidate*uint64(cfg.Period)), 0)
		expected, gerr := auth.GenerateTOTP(secret, t)
		if gerr != nil {
			continue
		}
		if code != expected {
			continue
		}

		// Check replay: must be greater than stored counter (skip first use when last==0)
		if last > 0 && candidate <= last {
			return false
		}

		// Persist new last counter
		if ok {
			rec.LastTOTPCounter = candidate
			uf.Users[key] = rec
			_ = v.writeUsersFile(uf)
		}
		return true
	}

	return false
}

// secureCompare performs constant-time comparison
func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// mustMarshalJSON marshals to JSON (panics on error)
func mustMarshalJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// mustUnmarshalJSON unmarshals from JSON
func mustUnmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
