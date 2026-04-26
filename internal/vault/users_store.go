// Package vault – multi-user store
// Each vault has a companion file <vault>.users that holds all user records.
// User records contain an argon2id password hash and the vault's enc+hmac keys
// wrapped (AES-256-GCM) with the user's personal password.  This lets every
// user unlock the same shared vault with their own password, while the vault
// file itself stays encrypted with a single key pair.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"password-manager/internal/auth"
	"password-manager/internal/models"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// UserRecord is one entry in the users file.
type UserRecord struct {
	Username           string                 `json:"username"`
	PasswordHash       []byte                 `json:"password_hash"`
	PasswordSalt       []byte                 `json:"password_salt"`
	Email              string                 `json:"email,omitempty"`
	Role               string                 `json:"role"`
	WrappedVaultKeys   []byte                 `json:"wrapped_vault_keys"`           // enc||hmac wrapped with user's pw
	WrappedMFASecret   []byte                 `json:"wrapped_mfa_secret,omitempty"` // TOTP seed AES-256-GCM with vault key
	MFASecret          []byte                 `json:"mfa_secret,omitempty"`         // plaintext TOTP seed, only during pre-vault registration
	MFAEnabled         bool                   `json:"mfa_enabled"`
	TOTPVerified       bool                   `json:"totp_verified"`
	FailedAttempts     int                    `json:"failed_attempts"`
	LockoutUntil       *time.Time             `json:"lockout_until,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	LastLogin          time.Time              `json:"last_login,omitempty"`
	PasswordChangeAt   *time.Time             `json:"password_change_at,omitempty"`
	IsRevoked          bool                   `json:"is_revoked"`
	ActiveSessionCount int                    `json:"active_session_count"` // Requirement 3.6: concurrent session tracking
	PasswordHistory    []PasswordHistoryEntry `json:"password_history,omitempty"`
	LastTOTPCounter    uint64                 `json:"last_totp_counter,omitempty"`
}

// usersFile is the on-disk format.
type usersFile struct {
	Users map[string]*UserRecord `json:"users"` // key = username
}

// ────────────────────────────────────────────────────────────
// Key-wrapping helpers
// ────────────────────────────────────────────────────────────

// wrapVaultKeys encrypts the 64-byte (enc||hmac) vault key pair with the
// user's personal password.  Format: [32-byte salt][12-byte nonce][ciphertext].
func wrapVaultKeys(userPassword string, encKey, hmacKey []byte) ([]byte, error) {
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("wrapVaultKeys: salt: %w", err)
	}

	wrapKey := argon2.IDKey([]byte(userPassword), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("wrapVaultKeys: nonce: %w", err)
	}

	plaintext := append(encKey, hmacKey...) // 64 bytes
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return append(salt, ciphertext...), nil
}

// unwrapVaultKeys reverses wrapVaultKeys.
func unwrapVaultKeys(userPassword string, wrapped []byte) (encKey, hmacKey []byte, err error) {
	if len(wrapped) < SaltLength+1 {
		return nil, nil, fmt.Errorf("invalid wrapped key blob")
	}

	salt := wrapped[:SaltLength]
	rest := wrapped[SaltLength:]

	wrapKey := argon2.IDKey([]byte(userPassword), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	block, err2 := aes.NewCipher(wrapKey)
	if err2 != nil {
		return nil, nil, err2
	}
	gcm, err2 := cipher.NewGCM(block)
	if err2 != nil {
		return nil, nil, err2
	}

	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return nil, nil, fmt.Errorf("wrapped key blob too short")
	}
	nonce, ct := rest[:nonceSize], rest[nonceSize:]

	plaintext, err2 := gcm.Open(nil, nonce, ct, nil)
	if err2 != nil {
		return nil, nil, fmt.Errorf("invalid password or corrupted key")
	}

	if len(plaintext) != 64 {
		return nil, nil, fmt.Errorf("unexpected unwrapped key length %d", len(plaintext))
	}

	return plaintext[:32], plaintext[32:], nil
}

// ────────────────────────────────────────────────────────────
// MFA secret encryption helpers (Req 3.3 – keys not in plaintext)
// ────────────────────────────────────────────────────────────

// wrapMFAWithPassword derives a key from the user's password+salt via Argon2id
// and encrypts the TOTP secret with AES-256-GCM.
// Format: [32-byte salt][12-byte nonce][ciphertext+tag].
// Used pre-vault (before first login creates the vault key).
func wrapMFAWithPassword(password, secret string) ([]byte, error) {
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return append(salt, ct...), nil
}

// unwrapMFAWithPassword reverses wrapMFAWithPassword.
func unwrapMFAWithPassword(password string, data []byte) (string, error) {
	if len(data) < SaltLength+1 {
		return "", fmt.Errorf("wrapped MFA data too short")
	}
	salt := data[:SaltLength]
	rest := data[SaltLength:]
	key := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns {
		return "", fmt.Errorf("wrapped MFA data too short for nonce")
	}
	plain, err := gcm.Open(nil, rest[:ns], rest[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt MFA secret with password key")
	}
	return string(plain), nil
}

// wrapMFAWithKey encrypts a TOTP secret string using a 32-byte AES-256-GCM key.
// Format on disk: [12-byte nonce][ciphertext+tag].
func wrapMFAWithKey(key []byte, secret string) ([]byte, error) {
	if secret == "" || len(key) != 32 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(secret), nil), nil
}

// unwrapMFAWithKey decrypts a WrappedMFASecret blob back to the plain TOTP string.
func unwrapMFAWithKey(key []byte, wrapped []byte) (string, error) {
	if len(wrapped) == 0 || len(key) != 32 {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return "", fmt.Errorf("wrapped MFA secret too short")
	}
	plain, err := gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt MFA secret: %w", err)
	}
	return string(plain), nil
}

// ────────────────────────────────────────────────────────────
// UsersStore – attached to VaultWithUser
// ────────────────────────────────────────────────────────────

func (v *VaultWithUser) usersFilePath() string {
	return v.Vault.filePath + ".users"
}

// resolveUsername looks up a username in the usersFile and returns the map key,
// the corresponding UserRecord and whether it was found. The lookup is
// case-insensitive and returns the canonical stored key when available.
func resolveUsername(uf *usersFile, username string) (string, *UserRecord, bool) {
	if uf == nil || username == "" {
		return "", nil, false
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", nil, false
	}

	// Direct key match first (fast path)
	if rec, ok := uf.Users[username]; ok {
		return username, rec, true
	}

	// Case-insensitive search for canonical key
	lower := strings.ToLower(username)
	for k, rec := range uf.Users {
		if strings.ToLower(strings.TrimSpace(k)) == lower {
			return k, rec, true
		}
	}
	return "", nil, false
}

func (v *VaultWithUser) readUsersFile() (*usersFile, error) {
	path := v.usersFilePath()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) || len(raw) == 0 {
		return &usersFile{Users: make(map[string]*UserRecord)}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("readUsersFile: %w", err)
	}

	var data []byte
	if len(raw) >= len(usersMagic) && string(raw[:len(usersMagic)]) == usersMagic {
		// Encrypted format — decrypt using the embedded app key.
		data, err = v.Vault.decryptAppData(raw[len(usersMagic):])
		if err != nil {
			return nil, fmt.Errorf("readUsersFile decrypt: %w", err)
		}
	} else if len(raw) > 0 && raw[0] == '{' {
		// Legacy plain JSON — accepted, will be encrypted on next write.
		data = raw
	} else {
		return nil, fmt.Errorf("readUsersFile: unrecognised file format")
	}

	var uf usersFile
	if err := json.Unmarshal(data, &uf); err != nil {
		return nil, fmt.Errorf("readUsersFile parse: %w", err)
	}
	if uf.Users == nil {
		uf.Users = make(map[string]*UserRecord)
	}
	return &uf, nil
}

func (v *VaultWithUser) writeUsersFile(uf *usersFile) error {
	data, err := json.Marshal(uf)
	if err != nil {
		return fmt.Errorf("writeUsersFile marshal: %w", err)
	}
	enc, err := v.Vault.encryptAppData(data)
	if err != nil {
		return fmt.Errorf("writeUsersFile encrypt: %w", err)
	}
	out := append([]byte(usersMagic), enc...)
	// Write atomically: write to temp file in same dir and rename.
	path := v.usersFilePath()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "users-*.tmp")
	if err != nil {
		return fmt.Errorf("writeUsersFile temp create: %w", err)
	}
	tmpPath := tmp.Name()
	// Ensure cleanup on error
	defer func() {
		tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(out); err != nil {
		return fmt.Errorf("writeUsersFile write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("writeUsersFile sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writeUsersFile close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("writeUsersFile rename: %w", err)
	}
	return nil
}

// userRecordToProfile converts a UserRecord to the in-memory UserProfile.
// MFA fields come from the record directly (stored there, not in vault).
func userRecordToProfile(r *UserRecord) *UserProfile {
	return &UserProfile{
		Username:         r.Username,
		PasswordHash:     r.PasswordHash,
		PasswordSalt:     r.PasswordSalt,
		Email:            r.Email,
		Role:             r.Role,
		MFAEnabled:       r.MFAEnabled,
		TOTPVerified:     r.TOTPVerified,
		FailedAttempts:   r.FailedAttempts,
		LockoutUntil:     r.LockoutUntil,
		CreatedAt:        r.CreatedAt,
		LastLogin:        r.LastLogin,
		PasswordChangeAt: r.PasswordChangeAt,
	}
}

// profileToRecord copies mutable fields from in-memory UserProfile back to UserRecord.
func profileToRecord(r *UserRecord, p *UserProfile) {
	r.Email = p.Email
	r.Role = p.Role
	r.FailedAttempts = p.FailedAttempts
	r.LockoutUntil = p.LockoutUntil
	r.LastLogin = p.LastLogin
	r.PasswordChangeAt = p.PasswordChangeAt
	r.MFAEnabled = p.MFAEnabled
	// NOTE: MFASecret is NOT written back as plaintext here.
	// WrappedMFASecret is managed by FlushUserProfile using the vault key.
	r.TOTPVerified = p.TOTPVerified
}

func isSupportedRole(role string) bool {
	switch role {
	case models.RoleAdministrator, models.RoleSecurityOfficer, models.RoleStandardUser, models.RoleReadOnly:
		return true
	default:
		return false
	}
}

func (v *VaultWithUser) requirePermission(byUsername, permission string) error {
	if v.userProfile == nil {
		return fmt.Errorf("authentication required")
	}
	if byUsername != "" && !strings.EqualFold(v.userProfile.Username, byUsername) {
		return fmt.Errorf("permission denied: actor mismatch")
	}
	if !v.HasPermission(permission) {
		return fmt.Errorf("permission denied: missing %s", permission)
	}
	return nil
}

// ────────────────────────────────────────────────────────────
// Public API used by login / register / admin flows
// ────────────────────────────────────────────────────────────

// resetSessionCounts zeroes every user's ActiveSessionCount in the users file.
// Called at process startup so stale counters from crashes/kills don't block logins.
func (v *VaultWithUser) resetSessionCounts() {
	uf, err := v.readUsersFile()
	if err != nil {
		return // file doesn't exist yet (first run) — nothing to reset
	}
	changed := false
	for name, rec := range uf.Users {
		if rec.ActiveSessionCount != 0 {
			rec.ActiveSessionCount = 0
			uf.Users[name] = rec
			changed = true
		}
	}
	if changed {
		_ = v.writeUsersFile(uf)
	}
}

func (v *VaultWithUser) decrementActiveSessionCount(username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	uf, err := v.readUsersFile()
	if err != nil {
		return
	}
	key, rec, ok := resolveUsername(uf, username)
	if !ok || rec.ActiveSessionCount <= 0 {
		return
	}
	rec.ActiveSessionCount--
	uf.Users[key] = rec
	_ = v.writeUsersFile(uf)
}

func (v *VaultWithUser) incrementActiveSessionCount(username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	uf, err := v.readUsersFile()
	if err != nil {
		return
	}
	key, rec, ok := resolveUsername(uf, username)
	if !ok {
		return
	}
	rec.ActiveSessionCount++
	uf.Users[key] = rec
	_ = v.writeUsersFile(uf)
}

// UsersFileExists reports whether the companion users file exists.
func (v *VaultWithUser) UsersFileExists() bool {
	_, err := os.Stat(v.usersFilePath())
	return err == nil
}

// saveAdminToUsersFile is called during SetupNewVault to persist the first
// (admin) user.  The vault must already be unlocked so we can read its keys.
func (v *VaultWithUser) saveAdminToUsersFile(username, password, email string) error {
	wrapped, err := wrapVaultKeys(password, v.Vault.encryptionKey, v.Vault.hmacKey)
	if err != nil {
		return err
	}

	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	now := time.Now()
	rec := &UserRecord{
		Username:         username,
		PasswordHash:     hashUserPassword(password, salt),
		PasswordSalt:     salt,
		Email:            email,
		Role:             models.RoleAdministrator,
		WrappedVaultKeys: wrapped,
		CreatedAt:        now,
		PasswordChangeAt: &now,
	}

	uf := &usersFile{Users: map[string]*UserRecord{username: rec}}
	return v.writeUsersFile(uf)
}

// RegisterFirstAdmin creates the initial admin user record in the users file.
// It does NOT create or unlock the vault — vault creation is deferred to first login.
// Call this only when no users file exists yet (brand-new installation).
// RegisterFirstAdmin creates the initial admin user record in the users file and
// generates a TOTP secret ready for QR enrollment. MFA is NOT yet active —
// the caller must display the QR and call ActivateFirstAdminMFA once verified.
// Vault creation is deferred to first login.
func (v *VaultWithUser) RegisterFirstAdmin(username, password, email string) (totpSecret string, err error) {
	if v.UsersFileExists() {
		return "", fmt.Errorf("users already registered; use login instead")
	}
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return "", fmt.Errorf("username must be at least 3 characters")
	}
	if ok, errs := v.ValidatePasswordAgainstVaultPolicy(password); !ok {
		return "", fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	secret, err := auth.GenerateMFASecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	// Wrap the TOTP secret with a password-derived key immediately so it is
	// never stored in plaintext on disk. It stays password-wrapped until the
	// first login creates the vault, at which point loginMultiUser re-wraps it
	// with the vault encryption key.
	wrappedMFA, err := wrapMFAWithPassword(password, secret)
	if err != nil {
		return "", fmt.Errorf("failed to wrap MFA secret: %w", err)
	}
	now := time.Now()
	rec := &UserRecord{
		Username:         username,
		PasswordHash:     hashUserPassword(password, salt),
		PasswordSalt:     salt,
		Email:            email,
		Role:             models.RoleAdministrator,
		MFAEnabled:       false, // activated after QR verification
		WrappedMFASecret: wrappedMFA,
		// WrappedVaultKeys left empty — vault is created on first login
		CreatedAt:        now,
		PasswordChangeAt: &now,
	}
	uf := &usersFile{Users: map[string]*UserRecord{username: rec}}
	if err := v.writeUsersFile(uf); err != nil {
		return "", err
	}
	return secret, nil
}

// ActivateFirstAdminMFA verifies the TOTP code entered during registration and
// marks MFA as enabled in the users file. No vault unlock needed.
// password is required to unwrap the pre-vault MFA secret (wrapped in RegisterFirstAdmin).
func (v *VaultWithUser) ActivateFirstAdminMFA(username, password, code string) error {
	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	key, rec, ok := resolveUsername(uf, username)
	if !ok {
		return fmt.Errorf("user not found")
	}
	var secret string
	if len(rec.WrappedMFASecret) > 0 {
		// Try password-derived key first (new pre-vault path from RegisterFirstAdmin).
		if password != "" {
			if s, uErr := unwrapMFAWithPassword(password, rec.WrappedMFASecret); uErr == nil && s != "" {
				secret = s
			}
		}
		// Fallback: vault-key-wrapped (vault already unlocked).
		if secret == "" && v.Vault.IsUnlocked() && len(v.Vault.encryptionKey) > 0 {
			if s, uErr := unwrapMFAWithKey(v.Vault.encryptionKey, rec.WrappedMFASecret); uErr == nil {
				secret = s
			}
		}
		if secret == "" {
			return fmt.Errorf("failed to decrypt MFA secret")
		}
	} else if len(rec.MFASecret) > 0 {
		// Legacy path: plaintext secret left from an older build.
		secret = string(rec.MFASecret)
	} else {
		return fmt.Errorf("MFA secret is missing for user")
	}
	if !v.validateTOTPForUser(key, secret, code) {
		return fmt.Errorf("incorrect code — check your authenticator app and try again")
	}
	rec.MFAEnabled = true
	rec.TOTPVerified = true
	uf.Users[key] = rec
	return v.writeUsersFile(uf)
}

// RegisterUser adds a new user to the vault.
// The caller must be logged in (vault unlocked) so the vault keys can be wrapped.
// Only Administrators may set the Security Officer or Administrator roles;
// self-registrants (via the Register screen supplying the vault master password)
// are limited to Standard User or Security Officer (not Admin).
func (v *VaultWithUser) RegisterUser(username, password, email, role string) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault must be unlocked to register a user")
	}
	if !isSupportedRole(role) {
		return fmt.Errorf("invalid role: %s", role)
	}

	if v.userProfile != nil {
		if !v.HasPermission(auth.CanCreateUser) {
			return fmt.Errorf("permission denied: missing %s", auth.CanCreateUser)
		}
	} else {
		// Registration path authenticated by vault access password only.
		// Restrict this path to least-privilege roles.
		if role != models.RoleReadOnly {
			return fmt.Errorf("self-registration is restricted to role %s", models.RoleReadOnly)
		}
	}

	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}
	if ok, errs := v.ValidatePasswordAgainstVaultPolicy(password); !ok {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	lowerName := strings.ToLower(username)
	for k := range uf.Users {
		if strings.ToLower(k) == lowerName {
			return fmt.Errorf("username '%s' is already taken", username)
		}
	}

	wrapped, err := wrapVaultKeys(password, v.Vault.encryptionKey, v.Vault.hmacKey)
	if err != nil {
		return fmt.Errorf("failed to wrap vault keys: %w", err)
	}

	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	now := time.Now()
	rec := &UserRecord{
		Username:         username,
		PasswordHash:     hashUserPassword(password, salt),
		PasswordSalt:     salt,
		Email:            email,
		Role:             role,
		WrappedVaultKeys: wrapped,
		CreatedAt:        now,
		PasswordChangeAt: &now,
	}

	uf.Users[username] = rec
	if err := v.writeUsersFile(uf); err != nil {
		return err
	}

	v.auditLog.LogAdminChange(
		func() string {
			if v.userProfile != nil {
				return v.userProfile.Username
			}
			return "system"
		}(),
		"USER_REGISTER", username,
		fmt.Sprintf("New user registered with role %s", role),
	)
	return nil
}

// SetupMFAForNewUser generates a TOTP secret for a just-registered user,
// wraps it with the vault encryption key, and stores it in the users file.
// The vault must be unlocked. Returns the plain secret for QR display.
func (v *VaultWithUser) SetupMFAForNewUser(username string) (string, error) {
	if !v.Vault.IsUnlocked() {
		return "", fmt.Errorf("vault must be unlocked")
	}
	secret, err := auth.GenerateMFASecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	uf, err := v.readUsersFile()
	if err != nil {
		return "", err
	}
	key, rec, ok := resolveUsername(uf, username)
	if !ok {
		return "", fmt.Errorf("user not found: %s", username)
	}

	wrapped, err := wrapMFAWithKey(v.Vault.encryptionKey, secret)
	if err != nil {
		return "", fmt.Errorf("failed to wrap MFA secret: %w", err)
	}

	rec.WrappedMFASecret = wrapped
	rec.MFAEnabled = false // activated only after QR verification
	uf.Users[key] = rec
	if err := v.writeUsersFile(uf); err != nil {
		return "", err
	}
	return secret, nil
}

// ActivateNewUserMFA verifies a TOTP code for a freshly-registered user and
// marks their MFA as enabled. The vault must be unlocked.
func (v *VaultWithUser) ActivateNewUserMFA(username, code string) error {
	if !v.Vault.IsUnlocked() {
		return fmt.Errorf("vault must be unlocked")
	}
	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	key, rec, ok := resolveUsername(uf, username)
	if !ok {
		return fmt.Errorf("user not found: %s", username)
	}

	secret, err := unwrapMFAWithKey(v.Vault.encryptionKey, rec.WrappedMFASecret)
	if err != nil || secret == "" {
		return fmt.Errorf("MFA not set up for this user — call SetupMFAForNewUser first")
	}
	if !v.validateTOTPForUser(key, secret, code) {
		return fmt.Errorf("incorrect code — check your authenticator app and try again")
	}

	rec.MFAEnabled = true
	rec.TOTPVerified = true
	uf.Users[key] = rec
	return v.writeUsersFile(uf)
}

// loginMultiUser authenticates a user from the users file, unwraps the vault
// keys, and unlocks the vault. It is unexported to avoid bypassing MFA; callers
// should use the exported Login/LoginWithMFA helpers which enforce MFA when required.
func (v *VaultWithUser) loginMultiUser(username, password, ipAddress string) error {
	uf, err := v.readUsersFile()
	if err != nil {
		return fmt.Errorf("failed to read user store: %w", err)
	}

	key, rec, ok := resolveUsername(uf, username)
	if !ok {
		return ErrUserNotFound
	}
	username = key

	// Lockout check (before expensive Argon2 work)
	if rec.LockoutUntil != nil && time.Now().Before(*rec.LockoutUntil) {
		return fmt.Errorf("account locked until %s", rec.LockoutUntil.Format("2006-01-02 15:04:05"))
	}
	if rec.IsRevoked {
		return fmt.Errorf("account has been revoked")
	}

	// Verify password
	expected := hashUserPassword(password, rec.PasswordSalt)
	if !secureCompare(expected, rec.PasswordHash) {
		rec.FailedAttempts++
		maxAttempts, lockoutDuration := v.GetLockoutSettings()
		if rec.FailedAttempts >= maxAttempts {
			until := time.Now().Add(lockoutDuration)
			rec.LockoutUntil = &until
		}
		uf.Users[username] = rec
		_ = v.writeUsersFile(uf)
		v.auditLog.LogLogin(username, false, "invalid credentials", ipAddress)
		return ErrInvalidPassword
	}

	// First-ever login: vault hasn't been created yet — create it now and wrap keys.
	if len(rec.WrappedVaultKeys) == 0 {
		_ = os.Remove(v.Vault.GetFilePath()) // remove any stale file
		if err := v.Vault.Create(password); err != nil {
			v.auditLog.LogLogin(username, false, "vault creation failed", ipAddress)
			return fmt.Errorf("failed to create vault: %w", err)
		}
		wrapped, wrapErr := wrapVaultKeys(password, v.Vault.encryptionKey, v.Vault.hmacKey)
		if wrapErr != nil {
			_ = v.Vault.Lock()
			return fmt.Errorf("failed to wrap vault keys: %w", wrapErr)
		}
		rec.WrappedVaultKeys = wrapped
		// On first login, upgrade the MFA secret to vault-key wrapping.
		// New path: WrappedMFASecret holds a password-wrapped blob from RegisterFirstAdmin.
		// Legacy path: MFASecret holds plaintext (from older builds).
		if len(rec.WrappedMFASecret) > 0 && len(rec.MFASecret) == 0 {
			if plain, uErr := unwrapMFAWithPassword(password, rec.WrappedMFASecret); uErr == nil && plain != "" {
				if wm, wErr := wrapMFAWithKey(v.Vault.encryptionKey, plain); wErr == nil && wm != nil {
					rec.WrappedMFASecret = wm
				}
			}
		} else if len(rec.MFASecret) > 0 {
			// Legacy plaintext path.
			if wm, wErr := wrapMFAWithKey(v.Vault.encryptionKey, string(rec.MFASecret)); wErr == nil && wm != nil {
				rec.WrappedMFASecret = wm
			}
			rec.MFASecret = nil
		}
		rec.FailedAttempts = 0
		rec.LockoutUntil = nil
		now2 := time.Now()
		rec.LastLogin = now2
		rec.ActiveSessionCount++ // Requirement 3.6: track session on first login
		uf.Users[username] = rec
		_ = v.writeUsersFile(uf)
		v.auditLog.SetHMACKey(v.Vault.hmacKey)
		v.auditLog.LogVaultOperation(username, AuditEventVaultCreate, "Vault created on first login", true)
		v.userProfile = userRecordToProfile(rec)
		v.userProfile.LastLogin = now2
		v.RecordLoginAttempt(true)
		v.auditLog.LogLogin(username, true, "first login - vault created", ipAddress)
		v.ApplyStoredRolePermissions()
		return nil
	}

	// Unwrap vault keys and unlock
	encKey, hmacKey, err := unwrapVaultKeys(password, rec.WrappedVaultKeys)
	if err != nil {
		v.auditLog.LogLogin(username, false, "key unwrap failed", ipAddress)
		return fmt.Errorf("invalid credentials")
	}

	if err := v.Vault.UnlockWithKey(encKey, hmacKey); err != nil {
		v.auditLog.LogLogin(username, false, "vault unlock failed", ipAddress)
		return fmt.Errorf("invalid credentials")
	}

	v.auditLog.SetHMACKey(v.Vault.hmacKey)

	// Decrypt TOTP secret for in-memory use (Req 3.3)
	// Keep MFA secret encrypted-only on disk; do not store plaintext in UserRecord.

	// Load profile into memory
	v.userProfile = userRecordToProfile(rec)

	// Requirement 3.6: Enforce concurrent session limit before completing login.
	if policy, pErr := v.GetSecurityPolicy(); pErr == nil && policy != nil && policy.MaxConcurrentSessions > 0 {
		if rec.ActiveSessionCount >= policy.MaxConcurrentSessions {
			_ = v.Vault.Lock()
			v.userProfile = nil
			v.auditLog.LogLogin(username, false, fmt.Sprintf("concurrent session limit (%d) reached", policy.MaxConcurrentSessions), ipAddress)
			return fmt.Errorf("concurrent session limit reached (%d/%d active) — close an existing session and try again",
				rec.ActiveSessionCount, policy.MaxConcurrentSessions)
		}
	}

	// Reset counters on success and increment session count
	rec.FailedAttempts = 0
	rec.LockoutUntil = nil
	now := time.Now()
	rec.LastLogin = now
	v.userProfile.LastLogin = now
	rec.ActiveSessionCount++
	uf.Users[username] = rec
	_ = v.writeUsersFile(uf)

	v.RecordLoginAttempt(true)
	v.auditLog.LogLogin(username, true, "", ipAddress)
	v.ApplyStoredRolePermissions()
	return nil
}

// FlushUserProfile writes the current in-memory userProfile back to the users file.
// Called after MFA changes, password changes, etc.
func (v *VaultWithUser) FlushUserProfile() error {
	if v.userProfile == nil {
		return nil
	}
	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	key, rec, ok := resolveUsername(uf, v.userProfile.Username)
	if !ok {
		return nil // user not in file (shouldn't happen)
	}
	profileToRecord(rec, v.userProfile)

	// Keep TOTP secret encrypted on disk (Req 3.3).
	// Source of truth can be either:
	//  1) userProfile.MFASecret (legacy/in-memory), or
	//  2) pendingMFASecret (generated during enrollment before activation flow
	//     clears it from memory after successful persistence).
	if v.Vault.IsUnlocked() {
		secret := strings.TrimSpace(v.userProfile.MFASecret)
		if secret == "" {
			v.pendingMu.Lock()
			secret = strings.TrimSpace(v.pendingMFASecret)
			v.pendingMu.Unlock()
		}

		if v.userProfile.MFAEnabled && v.userProfile.TOTPVerified {
			// Active MFA must have an encrypted secret on disk.
			if secret != "" {
				if wm, wErr := wrapMFAWithKey(v.Vault.encryptionKey, secret); wErr == nil && wm != nil {
					rec.WrappedMFASecret = wm
				}
			}
		} else {
			// MFA disabled or not fully activated: clear persisted secret material.
			rec.WrappedMFASecret = nil
		}
		// plaintext MFA secret field removed from UserRecord; encrypted-only at rest.
	}

	uf.Users[key] = rec
	return v.writeUsersFile(uf)
}

// ListUserRecords returns all user records (admin only in practice).
func (v *VaultWithUser) ListUserRecords() ([]*UserRecord, error) {
	if v.userProfile == nil {
		return nil, fmt.Errorf("authentication required")
	}
	if !v.HasPermission(auth.CanViewUsers) {
		return nil, fmt.Errorf("permission denied: missing %s", auth.CanViewUsers)
	}
	uf, err := v.readUsersFile()
	if err != nil {
		return nil, err
	}
	out := make([]*UserRecord, 0, len(uf.Users))
	for _, r := range uf.Users {
		cp := *r
		cp.PasswordHash = nil
		cp.PasswordSalt = nil
		cp.WrappedVaultKeys = nil
		cp.WrappedMFASecret = nil
		out = append(out, &cp)
	}
	return out, nil
}

// ListShareableUsernames returns active usernames suitable for share dialogs.
// It is intentionally minimal and does not expose credential material.
func (v *VaultWithUser) ListShareableUsernames() ([]string, error) {
	if v.userProfile == nil {
		return nil, fmt.Errorf("authentication required")
	}
	uf, err := v.readUsersFile()
	if err != nil {
		return nil, err
	}
	current := strings.ToLower(strings.TrimSpace(v.userProfile.Username))
	out := make([]string, 0, len(uf.Users))
	for username, rec := range uf.Users {
		if strings.ToLower(strings.TrimSpace(username)) == current {
			continue
		}
		if rec != nil && rec.IsRevoked {
			continue
		}
		out = append(out, username)
	}
	sort.Strings(out)
	return out, nil
}

// ChangeUserRole updates the role of another user (admin only).
func (v *VaultWithUser) ChangeUserRole(targetUsername, newRole, byUsername string) error {
	if err := v.requirePermission(byUsername, auth.CanChangeRole); err != nil {
		return err
	}
	if !isSupportedRole(newRole) {
		return fmt.Errorf("invalid role: %s", newRole)
	}

	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	rec, ok := uf.Users[targetUsername]
	if !ok {
		return fmt.Errorf("user '%s' not found", targetUsername)
	}
	oldRole := rec.Role
	rec.Role = newRole
	uf.Users[targetUsername] = rec
	if err := v.writeUsersFile(uf); err != nil {
		return err
	}
	if v.userProfile != nil && strings.EqualFold(targetUsername, v.userProfile.Username) {
		v.userProfile.Role = newRole
	}
	v.auditLog.LogAdminChange(byUsername, "ROLE_CHANGE", targetUsername,
		fmt.Sprintf("%s -> %s", oldRole, newRole))
	return nil
}

// RevokeUserRecord revokes a user's access immediately.
func (v *VaultWithUser) RevokeUserRecord(targetUsername, byUsername string) error {
	if err := v.requirePermission(byUsername, auth.CanLockUser); err != nil {
		return err
	}

	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	rec, ok := uf.Users[targetUsername]
	if !ok {
		return fmt.Errorf("user '%s' not found", targetUsername)
	}
	rec.IsRevoked = true
	uf.Users[targetUsername] = rec
	if err := v.writeUsersFile(uf); err != nil {
		return err
	}
	v.auditLog.LogAdminChange(byUsername, "USER_REVOKE", targetUsername, "access revoked")
	return nil
}

// UpdateUserEmail updates the current user's email address.
func (v *VaultWithUser) UpdateUserEmail(newEmail string) error {
	if v.userProfile == nil {
		return fmt.Errorf("not logged in")
	}
	newEmail = strings.TrimSpace(newEmail)
	v.userProfile.Email = newEmail
	if err := v.FlushUserProfile(); err != nil {
		return err
	}
	v.auditLog.LogAdminChange(v.userProfile.Username, "PROFILE_UPDATE", v.userProfile.Username, "email updated")
	return nil
}

// RenameUser renames the currently-logged-in user after verifying their password.
// The rename:
//   - moves the UserRecord to the new key in the users file
//   - updates userProfile.Username in memory
//   - reattributes all vault entries whose CreatedBy == oldUsername
func (v *VaultWithUser) RenameUser(currentPassword, newUsername string) error {
	if v.userProfile == nil {
		return fmt.Errorf("not logged in")
	}
	newUsername = strings.TrimSpace(newUsername)
	if len(newUsername) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}
	oldUsername := v.userProfile.Username
	if strings.EqualFold(newUsername, oldUsername) {
		return fmt.Errorf("new username is the same as the current one")
	}

	// Verify password
	expected := hashUserPassword(currentPassword, v.userProfile.PasswordSalt)
	if !hmac.Equal(expected, v.userProfile.PasswordHash) {
		return fmt.Errorf("incorrect password")
	}

	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}

	// Reject if new name already taken (case-insensitive)
	lowerNew := strings.ToLower(newUsername)
	for k := range uf.Users {
		if strings.ToLower(k) == lowerNew {
			return fmt.Errorf("username '%s' is already taken", newUsername)
		}
	}

	// Move record to new key
	rec, ok := uf.Users[oldUsername]
	if !ok {
		return fmt.Errorf("user record not found")
	}
	rec.Username = newUsername
	delete(uf.Users, oldUsername)
	uf.Users[newUsername] = rec
	if err := v.writeUsersFile(uf); err != nil {
		return err
	}

	// Reattribute vault entries
	if v.Vault.IsUnlocked() {
		v.Vault.mu.Lock()
		changed := false
		for _, s := range v.Vault.entries {
			if s.CreatedBy == oldUsername {
				s.CreatedBy = newUsername
				changed = true
			}
		}
		if changed {
			v.Vault.dirty = true
		}
		v.Vault.mu.Unlock()
		if changed {
			_ = v.Vault.saveToFile()
		}
	}

	v.userProfile.Username = newUsername
	v.auditLog.LogAdminChange(newUsername, "USER_RENAME", oldUsername, fmt.Sprintf("renamed to '%s'", newUsername))
	return nil
}

// DeleteUserRecord removes a user entirely.
func (v *VaultWithUser) DeleteUserRecord(targetUsername, byUsername string) error {
	if err := v.requirePermission(byUsername, auth.CanDeleteUser); err != nil {
		return err
	}

	uf, err := v.readUsersFile()
	if err != nil {
		return err
	}
	if _, ok := uf.Users[targetUsername]; !ok {
		return fmt.Errorf("user '%s' not found", targetUsername)
	}
	delete(uf.Users, targetUsername)
	if err := v.writeUsersFile(uf); err != nil {
		return err
	}
	v.auditLog.LogAdminChange(byUsername, "USER_DELETE", targetUsername, "user deleted")
	return nil
}
