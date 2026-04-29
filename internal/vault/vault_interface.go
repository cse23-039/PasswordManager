package vault

import "time"

// IVault defines the read/write surface of a Vault that callers outside the
// package depend on.  Implementing this interface makes it possible to swap in
// a test double (e.g. an in-memory stub) without touching production code.
//
// Only the methods that are called from outside the vault package are listed
// here.  Internal helpers (saveToFile, scheduleSave, etc.) are intentionally
// excluded — they are implementation details, not part of the public contract.
type IVault interface {
	// Lifecycle
	Create(masterPassword string) error
	Unlock(masterPassword string) error
	UnlockWithKey(encKey, hmacKey []byte) error
	Lock() error
	IsUnlocked() bool
	Exists() bool
	GetFilePath() string

	// Secret CRUD
	AddSecret(secret *SecretData) error
	UpdateSecret(secret *SecretData) error
	DeleteSecret(id string) error
	ListSecrets() ([]*SecretData, error)
	SearchSecrets(query, category string, tags []string) ([]*SecretData, error)
	GetSecretByName(name string) (*SecretData, error)
	GetPasswordHistory(id string) ([]PasswordHistoryEntry, error)

	// Vault management
	ChangeMasterPassword(currentPassword, newPassword string) error
	ExportVault(exportPath string) error
	ImportVault(importPath, importPassword string) (int, error)
	GetStats() (map[string]interface{}, error)
	GetHealthReport() (*VaultHealthReport, error)
	CheckExternalModification() bool
	SetMaxPasswordHistory(n int)
}

// compile-time assertion: *Vault must satisfy IVault.
var _ IVault = (*Vault)(nil)

// IVaultWithUser extends IVault with the user-authentication surface consumed
// by the UI and admin packages.
type IVaultWithUser interface {
	IVault

	// Auth
	SetupNewVault(username, password, email string) error
	Login(username, password, ipAddress string) error
	LoginWithMFA(username, password, totpCode, ipAddress string) error
	Logout() error
	GetRole() string
	HasPermission(permission string) bool

	// MFA
	EnableMFA() (secret string, err error)
	VerifyAndActivateMFA(code string) error
	DisableMFA(password string) error

	// Profile / password
	GetUserProfile() (*UserProfile, error)
	ChangePassword(currentPassword, newPassword string) error
	UpdateEmail(email string) error

	// Health & stats
	GetStatsByUser() (map[string]interface{}, error)

	// Audited operations (used by UI layer)
	AddSecretAudited(secret *SecretData) error
	GetSecretAudited(id string) (*SecretData, error)
	UpdateSecretAudited(secret *SecretData) error
	DeleteSecretAudited(id string) error
	ListSecretsAudited() ([]*SecretData, error)
	ExportVaultAudited(exportPath string) error
	ImportVaultAudited(importPath, importPassword string) (int, error)
}

// compile-time assertion: *VaultWithUser must satisfy IVaultWithUser.
var _ IVaultWithUser = (*VaultWithUser)(nil)

// ── Stub helpers for testing ──────────────────────────────────────────────────

// vaultCreatedAt is a convenience accessor used by tests that need the vault's
// creation timestamp without depending on GetStats map key names.
func vaultCreatedAt(v IVault) time.Time {
	stats, err := v.GetStats()
	if err != nil {
		return time.Time{}
	}
	if t, ok := stats["created_at"].(time.Time); ok {
		return t
	}
	return time.Time{}
}
