// Package vault provides shared-credential management.
// Requirement 3.2: support shared credentials with restricted access controls.
//
// SharedCredentialManager extends the base vault with the concept of a shared
// secret – a credential that multiple named users may access, subject to
// per-user RBAC permission checks.
package vault

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"password-manager/internal/auth"
)

// SharedAccess describes one named user's access rights on a shared secret.
type SharedAccess struct {
	Username  string     `json:"username"`
	CanRead   bool       `json:"can_read"`
	CanUpdate bool       `json:"can_update"`
	CanDelete bool       `json:"can_delete"`
	GrantedBy string     `json:"granted_by"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = never expires
	Revoked   bool       `json:"revoked"`
	RevokedBy string     `json:"revoked_by,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// SharedSecretMeta is metadata stored alongside a SecretData entry to track
// sharing state.  It is stored as a vault entry under ID "__SHARE__<secretID>".
type SharedSecretMeta struct {
	SecretID  string          `json:"secret_id"`
	Owner     string          `json:"owner"`
	CreatedAt time.Time       `json:"created_at"`
	Access    []*SharedAccess `json:"access"`
}

// SharedCredentialManager wraps a VaultWithUser and adds multi-user sharing
// semantics with fine-grained access control.
type SharedCredentialManager struct {
	mu    sync.RWMutex
	vault *VaultWithUser
	// shareMetaPrefix is the vault entry ID prefix for sharing metadata.
	shareMetaPrefix string
}

const sharedMetaPrefix = "__SHARE__"

// NewSharedCredentialManager creates a manager backed by the given vault.
func NewSharedCredentialManager(v *VaultWithUser) *SharedCredentialManager {
	return &SharedCredentialManager{
		vault:           v,
		shareMetaPrefix: sharedMetaPrefix,
	}
}

// ShareSecret grants a named user access to an existing secret.
// The acting user must be the secret owner and have CanShareSecret permission.
func (m *SharedCredentialManager) ShareSecret(
	actingUser, secretID, targetUser string,
	canRead, canUpdate, canDelete bool,
	expiresAt *time.Time,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	actor, err := m.authenticatedActor()
	if err != nil {
		return err
	}
	if strings.TrimSpace(actingUser) != "" && !strings.EqualFold(strings.TrimSpace(actingUser), actor) {
		return fmt.Errorf("permission denied: actor mismatch")
	}
	if err := m.vault.checkSecretPermission(auth.CanShareSecret); err != nil {
		return fmt.Errorf("permission denied: sharing requires share_secret permission")
	}

	secret, err := m.vault.Vault.getSecret(secretID)
	if err != nil {
		return fmt.Errorf("secret not found: %s", secretID)
	}
	if secret.Category == "__SYSTEM__" {
		return fmt.Errorf("cannot share system secrets")
	}
	owner := strings.TrimSpace(secret.CreatedBy)
	if owner == "" {
		return fmt.Errorf("cannot share legacy secret without owner metadata")
	}
	if !strings.EqualFold(owner, actor) {
		return fmt.Errorf("only the credential owner (%s) may share this secret", owner)
	}
	if strings.TrimSpace(targetUser) == "" {
		return fmt.Errorf("target user is required")
	}
	targetUser = strings.TrimSpace(targetUser)

	meta, err := m.loadMeta(secretID)
	if err != nil {
		// No existing meta – create new
		meta = &SharedSecretMeta{
			SecretID:  secretID,
			Owner:     owner,
			CreatedAt: time.Now(),
			Access:    make([]*SharedAccess, 0),
		}
	}
	if meta.Owner == "" {
		meta.Owner = owner
	}
	if !strings.EqualFold(meta.Owner, owner) {
		return fmt.Errorf("share metadata owner mismatch")
	}

	// Remove any existing entry for targetUser before re-adding
	updated := make([]*SharedAccess, 0, len(meta.Access))
	for _, a := range meta.Access {
		if a.Username != targetUser {
			updated = append(updated, a)
		}
	}
	now := time.Now()
	updated = append(updated, &SharedAccess{
		Username:  targetUser,
		CanRead:   canRead,
		CanUpdate: canUpdate,
		CanDelete: canDelete,
		GrantedBy: actor,
		GrantedAt: now,
		ExpiresAt: expiresAt,
	})
	meta.Access = updated

	if err := m.saveMeta(meta); err != nil {
		return fmt.Errorf("failed to save share metadata: %w", err)
	}

	m.vault.auditLog.LogAdminChange(actor, "share_secret",
		targetUser, fmt.Sprintf("secret_id=%s read=%v update=%v delete=%v", secretID, canRead, canUpdate, canDelete))
	return nil
}

// RevokeShare revokes access for targetUser on secretID.
func (m *SharedCredentialManager) RevokeShare(actingUser, secretID, targetUser string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	actor, err := m.authenticatedActor()
	if err != nil {
		return err
	}
	if strings.TrimSpace(actingUser) != "" && !strings.EqualFold(strings.TrimSpace(actingUser), actor) {
		return fmt.Errorf("permission denied: actor mismatch")
	}
	secret, err := m.vault.Vault.getSecret(secretID)
	if err != nil {
		return fmt.Errorf("secret not found: %s", secretID)
	}
	if secret.Category == "__SYSTEM__" {
		return fmt.Errorf("cannot revoke shares on system secrets")
	}
	owner := strings.TrimSpace(secret.CreatedBy)
	if owner == "" {
		return fmt.Errorf("cannot revoke share for legacy secret without owner metadata")
	}

	meta, err := m.loadMeta(secretID)
	if err != nil {
		return fmt.Errorf("no sharing metadata found for secret %s", secretID)
	}
	if meta.Owner == "" {
		meta.Owner = owner
	}
	if !strings.EqualFold(meta.Owner, owner) {
		return fmt.Errorf("share metadata owner mismatch")
	}
	if !strings.EqualFold(meta.Owner, actor) {
		return fmt.Errorf("only the credential owner may revoke shares")
	}

	now := time.Now()
	for _, a := range meta.Access {
		if strings.EqualFold(a.Username, strings.TrimSpace(targetUser)) && !a.Revoked {
			a.Revoked = true
			a.RevokedBy = actor
			a.RevokedAt = &now
		}
	}

	if err := m.saveMeta(meta); err != nil {
		return fmt.Errorf("failed to save revocation: %w", err)
	}

	m.vault.auditLog.LogAdminChange(actor, "revoke_share", targetUser,
		fmt.Sprintf("secret_id=%s", secretID))
	return nil
}

// CheckAccess returns whether username has the requested permission on secretID.
func (m *SharedCredentialManager) CheckAccess(username, secretID string, needUpdate, needDelete bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	meta, err := m.loadMeta(secretID)
	if err != nil {
		// No sharing record – only the implicit owner (vault user) may access
		return fmt.Errorf("no access record for secret %s", secretID)
	}

	// Owner always has full access
	if strings.EqualFold(meta.Owner, username) {
		return nil
	}

	now := time.Now()
	for _, a := range meta.Access {
		if !strings.EqualFold(a.Username, username) || a.Revoked {
			continue
		}
		if a.ExpiresAt != nil && now.After(*a.ExpiresAt) {
			continue // expired
		}
		if !a.CanRead {
			return fmt.Errorf("user %s does not have read access to this credential", username)
		}
		if needUpdate && !a.CanUpdate {
			return fmt.Errorf("user %s does not have update access to this credential", username)
		}
		if needDelete && !a.CanDelete {
			return fmt.Errorf("user %s does not have delete access to this credential", username)
		}
		return nil // access granted
	}

	return fmt.Errorf("user %s does not have access to this credential", username)
}

// ListSharedWith returns all active (non-revoked, non-expired) access entries for secretID.
func (m *SharedCredentialManager) ListSharedWith(secretID string) ([]*SharedAccess, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	meta, err := m.loadMeta(secretID)
	if err != nil {
		return nil, nil // no shares
	}

	now := time.Now()
	var active []*SharedAccess
	for _, a := range meta.Access {
		if a.Revoked {
			continue
		}
		if a.ExpiresAt != nil && now.After(*a.ExpiresAt) {
			continue
		}
		active = append(active, a)
	}
	return active, nil
}

// ListSecretsSharedWithMe returns secret IDs where username has active access.
func (m *SharedCredentialManager) ListSecretsSharedWithMe(username string) ([]string, error) {
	secrets, err := m.vault.ListSecrets()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var ids []string
	for _, s := range secrets {
		meta, err := m.loadMeta(s.ID)
		if err != nil {
			continue
		}
		for _, a := range meta.Access {
			if strings.EqualFold(a.Username, username) && !a.Revoked {
				if a.ExpiresAt == nil || now.Before(*a.ExpiresAt) {
					ids = append(ids, s.ID)
					break
				}
			}
		}
	}
	return ids, nil
}

// GetOwner returns the recorded owner of secretID, or "" if no sharing record
// exists (meaning the secret was never shared and belongs to the vault user).
func (m *SharedCredentialManager) GetOwner(secretID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	meta, err := m.loadMeta(secretID)
	if err != nil {
		return "" // no sharing record → implicit owner
	}
	return meta.Owner
}

// GetGranteeAccess returns the active SharedAccess record for username on
// secretID, or nil if the user has no active grant.
func (m *SharedCredentialManager) GetGranteeAccess(secretID, username string) *SharedAccess {
	m.mu.RLock()
	defer m.mu.RUnlock()

	meta, err := m.loadMeta(secretID)
	if err != nil {
		return nil
	}

	now := time.Now()
	for _, a := range meta.Access {
		if !strings.EqualFold(a.Username, username) || a.Revoked {
			continue
		}
		if a.ExpiresAt != nil && now.After(*a.ExpiresAt) {
			continue
		}
		return a
	}
	return nil
}

// ─── internal helpers ────────────────────────────────────────────────────────

func (m *SharedCredentialManager) metaID(secretID string) string {
	return m.shareMetaPrefix + secretID
}

func (m *SharedCredentialManager) authenticatedActor() (string, error) {
	if m.vault == nil || m.vault.userProfile == nil || !m.vault.Vault.IsUnlocked() {
		return "", fmt.Errorf("authentication required")
	}
	actor := strings.TrimSpace(m.vault.userProfile.Username)
	if actor == "" {
		return "", fmt.Errorf("authentication required")
	}
	return actor, nil
}

func (m *SharedCredentialManager) loadMeta(secretID string) (*SharedSecretMeta, error) {
	entry, err := m.vault.Vault.getSecret(m.metaID(secretID))
	if err != nil {
		return nil, err
	}
	var meta SharedSecretMeta
	if err := mustUnmarshalJSON([]byte(entry.Notes), &meta); err != nil {
		return nil, fmt.Errorf("corrupt share metadata: %w", err)
	}
	return &meta, nil
}

func (m *SharedCredentialManager) saveMeta(meta *SharedSecretMeta) error {
	raw, err := marshalJSON(meta)
	if err != nil {
		return fmt.Errorf("failed to serialize share metadata: %w", err)
	}
	data := string(raw)
	id := m.metaID(meta.SecretID)

	// Check if entry already exists
	if _, err := m.vault.Vault.getSecret(id); err == nil {
		// Update
		return m.vault.Vault.UpdateSecret(&SecretData{
			ID:       id,
			Name:     id,
			Category: "__SYSTEM__",
			Notes:    data,
		})
	}
	// Create
	return m.vault.Vault.AddSecret(&SecretData{
		ID:       id,
		Name:     id,
		Category: "__SYSTEM__",
		Notes:    data,
	})
}
