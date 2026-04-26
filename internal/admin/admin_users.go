package admin

import (
	"password-manager/internal/audit"
	"password-manager/internal/models"
	"sync"
	"time"
)

// UserManager manages user accounts
// Requirement 3.5: Administrators shall be able to manage users, roles, and permissions
type UserManager struct {
	mu    sync.RWMutex
	users map[string]*models.User
}

// NewUserManager creates a new user manager
func NewUserManager() *UserManager {
	return &UserManager{
		users: make(map[string]*models.User),
	}
}

// GetUser retrieves a user by username
func (um *UserManager) GetUser(username string) (*models.User, bool) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	user, exists := um.users[username]
	return user, exists
}

// GetUsers retrieves the users map (for admin functions)
func (um *UserManager) GetUsers() map[string]*models.User {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.users
}

// AddUser adds a user to the managed users
func (um *UserManager) AddUser(user *models.User) {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.users[user.Username] = user
}

// RemoveUser removes a user from managed users
func (um *UserManager) RemoveUser(username string) {
	um.mu.Lock()
	defer um.mu.Unlock()
	delete(um.users, username)
}

// UpdateLastLogin updates the last login time for a user
func (um *UserManager) UpdateLastLogin(username string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if user, exists := um.users[username]; exists {
		user.LastLogin = time.Now()
	}
}

// IsUserLocked checks if a user account is locked
func (um *UserManager) IsUserLocked(username string) bool {
	um.mu.RLock()
	defer um.mu.RUnlock()

	user, exists := um.users[username]
	if !exists {
		return false
	}
	return user.Locked
}

// CountUsers returns the total number of users
func (um *UserManager) CountUsers() int {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return len(um.users)
}

// AccessRevoker manages access revocation
// Requirement 3.5: Administrators shall be able to disable or revoke user access immediately
type AccessRevoker struct {
	mu      sync.RWMutex
	revoked map[string]*RevocationInfo
	logger  *audit.AuditLogger
}

// RevocationInfo stores details about access revocation
type RevocationInfo struct {
	Username  string
	Reason    string
	RevokedAt time.Time
	RevokedBy string
	Until     *time.Time // nil means permanent
}

// NewAccessRevoker creates a new access revoker
func NewAccessRevoker(logger *audit.AuditLogger) *AccessRevoker {
	return &AccessRevoker{
		revoked: make(map[string]*RevocationInfo),
		logger:  logger,
	}
}

// RevokeAccess immediately revokes a user's access
func (ar *AccessRevoker) RevokeAccess(username, reason, revokedBy string, until *time.Time) {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	ar.revoked[username] = &RevocationInfo{
		Username:  username,
		Reason:    reason,
		RevokedAt: time.Now(),
		RevokedBy: revokedBy,
		Until:     until,
	}

	if ar.logger != nil {
		ar.logger.LogAdminChange(revokedBy, audit.ActionAccessRevoke, username, reason)
	}
}

// RestoreAccess restores a user's access
func (ar *AccessRevoker) RestoreAccess(username, restoredBy string) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	delete(ar.revoked, username)

	if ar.logger != nil {
		ar.logger.LogAdminChange(restoredBy, "ACCESS_RESTORE", username, "access restored")
	}
}

// IsRevoked checks if a user's access is currently revoked
func (ar *AccessRevoker) IsRevoked(username string) (*RevocationInfo, bool) {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	info, exists := ar.revoked[username]
	if !exists {
		return nil, false
	}

	// Check if revocation has expired
	if info.Until != nil && time.Now().After(*info.Until) {
		return nil, false
	}

	return info, true
}

// PermissionManager manages role-based permissions
type PermissionManager struct {
	mu          sync.RWMutex
	customPerms map[string][]string // username -> extra permissions
}

// NewPermissionManager creates a new permission manager
func NewPermissionManager() *PermissionManager {
	return &PermissionManager{
		customPerms: make(map[string][]string),
	}
}

// GrantPermission grants an additional permission to a user
func (pm *PermissionManager) GrantPermission(username, permission string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	perms := pm.customPerms[username]
	for _, p := range perms {
		if p == permission {
			return // Already granted
		}
	}
	pm.customPerms[username] = append(perms, permission)
}

// RevokePermission removes a custom permission
func (pm *PermissionManager) RevokePermission(username, permission string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	perms := pm.customPerms[username]
	for i, p := range perms {
		if p == permission {
			pm.customPerms[username] = append(perms[:i], perms[i+1:]...)
			return
		}
	}
}

// GetCustomPermissions returns custom permissions for a user
func (pm *PermissionManager) GetCustomPermissions(username string) []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.customPerms[username]
}
