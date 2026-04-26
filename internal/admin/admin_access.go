package admin

import (
	"fmt"
	"password-manager/internal/audit"
	"password-manager/internal/models"
	"sync"
	"time"
)

// AccessController manages access control and revocation
// Requirement 3.5: Administrators shall be able to disable or revoke user access immediately
type AccessController struct {
	mu       sync.RWMutex
	revoker  *AccessRevoker
	sessions *SessionManager
	logger   *audit.AuditLogger
}

// NewAccessController creates a new access controller
func NewAccessController(sessions *SessionManager, logger *audit.AuditLogger) *AccessController {
	return &AccessController{
		revoker:  NewAccessRevoker(logger),
		sessions: sessions,
		logger:   logger,
	}
}

// RevokeUserAccess immediately revokes a user's access and terminates their sessions
func (ac *AccessController) RevokeUserAccess(username, reason, revokedBy string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Revoke access
	ac.revoker.RevokeAccess(username, reason, revokedBy, nil)

	// End all their sessions
	if ac.sessions != nil {
		ac.sessions.InvalidateAllUserSessions(username)
	}

	return nil
}

// TemporaryRevoke revokes access until a specified time
func (ac *AccessController) TemporaryRevoke(username, reason, revokedBy string, until time.Time) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.revoker.RevokeAccess(username, reason, revokedBy, &until)

	if ac.sessions != nil {
		ac.sessions.InvalidateAllUserSessions(username)
	}

	return nil
}

// RestoreUserAccess restores a user's access
func (ac *AccessController) RestoreUserAccess(username, restoredBy string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.revoker.RestoreAccess(username, restoredBy)
	return nil
}

// IsUserAccessRevoked checks if a user has their access revoked
func (ac *AccessController) IsUserAccessRevoked(username string) (*RevocationInfo, bool) {
	return ac.revoker.IsRevoked(username)
}

// CheckAccess verifies a user can access the system
func (ac *AccessController) CheckAccess(user *models.User) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}

	if user.Locked {
		return fmt.Errorf("account is locked")
	}

	if info, revoked := ac.revoker.IsRevoked(user.Username); revoked {
		return fmt.Errorf("access revoked: %s", info.Reason)
	}

	return nil
}

// GetRevokedUsers returns all users with revoked access
func (ac *AccessController) GetRevokedUsers() []*RevocationInfo {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	var revoked []*RevocationInfo
	for _, info := range ac.revoker.revoked {
		if _, isRevoked := ac.revoker.IsRevoked(info.Username); isRevoked {
			revoked = append(revoked, info)
		}
	}
	return revoked
}
