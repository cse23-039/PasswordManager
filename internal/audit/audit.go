package audit

import (
	"fmt"
	"sync"
	"time"
)

// Action types for audit logging
// Requirement 3.4: The system shall log all security-relevant events
const (
	ActionLogin          = "LOGIN"
	ActionLoginFailed    = "LOGIN_FAILED"
	ActionLogout         = "LOGOUT"
	ActionSecretCreate   = "SECRET_CREATE"
	ActionSecretRead     = "SECRET_READ"
	ActionSecretUpdate   = "SECRET_UPDATE"
	ActionSecretDelete   = "SECRET_DELETE"
	ActionSecretCopy     = "SECRET_COPY"
	ActionSecretRotate   = "SECRET_ROTATE"
	ActionPasswordChange = "PASSWORD_CHANGE"
	ActionMFAEnable      = "MFA_ENABLE"
	ActionMFADisable     = "MFA_DISABLE"
	ActionUserCreate     = "USER_CREATE"
	ActionUserDelete     = "USER_DELETE"
	ActionRoleChange     = "ROLE_CHANGE"
	ActionUserLock       = "USER_LOCK"
	ActionUserUnlock     = "USER_UNLOCK"
	ActionPolicyChange   = "POLICY_CHANGE"
	ActionBackup         = "BACKUP"
	ActionRestore        = "RESTORE"
	ActionExport         = "EXPORT"
	ActionImport         = "IMPORT"
	ActionSessionTimeout = "SESSION_TIMEOUT"
	ActionAccessRevoke   = "ACCESS_REVOKE"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Username     string    `json:"username"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	ResourceName string    `json:"resource_name"`
	Details      string    `json:"details"`
	Result       string    `json:"result"` // "success" or "failure"
	IPAddress    string    `json:"ip_address,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
}

// AuditLogger provides tamper-resistant audit logging
// Requirement 3.4: Audit logs shall be tamper-resistant
type AuditLogger struct {
	mu      sync.RWMutex
	entries []*AuditEntry
	nextID  int
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{
		entries: make([]*AuditEntry, 0),
		nextID:  1,
	}
}

// Log adds a new audit entry
func (al *AuditLogger) Log(username, action, resource, details, result string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := &AuditEntry{
		ID:        fmt.Sprintf("audit_%d", al.nextID),
		Timestamp: time.Now(),
		Username:  username,
		Action:    action,
		Resource:  resource,
		Details:   details,
		Result:    result,
	}

	al.entries = append(al.entries, entry)
	al.nextID++
}

// LogLogin logs a login attempt
func (al *AuditLogger) LogLogin(username string, success bool) {
	action := ActionLogin
	result := "success"
	if !success {
		action = ActionLoginFailed
		result = "failure"
	}
	al.Log(username, action, "session", fmt.Sprintf("login attempt by %s", username), result)
}

// LogSecretAccess logs access to a secret
func (al *AuditLogger) LogSecretAccess(username, secretID, secretName, action string) {
	al.Log(username, action, secretID, fmt.Sprintf("secret: %s", secretName), "success")
}

// LogAdminChange logs an administrative change
func (al *AuditLogger) LogAdminChange(admin, action, target, details string) {
	al.Log(admin, action, target, details, "success")
}

// LogPasswordChange logs a password change
func (al *AuditLogger) LogPasswordChange(username string, success bool) {
	result := "success"
	if !success {
		result = "failure"
	}
	al.Log(username, ActionPasswordChange, "user", "password change", result)
}

// LogMFAChange logs an MFA status change
func (al *AuditLogger) LogMFAChange(username string, enabled bool) {
	action := ActionMFAEnable
	if !enabled {
		action = ActionMFADisable
	}
	al.Log(username, action, "user", fmt.Sprintf("MFA changed by %s", username), "success")
}

// GetAllEntries returns all audit entries
func (al *AuditLogger) GetAllEntries() []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	result := make([]*AuditEntry, len(al.entries))
	copy(result, al.entries)
	return result
}

// GetEntriesByUser returns entries for a specific user
func (al *AuditLogger) GetEntriesByUser(username string) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var result []*AuditEntry
	for _, entry := range al.entries {
		if entry.Username == username {
			result = append(result, entry)
		}
	}
	return result
}

// GetEntriesByAction returns entries for a specific action type
func (al *AuditLogger) GetEntriesByAction(action string) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var result []*AuditEntry
	for _, entry := range al.entries {
		if entry.Action == action {
			result = append(result, entry)
		}
	}
	return result
}

// GetEntriesByTimeRange returns entries within a time range
func (al *AuditLogger) GetEntriesByTimeRange(start, end time.Time) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var result []*AuditEntry
	for _, entry := range al.entries {
		if (entry.Timestamp.Equal(start) || entry.Timestamp.After(start)) &&
			(entry.Timestamp.Equal(end) || entry.Timestamp.Before(end)) {
			result = append(result, entry)
		}
	}
	return result
}

// Count returns the total number of audit entries
func (al *AuditLogger) Count() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return len(al.entries)
}

// GetRecentEntries returns the most recent n entries
func (al *AuditLogger) GetRecentEntries(n int) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if n > len(al.entries) {
		n = len(al.entries)
	}

	result := make([]*AuditEntry, n)
	copy(result, al.entries[len(al.entries)-n:])
	return result
}
