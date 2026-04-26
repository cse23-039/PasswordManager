package audit

import "time"

// QueryFilter defines criteria for filtering audit entries
type QueryFilter struct {
	Username  string
	Action    string
	Resource  string
	StartTime *time.Time
	EndTime   *time.Time
	Result    string
	Limit     int
	Offset    int
}

// QueryEntries filters audit entries based on criteria
func (al *AuditLogger) QueryEntries(filter *QueryFilter) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditEntry

	for _, entry := range al.entries {
		if filter.Username != "" && entry.Username != filter.Username {
			continue
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if filter.Resource != "" && entry.Resource != filter.Resource {
			continue
		}
		if filter.Result != "" && entry.Result != filter.Result {
			continue
		}
		if filter.StartTime != nil && entry.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && entry.Timestamp.After(*filter.EndTime) {
			continue
		}

		results = append(results, entry)
	}

	// Apply offset
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	} else if filter.Offset >= len(results) {
		return nil
	}

	// Apply limit
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	return results
}

// GetLoginAttempts returns all login-related entries
func (al *AuditLogger) GetLoginAttempts() []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditEntry
	for _, entry := range al.entries {
		if entry.Action == ActionLogin || entry.Action == ActionLoginFailed {
			results = append(results, entry)
		}
	}
	return results
}

// GetFailedLogins returns all failed login entries
func (al *AuditLogger) GetFailedLogins() []*AuditEntry {
	return al.GetEntriesByAction(ActionLoginFailed)
}

// GetSecretAccessLog returns all secret access entries
func (al *AuditLogger) GetSecretAccessLog() []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditEntry
	for _, entry := range al.entries {
		switch entry.Action {
		case ActionSecretCreate, ActionSecretRead, ActionSecretUpdate,
			ActionSecretDelete, ActionSecretCopy, ActionSecretRotate:
			results = append(results, entry)
		}
	}
	return results
}

// GetAdminActions returns all administrative action entries
func (al *AuditLogger) GetAdminActions() []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditEntry
	for _, entry := range al.entries {
		switch entry.Action {
		case ActionUserCreate, ActionUserDelete, ActionRoleChange, ActionUserLock,
			ActionUserUnlock, ActionPolicyChange, ActionBackup, ActionRestore,
			ActionAccessRevoke:
			results = append(results, entry)
		}
	}
	return results
}

// GetStatistics returns audit log statistics
func (al *AuditLogger) GetStatistics() map[string]int {
	al.mu.RLock()
	defer al.mu.RUnlock()

	stats := map[string]int{
		"total_entries":    len(al.entries),
		"login_success":    0,
		"login_failed":     0,
		"secret_access":    0,
		"admin_actions":    0,
		"password_changes": 0,
	}

	for _, entry := range al.entries {
		switch entry.Action {
		case ActionLogin:
			stats["login_success"]++
		case ActionLoginFailed:
			stats["login_failed"]++
		case ActionSecretCreate, ActionSecretRead, ActionSecretUpdate, ActionSecretDelete:
			stats["secret_access"]++
		case ActionUserCreate, ActionUserDelete, ActionRoleChange, ActionPolicyChange:
			stats["admin_actions"]++
		case ActionPasswordChange:
			stats["password_changes"]++
		}
	}

	return stats
}
