package auth

import (
	"fmt"
	"sync"

	"password-manager/internal/models"
)

// Permission constants for RBAC
// Requirement 3.1: RBAC including Administrator, Security Officer, Standard User, Read-Only User
const (
	// Secret permissions
	CanViewSecrets  = "view_secrets"
	CanCreateSecret = "create_secret"
	CanEditSecret   = "edit_secret"
	CanDeleteSecret = "delete_secret"
	CanCopySecret   = "copy_secret"
	CanRotateSecret = "rotate_secret"

	// User management permissions
	CanCreateUser = "create_user"
	CanDeleteUser = "delete_user"
	CanChangeRole = "change_role"
	CanViewUsers  = "view_users"
	CanLockUser   = "lock_user"

	// Admin permissions
	CanManagePolicy   = "manage_policy"
	CanViewAuditLogs  = "view_audit_logs"
	CanExportData     = "export_data"
	CanImportData     = "import_data"
	CanBackupVault    = "backup_vault"
	CanRestoreVault   = "restore_vault"
	CanManageSessions = "manage_sessions"
	CanManageRoles    = "manage_roles"
)

// RolePermissions maps roles to their allowed permissions
var RolePermissions = map[string][]string{
	models.RoleAdministrator: {
		CanViewSecrets, CanCreateSecret, CanEditSecret, CanDeleteSecret,
		CanCopySecret, CanRotateSecret,
		CanCreateUser, CanDeleteUser, CanChangeRole, CanViewUsers, CanLockUser,
		CanManagePolicy, CanViewAuditLogs, CanExportData, CanImportData,
		CanBackupVault, CanRestoreVault, CanManageSessions, CanManageRoles,
	},
	models.RoleSecurityOfficer: {

		CanViewSecrets, CanCreateSecret, CanEditSecret, CanCopySecret,
		CanRotateSecret,
		CanViewUsers,
		CanViewAuditLogs, CanExportData,
	},
	models.RoleStandardUser: {
		CanViewSecrets, CanCreateSecret, CanEditSecret, CanDeleteSecret,
		CanCopySecret,
	},
	models.RoleReadOnly: {
		CanViewSecrets, CanCopySecret,
	},
}

// rpMu protects RolePermissions for concurrent access
var rpMu sync.RWMutex

// CheckPermission checks if a user has a specific permission
func CheckPermission(user *models.User, permission string) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}

	rpMu.RLock()
	perms, ok := RolePermissions[user.Role]
	rpMu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown role: %s", user.Role)
	}

	for _, p := range perms {
		if p == permission {
			return nil
		}
	}

	return fmt.Errorf("permission denied: %s does not have %s", user.Role, permission)
}

// HasPermission returns true if the user has the specified permission
func HasPermission(user *models.User, permission string) bool {
	return CheckPermission(user, permission) == nil
}

// GetRolePermissions returns all permissions for a role
func GetRolePermissions(role string) ([]string, error) {
	rpMu.RLock()
	perms, ok := RolePermissions[role]
	rpMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown role: %s", role)
	}
	// Return a copy
	result := make([]string, len(perms))
	copy(result, perms)
	return result, nil
}

// GetAllRoles returns all available roles
func GetAllRoles() []string {
	return []string{
		models.RoleAdministrator,
		models.RoleSecurityOfficer,
		models.RoleStandardUser,
		models.RoleReadOnly,
	}
}

// AllPermissions enumerates every permission key in logical groups.
var AllPermissions = []string{
	// Secrets
	CanViewSecrets, CanCreateSecret, CanEditSecret, CanDeleteSecret, CanCopySecret, CanRotateSecret,
	// Users
	CanViewUsers, CanCreateUser, CanDeleteUser, CanChangeRole, CanLockUser,
	// Admin
	CanManagePolicy, CanViewAuditLogs, CanExportData, CanImportData,
	CanBackupVault, CanRestoreVault, CanManageSessions,
	CanManageRoles,
}

// PermissionLabels maps each permission key to a human-readable label.
var PermissionLabels = map[string]string{
	CanViewSecrets:    "View secrets",
	CanCreateSecret:   "Create secrets",
	CanEditSecret:     "Edit secrets",
	CanDeleteSecret:   "Delete secrets",
	CanCopySecret:     "Copy secret to clipboard",
	CanRotateSecret:   "Rotate / regenerate secrets",
	CanViewUsers:      "View user list",
	CanCreateUser:     "Create new users",
	CanDeleteUser:     "Delete users",
	CanChangeRole:     "Change user roles",
	CanLockUser:       "Lock / revoke users",
	CanManagePolicy:   "Manage security policy",
	CanViewAuditLogs:  "View audit logs",
	CanExportData:     "Export audit / data",
	CanImportData:     "Import data",
	CanBackupVault:    "Create vault backups",
	CanRestoreVault:   "Restore vault backups",
	CanManageSessions: "Manage sessions",
	CanManageRoles:    "Manage role permissions",
}

// PermissionGroups organises AllPermissions into labelled sections for UI.
var PermissionGroups = []struct {
	Label       string
	Permissions []string
}{
	{"Secrets", []string{CanViewSecrets, CanCreateSecret, CanEditSecret, CanDeleteSecret, CanCopySecret, CanRotateSecret}},
	{"Users", []string{CanViewUsers, CanCreateUser, CanDeleteUser, CanChangeRole, CanLockUser}},
	{"Administration", []string{CanManagePolicy, CanManageRoles, CanViewAuditLogs, CanExportData, CanImportData, CanBackupVault, CanRestoreVault, CanManageSessions}},
}

// ApplyRolePermissions replaces the runtime RolePermissions map entries from the
// provided overrides map. Only roles present in overrides are updated; other
// roles keep their compile-time defaults. Call this after loading persisted
// overrides from the vault.
func ApplyRolePermissions(overrides map[string][]string) {
	rpMu.Lock()
	defer rpMu.Unlock()
	for role, perms := range overrides {
		cp := make([]string, len(perms))
		copy(cp, perms)
		RolePermissions[role] = cp
	}
}

// DefaultRolePermissions returns a deep copy of the current RolePermissions map.
func DefaultRolePermissions() map[string][]string {
	rpMu.RLock()
	defer rpMu.RUnlock()
	out := make(map[string][]string, len(RolePermissions))
	for role, perms := range RolePermissions {
		cp := make([]string, len(perms))
		copy(cp, perms)
		out[role] = cp
	}
	return out
}
