package admin

import (
	"fmt"
	"unicode"

	"password-manager/internal/audit"
	"password-manager/internal/auth"
	"password-manager/internal/crypto"
	"password-manager/internal/models"
)

// CreateUser creates a new user (requires CreateUser permission)
// Requirement 3.5: Administrators shall be able to manage users, roles, and permissions
func CreateUser(username, password, role string, users map[string]*models.User, mfaEnabled bool, requester *models.User, logger *audit.AuditLogger) (*models.User, error) {
	if err := auth.CheckPermission(requester, auth.CanCreateUser); err != nil {
		return nil, err
	}
	if users == nil {
		return nil, fmt.Errorf("users map is nil")
	}

	if _, exists := users[username]; exists {
		return nil, fmt.Errorf("user already exists")
	}

	if !isValidRole(role) {
		return nil, fmt.Errorf("invalid role: %s", role)
	}

	if !isStrongPassword(password) {
		return nil, fmt.Errorf("password must be at least 12 characters and contain uppercase, lowercase, digits, and special characters")
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		MFAEnabled:   mfaEnabled,
		MFASecret:    "",
	}

	users[username] = user

	if logger != nil {
		logger.LogAdminChange(requester.Username, audit.ActionUserCreate, username, fmt.Sprintf("role=%s", role))
	}

	return user, nil
}

// DeleteUser removes a user (requires DeleteUser permission)
func DeleteUser(username string, users map[string]*models.User, requester *models.User, logger *audit.AuditLogger) error {
	if err := auth.CheckPermission(requester, auth.CanDeleteUser); err != nil {
		return err
	}
	if _, exists := users[username]; !exists {
		return fmt.Errorf("user not found")
	}
	delete(users, username)

	if logger != nil {
		logger.LogAdminChange(requester.Username, audit.ActionUserDelete, username, "user deleted")
	}

	return nil
}

// SetUserRole changes a user's role (requires ChangeRole permission)
func SetUserRole(username, newRole string, users map[string]*models.User, requester *models.User, logger *audit.AuditLogger) error {
	if err := auth.CheckPermission(requester, auth.CanChangeRole); err != nil {
		return err
	}
	user, exists := users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	if !isValidRole(newRole) {
		return fmt.Errorf("invalid role: %s", newRole)
	}

	user.Role = newRole

	if logger != nil {
		logger.LogAdminChange(requester.Username, audit.ActionRoleChange, username, fmt.Sprintf("new_role=%s", newRole))
	}

	return nil
}

// LockUser locks a user account (requires LockUser permission)
func LockUser(username string, users map[string]*models.User, requester *models.User, logger *audit.AuditLogger) error {
	if err := auth.CheckPermission(requester, auth.CanLockUser); err != nil {
		return err
	}
	user, exists := users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.Locked = true

	if logger != nil {
		logger.LogAdminChange(requester.Username, audit.ActionUserLock, username, "account locked")
	}

	return nil
}

// UnlockUser unlocks a user account
func UnlockUser(username string, users map[string]*models.User, requester *models.User, logger *audit.AuditLogger) error {
	if err := auth.CheckPermission(requester, auth.CanLockUser); err != nil {
		return err
	}
	user, exists := users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.Locked = false

	if logger != nil {
		logger.LogAdminChange(requester.Username, audit.ActionUserUnlock, username, "account unlocked")
	}

	return nil
}

// ListUsers returns all users (requires ViewUsers permission)
func ListUsers(users map[string]*models.User, requester *models.User) ([]*models.User, error) {
	if err := auth.CheckPermission(requester, auth.CanViewUsers); err != nil {
		return nil, err
	}

	var result []*models.User
	for _, user := range users {
		// Return copies without password hash
		u := *user
		u.PasswordHash = ""
		result = append(result, &u)
	}
	return result, nil
}

// isValidRole checks if a role string is one of the predefined roles
func isValidRole(role string) bool {
	switch role {
	case models.RoleAdministrator, models.RoleSecurityOfficer,
		models.RoleStandardUser, models.RoleReadOnly:
		return true
	}
	return false
}

// isStrongPassword checks if a password meets minimum strength requirements
func isStrongPassword(password string) bool {
	if len(password) < 12 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}
