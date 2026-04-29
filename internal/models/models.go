package models

import "time"

// User represents a user in the system
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	MFASecret    string    `json:"mfa_secret,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Locked    bool      `json:"locked"` // manual admin lock; see VaultWithUser.LockoutUntil for timed lockout
	LastLogin time.Time `json:"last_login,omitempty"`
	Email        string    `json:"email,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
	Result    string    `json:"result"`
	IPAddress string    `json:"ip_address,omitempty"`
}

// Session represents a user session
type Session struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Token        string    `json:"token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActivity time.Time `json:"last_activity"`
	IsActive     bool      `json:"is_active"`
}

// Role represents a role in the RBAC system
type Role struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Description string   `json:"description"`
}

// Predefined roles
const (
	RoleAdministrator   = "administrator"
	RoleSecurityOfficer = "security_officer"
	RoleStandardUser    = "standard_user"
	RoleReadOnly        = "read_only"
)
