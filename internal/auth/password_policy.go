package auth

import (
	"fmt"
	"unicode"
)

// ValidatePasswordPolicy checks if a password meets the security policy
// Requirement 3.1: Strong password policies (minimum length, complexity, expiration)
func ValidatePasswordPolicy(password string, minLength int) []string {
	var errors []string

	if len(password) < minLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters", minLength))
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

	if !hasUpper {
		errors = append(errors, "must contain at least one uppercase letter")
	}
	if !hasLower {
		errors = append(errors, "must contain at least one lowercase letter")
	}
	if !hasDigit {
		errors = append(errors, "must contain at least one digit")
	}
	if !hasSpecial {
		errors = append(errors, "must contain at least one special character")
	}

	return errors
}

// IsPasswordExpired checks if a password has expired based on policy
func IsPasswordExpired(daysSinceChange, expiryDays int) bool {
	if expiryDays <= 0 {
		return false // No expiry policy
	}
	return daysSinceChange >= expiryDays
}

// PasswordStrength returns a strength score (0-4) for a password
func PasswordStrength(password string) int {
	score := 0

	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
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

	if hasUpper && hasLower {
		score++
	}
	if hasDigit && hasSpecial {
		score++
	}

	return score
}
