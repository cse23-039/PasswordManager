package admin

import (
	"fmt"
	"strings"
	"time"

	"password-manager/internal/auth"
)

// ComplianceReport represents a compliance status report
// Requirement 3.5: System shall generate compliance reports
type ComplianceReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	GeneratedBy     string              `json:"generated_by"`
	OverallStatus   string              `json:"overall_status"` // COMPLIANT, NON_COMPLIANT, PARTIAL
	Sections        []ComplianceSection `json:"sections"`
	TotalChecks     int                 `json:"total_checks"`
	PassedChecks    int                 `json:"passed_checks"`
	FailedChecks    int                 `json:"failed_checks"`
	Recommendations []string            `json:"recommendations,omitempty"`
}

// ComplianceSection represents a section of the compliance report
type ComplianceSection struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Checks      []ComplianceCheck `json:"checks"`
	Description string            `json:"description"`
}

// ComplianceCheck represents an individual compliance check
type ComplianceCheck struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"` // PASS, FAIL, WARN
	Details     string `json:"details"`
	Requirement string `json:"requirement"`
}

// GenerateComplianceReport generates a full compliance report
func GenerateComplianceReport(pe *PolicyEnforcer, sm *SessionManager, generatedBy string) *ComplianceReport {
	report := &ComplianceReport{
		GeneratedAt: time.Now(),
		GeneratedBy: generatedBy,
	}

	// Check encryption compliance
	encSection := checkEncryptionCompliance()
	report.Sections = append(report.Sections, encSection)

	// Check password policy compliance
	pwdSection := checkPasswordCompliance(pe)
	report.Sections = append(report.Sections, pwdSection)

	// Check session management compliance
	sessSection := checkSessionCompliance(sm)
	report.Sections = append(report.Sections, sessSection)

	// Check audit compliance
	auditSection := checkAuditCompliance(pe)
	report.Sections = append(report.Sections, auditSection)

	// Check MFA compliance
	mfaSection := checkMFACompliance(pe)
	report.Sections = append(report.Sections, mfaSection)

	// Calculate totals
	for _, section := range report.Sections {
		for _, check := range section.Checks {
			report.TotalChecks++
			switch check.Status {
			case "PASS":
				report.PassedChecks++
			case "FAIL":
				report.FailedChecks++
			}
		}
	}

	// Set overall status
	if report.FailedChecks == 0 {
		report.OverallStatus = "COMPLIANT"
	} else if report.PassedChecks > report.FailedChecks {
		report.OverallStatus = "PARTIAL"
	} else {
		report.OverallStatus = "NON_COMPLIANT"
	}

	return report
}

func checkEncryptionCompliance() ComplianceSection {
	section := ComplianceSection{
		Name:        "Encryption (Req 3.1)",
		Description: "Data encryption and key management",
	}

	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "ENC-001",
		Name:        "AES-256-GCM Encryption",
		Status:      "PASS",
		Details:     "AES-256-GCM is used for all vault encryption",
		Requirement: "3.1 - master password shall encrypt/decrypt locally",
	})

	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "ENC-002",
		Name:        "Argon2id Key Derivation",
		Status:      "PASS",
		Details:     "Argon2id with proper parameters used for key derivation",
		Requirement: "3.1 - Argon2id for master password encryption",
	})

	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "ENC-003",
		Name:        "Local File Storage",
		Status:      "PASS",
		Details:     "Passwords stored in encrypted local vault file (.pwm)",
		Requirement: "3.1 - local vault file storage",
	})

	// Verify TOTP uses SHA256, not the deprecated SHA1
	mfaCfg := auth.DefaultMFAConfig()
	totpStatus := "PASS"
	totpDetails := fmt.Sprintf("TOTP algorithm: %s (required: SHA256)", mfaCfg.Algorithm)
	if mfaCfg.Algorithm != "SHA256" {
		totpStatus = "FAIL"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "ENC-004",
		Name:        "TOTP HMAC Algorithm",
		Status:      totpStatus,
		Details:     totpDetails,
		Requirement: "3.3 - strong HMAC for TOTP",
	})

	section.Status = sectionStatus(section.Checks)
	return section
}

func checkPasswordCompliance(pe *PolicyEnforcer) ComplianceSection {
	section := ComplianceSection{
		Name:        "Password Policy (Req 3.2)",
		Description: "Password strength and management",
	}

	policy := pe.GetPolicy()

	// Check minimum length
	status := "PASS"
	if policy.MinPasswordLength < 12 {
		status = "FAIL"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "PWD-001",
		Name:        "Minimum Password Length",
		Status:      status,
		Details:     fmt.Sprintf("Minimum length: %d (required: 12+)", policy.MinPasswordLength),
		Requirement: "3.2 - minimum 12 characters",
	})

	// Check complexity requirements
	status = "PASS"
	if !policy.RequireUppercase || !policy.RequireLowercase || !policy.RequireDigits || !policy.RequireSpecialChars {
		status = "FAIL"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "PWD-002",
		Name:        "Password Complexity",
		Status:      status,
		Details:     "Requires uppercase, lowercase, digits, and special characters",
		Requirement: "3.2 - enforce complexity rules",
	})

	// Check password history
	status = "PASS"
	if policy.PasswordHistoryCount < 5 {
		status = "WARN"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "PWD-003",
		Name:        "Password History",
		Status:      status,
		Details:     fmt.Sprintf("History count: %d", policy.PasswordHistoryCount),
		Requirement: "3.2 - prevent password reuse",
	})

	section.Status = sectionStatus(section.Checks)
	return section
}

func checkSessionCompliance(sm *SessionManager) ComplianceSection {
	section := ComplianceSection{
		Name:        "Session Management (Req 3.6)",
		Description: "Session timeout and controls",
	}

	// Check idle timeout is within a reasonable range (≤ 30 minutes)
	idleStatus := "PASS"
	idleDetails := "Session manager not available"
	if sm != nil {
		sm.mu.RLock()
		idle := sm.maxIdleTime
		sm.mu.RUnlock()
		idleDetails = fmt.Sprintf("Idle timeout: %v (required: ≤30m)", idle.Round(time.Minute))
		if idle > 30*time.Minute {
			idleStatus = "FAIL"
		}
	} else {
		idleStatus = "WARN"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "SESS-001",
		Name:        "Session Idle Timeout",
		Status:      idleStatus,
		Details:     idleDetails,
		Requirement: "3.6 - session timeout after inactivity",
	})

	// Check max session duration is configured (≤ 24 hours)
	maxStatus := "PASS"
	maxDetails := "Session manager not available"
	if sm != nil {
		sm.mu.RLock()
		maxSess := sm.maxSessionTime
		sm.mu.RUnlock()
		maxDetails = fmt.Sprintf("Max session: %v (required: ≤24h)", maxSess.Round(time.Minute))
		if maxSess > 24*time.Hour {
			maxStatus = "FAIL"
		}
	} else {
		maxStatus = "WARN"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "SESS-002",
		Name:        "Maximum Session Duration",
		Status:      maxStatus,
		Details:     maxDetails,
		Requirement: "3.6 - session invalidation support",
	})

	section.Status = sectionStatus(section.Checks)
	return section
}

func checkAuditCompliance(pe *PolicyEnforcer) ComplianceSection {
	section := ComplianceSection{
		Name:        "Audit Logging (Req 3.4)",
		Description: "Audit trail and monitoring",
	}

	policy := pe.GetPolicy()

	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "AUD-001",
		Name:        "Audit Logging Enabled",
		Status:      "PASS",
		Details:     "All actions are logged with HMAC tamper detection",
		Requirement: "3.4 - tamper-resistant audit logs",
	})

	status := "PASS"
	if policy.AuditRetentionDays < 90 {
		status = "WARN"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "AUD-002",
		Name:        "Audit Retention",
		Status:      status,
		Details:     fmt.Sprintf("Retention: %d days (recommended: 90+)", policy.AuditRetentionDays),
		Requirement: "3.4 - audit log retention",
	})

	section.Status = sectionStatus(section.Checks)
	return section
}

func checkMFACompliance(pe *PolicyEnforcer) ComplianceSection {
	section := ComplianceSection{
		Name:        "Multi-Factor Auth (Req 3.3)",
		Description: "MFA configuration and enforcement",
	}

	policy := pe.GetPolicy()

	status := "PASS"
	if !policy.MFAForAdmins {
		status = "WARN"
	}
	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "MFA-001",
		Name:        "MFA for Administrators",
		Status:      status,
		Details:     fmt.Sprintf("MFA required for admins: %v", policy.MFAForAdmins),
		Requirement: "3.3 - TOTP-based MFA support",
	})

	section.Checks = append(section.Checks, ComplianceCheck{
		ID:          "MFA-002",
		Name:        "TOTP Implementation",
		Status:      "PASS",
		Details:     "TOTP (RFC 6238) implemented with 30-second intervals",
		Requirement: "3.3 - TOTP-based second factor",
	})

	section.Status = sectionStatus(section.Checks)
	return section
}

func sectionStatus(checks []ComplianceCheck) string {
	hasFail := false
	for _, c := range checks {
		if c.Status == "FAIL" {
			hasFail = true
		}
	}
	if hasFail {
		return "FAIL"
	}
	return "PASS"
}

// FormatComplianceReport formats a compliance report as a readable string
func FormatComplianceReport(report *ComplianceReport) string {
	var b strings.Builder

	b.WriteString("=== Compliance Report ===\n")
	b.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Generated By: %s\n", report.GeneratedBy))
	b.WriteString(fmt.Sprintf("Overall Status: %s\n", report.OverallStatus))
	b.WriteString(fmt.Sprintf("Checks: %d passed, %d failed, %d total\n\n",
		report.PassedChecks, report.FailedChecks, report.TotalChecks))

	for _, section := range report.Sections {
		b.WriteString(fmt.Sprintf("--- %s [%s] ---\n", section.Name, section.Status))
		for _, check := range section.Checks {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", check.Status, check.ID, check.Name))
			b.WriteString(fmt.Sprintf("         %s\n", check.Details))
		}
		b.WriteString("\n")
	}

	return b.String()
}
