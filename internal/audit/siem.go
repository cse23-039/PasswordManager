package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SIEMExporter provides log export for SIEM/log management integration
// Requirement 3.4: The system shall support log export or integration with SIEM/log management tools

// ExportJSON exports audit entries as JSON
func (al *AuditLogger) ExportJSON() ([]byte, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	return json.MarshalIndent(al.entries, "", "  ")
}

// ExportCSV exports audit entries as CSV
func (al *AuditLogger) ExportCSV() string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("ID,Timestamp,Username,Action,Resource,Details,Result\n")

	for _, entry := range al.entries {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(entry.ID),
			entry.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			csvEscape(entry.Username),
			csvEscape(entry.Action),
			csvEscape(entry.Resource),
			csvEscape(entry.Details),
			csvEscape(entry.Result),
		))
	}

	return sb.String()
}

// ExportCEF exports audit entries in Common Event Format (ArcSight compatible)
func (al *AuditLogger) ExportCEF() string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var sb strings.Builder

	for _, entry := range al.entries {
		severity := "3" // Low
		if entry.Result == "failure" {
			severity = "7" // High
		}

		sb.WriteString(fmt.Sprintf("CEF:0|PasswordManager|Vault|1.0|%s|%s|%s|"+
			"suser=%s msg=%s outcome=%s rt=%s\n",
			entry.Action,
			entry.Action,
			severity,
			entry.Username,
			cefEscape(entry.Details),
			entry.Result,
			entry.Timestamp.Format("Jan 02 2006 15:04:05"),
		))
	}

	return sb.String()
}

// ExportSyslog exports entries in syslog format
func (al *AuditLogger) ExportSyslog() string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var sb strings.Builder

	for _, entry := range al.entries {
		priority := 14 // facility=1 (user), severity=6 (informational)
		if entry.Result == "failure" {
			priority = 11 // facility=1 (user), severity=3 (error)
		}

		sb.WriteString(fmt.Sprintf("<%d>%s PasswordManager: user=%s action=%s resource=%s result=%s details=\"%s\"\n",
			priority,
			entry.Timestamp.Format("Jan 02 15:04:05"),
			entry.Username,
			entry.Action,
			entry.Resource,
			entry.Result,
			entry.Details,
		))
	}

	return sb.String()
}

// csvEscape escapes a string for CSV output
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return fmt.Sprintf("\"%s\"", strings.ReplaceAll(s, "\"", "\"\""))
	}
	return s
}

// cefEscape escapes a string for CEF format
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}
