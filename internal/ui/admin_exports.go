package ui

import (
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
)

// ensureExt appends ext to path if it doesn't already have that extension.
func ensureExt(path, ext string) string {
	if !strings.EqualFold(filepath.Ext(path), ext) {
		return path + ext
	}
	return path
}

// AdminExportsUI provides import/export and reporting UI
// Requirement 3.4: Audit log export (JSON, CSV, CEF)
type AdminExportsUI struct {
	window fyne.Window
}

// NewAdminExportsUI creates a new admin exports UI
func NewAdminExportsUI(window fyne.Window) *AdminExportsUI {
	return &AdminExportsUI{window: window}
}

// GetExportView creates the export/report view
func (ae *AdminExportsUI) GetExportView(onExportJSON, onExportCSV, onExportCEF func(string), onComplianceReport func()) *fyne.Container {
	auditContent := container.NewVBox(
		container.NewHBox(
			makeSecondaryBtn("Export JSON", theme.DocumentIcon(), func() {
				ae.showSaveDialog("audit_log.json", onExportJSON)
			}),
			makeSecondaryBtn("Export CSV", theme.DocumentIcon(), func() {
				ae.showSaveDialog("audit_log.csv", onExportCSV)
			}),
			makeSecondaryBtn("Export CEF", theme.DocumentIcon(), func() {
				ae.showSaveDialog("audit_log.cef", onExportCEF)
			}),
		),
	)

	complianceContent := container.NewVBox(
		makePrimaryBtn("Generate Compliance Report", theme.InfoIcon(), func() {
			if onComplianceReport != nil {
				onComplianceReport()
			}
		}),
	)

	return container.NewVBox(
		makeCenteredHeading("Reports & Exports"),
		makeDivider(),
		makeSectionCard("Audit Log Export", "Export audit logs for SIEM integration or compliance review", auditContent),
		makeDivider(),
		makeSectionCard("Compliance Reports", "Generate compliance and security assessment reports", complianceContent),
	)
}

func (ae *AdminExportsUI) showSaveDialog(suggested string, onSave func(string)) {
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		writer.Close()
		path := ensureExt(writer.URI().Path(), filepath.Ext(suggested))
		if onSave != nil {
			onSave(path)
		}
	}, ae.window)
}
