package ui

import (
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
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
	title := widget.NewLabelWithStyle("Reports & Exports", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	// Audit log export section
	auditSection := container.NewVBox(
		widget.NewLabelWithStyle("Audit Log Export", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Export audit logs for SIEM integration or compliance review"),
		container.NewHBox(
			widget.NewButtonWithIcon("Export JSON", theme.DocumentIcon(), func() {
				ae.showSaveDialog("audit_log.json", onExportJSON)
			}),
			widget.NewButtonWithIcon("Export CSV", theme.DocumentIcon(), func() {
				ae.showSaveDialog("audit_log.csv", onExportCSV)
			}),
			widget.NewButtonWithIcon("Export CEF", theme.DocumentIcon(), func() {
				ae.showSaveDialog("audit_log.cef", onExportCEF)
			}),
		),
	)

	// Compliance report section
	complianceSection := container.NewVBox(
		widget.NewLabelWithStyle("Compliance Reports", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Generate compliance and security assessment reports"),
		widget.NewButtonWithIcon("Generate Compliance Report", theme.InfoIcon(), func() {
			if onComplianceReport != nil {
				onComplianceReport()
			}
		}),
	)

	return container.NewVBox(
		title,
		widget.NewSeparator(),
		auditSection,
		widget.NewSeparator(),
		complianceSection,
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
