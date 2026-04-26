package ui

import (
	"password-manager/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// AppUI is the main UI coordinator that wraps the full application UI
type AppUI struct {
	App    fyne.App
	Window fyne.Window
	Vault  *vault.VaultWithUser
}

// NewAppUI creates a new application UI
func NewAppUI(app fyne.App, window fyne.Window, v *vault.VaultWithUser) *AppUI {
	return &AppUI{
		App:    app,
		Window: window,
		Vault:  v,
	}
}

// Initialize sets up and starts the UI
func (a *AppUI) Initialize() {
	InitializeLocalUI(a.App, a.Window, a.Vault)
}

// ShowAboutDialog displays an about dialog
func ShowAboutDialog(window fyne.Window) {
	aboutContent := container.NewVBox(
		widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Version: 1.0.0"),
		widget.NewSeparator(),
		widget.NewLabel("Secure password management with:"),
		widget.NewLabel("• AES-256-GCM encryption"),
		widget.NewLabel("• Argon2id key derivation"),
		widget.NewLabel("• TOTP multi-factor authentication"),
		widget.NewLabel("• Role-based access control"),
		widget.NewLabel("• Tamper-resistant audit logging"),
		widget.NewSeparator(),
		widget.NewLabel("Local vault file (.pwm) storage"),
	)

	aboutDialog := widget.NewModalPopUp(
		container.NewVBox(
			aboutContent,
			widget.NewButtonWithIcon("Close", theme.CancelIcon(), nil),
		),
		window.Canvas(),
	)

	// Set close handler
	closeBtn := aboutDialog.Content.(*fyne.Container).Objects[1].(*widget.Button)
	closeBtn.OnTapped = func() {
		aboutDialog.Hide()
	}

	aboutDialog.Show()
}
