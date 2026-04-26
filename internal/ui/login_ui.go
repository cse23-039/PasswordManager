package ui

import (
	"errors"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showLoginUI creates the login form components
// Note: The primary login implementation is in local_vault_ui.go
// This file provides reusable login form widgets

// LoginForm represents a reusable login form
type LoginForm struct {
	UsernameEntry *widget.Entry
	PasswordEntry *widget.Entry
	MFAEntry      *widget.Entry
	ErrorLabel    *widget.Label
	OnLogin       func(username, password, mfaCode string)
}

// NewLoginForm creates a new login form
func NewLoginForm(onLogin func(username, password, mfaCode string)) *LoginForm {
	form := &LoginForm{
		UsernameEntry: widget.NewEntry(),
		PasswordEntry: widget.NewPasswordEntry(),
		MFAEntry:      widget.NewEntry(),
		ErrorLabel:    widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{}),
		OnLogin:       onLogin,
	}

	form.UsernameEntry.SetPlaceHolder("Username")
	form.PasswordEntry.SetPlaceHolder("Password")
	form.MFAEntry.SetPlaceHolder("MFA Code (if enabled)")
	form.ErrorLabel.Importance = widget.DangerImportance

	return form
}

// GetContainer returns the login form as a container
func (lf *LoginForm) GetContainer(showMFA bool) *fyne.Container {
	items := []fyne.CanvasObject{
		widget.NewLabelWithStyle("Login", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("Username:"),
		lf.UsernameEntry,
		widget.NewLabel("Password:"),
		lf.PasswordEntry,
	}

	if showMFA {
		items = append(items,
			widget.NewLabel("MFA Code:"),
			lf.MFAEntry,
		)
	}

	items = append(items,
		lf.ErrorLabel,
		widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
			username := strings.TrimSpace(lf.UsernameEntry.Text)
			password := lf.PasswordEntry.Text
			mfaCode := strings.TrimSpace(lf.MFAEntry.Text)

			if username == "" || password == "" {
				lf.ErrorLabel.SetText("Username and password are required")
				return
			}

			if lf.OnLogin != nil {
				lf.OnLogin(username, password, mfaCode)
			}
		}),
	)

	return container.NewVBox(items...)
}

// SetError sets an error message on the login form
func (lf *LoginForm) SetError(msg string) {
	lf.ErrorLabel.SetText(msg)
}

// Clear clears the login form fields
func (lf *LoginForm) Clear() {
	lf.UsernameEntry.SetText("")
	lf.PasswordEntry.SetText("")
	lf.MFAEntry.SetText("")
	lf.ErrorLabel.SetText("")
}

// ShowLoginError shows a login error dialog
func ShowLoginError(window fyne.Window, message string) {
	dialog.ShowError(errors.New(message), window)
}
