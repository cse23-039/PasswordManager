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

// LoginForm represents a reusable login form widget.
type LoginForm struct {
	UsernameEntry *widget.Entry
	PasswordEntry *widget.Entry
	MFAEntry      *widget.Entry
	ErrorLabel    *widget.Label
	OnLogin       func(username, password, mfaCode string)
}

// NewLoginForm creates a new login form.
func NewLoginForm(onLogin func(username, password, mfaCode string)) *LoginForm {
	form := &LoginForm{
		UsernameEntry: widget.NewEntry(),
		PasswordEntry: widget.NewPasswordEntry(),
		MFAEntry:      widget.NewEntry(),
		ErrorLabel:    makeErrorLabel(),
		OnLogin:       onLogin,
	}
	form.UsernameEntry.SetPlaceHolder("Enter your username")
	form.PasswordEntry.SetPlaceHolder("Enter your password")
	form.MFAEntry.SetPlaceHolder("6-digit code from your authenticator app")
	return form
}

// GetContainer returns the login form as a modern card container.
func (lf *LoginForm) GetContainer(showMFA bool) *fyne.Container {
	loginBtn := makePrimaryBtn("Login", theme.LoginIcon(), func() {
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
	})
	lf.PasswordEntry.OnSubmitted = func(_ string) { loginBtn.OnTapped() }

	fields := container.NewVBox(
		makeFormRow("Username", makeFullWidthEntry(lf.UsernameEntry)),
		makeFormRow("Password", makeFullWidthEntry(lf.PasswordEntry)),
	)
	if showMFA {
		fields.Add(makeFormRow("MFA Code", makeFullWidthEntry(lf.MFAEntry)))
	}

	return container.NewVBox(
		makeCenteredHeading("Sign In"),
		makeDivider(),
		container.NewPadded(fields),
		lf.ErrorLabel,
		loginBtn,
	)
}

// SetError sets an error message on the login form.
func (lf *LoginForm) SetError(msg string) { lf.ErrorLabel.SetText(msg) }

// Clear resets all form fields.
func (lf *LoginForm) Clear() {
	lf.UsernameEntry.SetText("")
	lf.PasswordEntry.SetText("")
	lf.MFAEntry.SetText("")
	lf.ErrorLabel.SetText("")
}

// ShowLoginError shows a login error in a dialog.
func ShowLoginError(window fyne.Window, message string) {
	dialog.ShowError(errors.New(message), window)
}
