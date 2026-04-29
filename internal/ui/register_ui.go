package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// RegisterForm represents a user registration form.
type RegisterForm struct {
	UsernameEntry *widget.Entry
	EmailEntry    *widget.Entry
	PasswordEntry *widget.Entry
	ConfirmEntry  *widget.Entry
	ErrorLabel    *widget.Label
	OnRegister    func(username, email, password string)
}

// NewRegisterForm creates a new registration form.
func NewRegisterForm(onRegister func(username, email, password string)) *RegisterForm {
	form := &RegisterForm{
		UsernameEntry: widget.NewEntry(),
		EmailEntry:    widget.NewEntry(),
		PasswordEntry: widget.NewPasswordEntry(),
		ConfirmEntry:  widget.NewPasswordEntry(),
		ErrorLabel:    makeErrorLabel(),
		OnRegister:    onRegister,
	}
	form.UsernameEntry.SetPlaceHolder("Minimum 3 characters")
	form.EmailEntry.SetPlaceHolder("Optional — used for recovery")
	form.PasswordEntry.SetPlaceHolder("Minimum 12 characters")
	form.ConfirmEntry.SetPlaceHolder("Re-enter password")
	return form
}

// GetContainer returns the registration form as a modern card container.
func (rf *RegisterForm) GetContainer() *fyne.Container {
	reqLabel := widget.NewLabel("12+ chars · upper & lower · number · special character")
	reqLabel.Importance = widget.LowImportance

	createBtn := makePrimaryBtn("Create Account", theme.ContentAddIcon(), func() {
		username := strings.TrimSpace(rf.UsernameEntry.Text)
		email := strings.TrimSpace(rf.EmailEntry.Text)
		password := rf.PasswordEntry.Text
		confirm := rf.ConfirmEntry.Text

		if len(username) < 3 {
			rf.ErrorLabel.SetText("Username must be at least 3 characters")
			return
		}
		if len(password) < 12 {
			rf.ErrorLabel.SetText("Password must be at least 12 characters")
			return
		}
		hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
		for _, c := range password {
			switch {
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= '0' && c <= '9':
				hasDigit = true
			default:
				hasSpecial = true
			}
		}
		switch {
		case !hasUpper:
			rf.ErrorLabel.SetText("Password must contain at least one uppercase letter")
			return
		case !hasLower:
			rf.ErrorLabel.SetText("Password must contain at least one lowercase letter")
			return
		case !hasDigit:
			rf.ErrorLabel.SetText("Password must contain at least one digit")
			return
		case !hasSpecial:
			rf.ErrorLabel.SetText("Password must contain at least one special character")
			return
		}
		if password != confirm {
			rf.ErrorLabel.SetText("Passwords do not match")
			return
		}
		if rf.OnRegister != nil {
			rf.OnRegister(username, email, password)
		}
	})

	fields := container.NewVBox(
		makeFormRow("Username", makeFullWidthEntry(rf.UsernameEntry)),
		makeFormRow("Email", makeFullWidthEntry(rf.EmailEntry)),
		makeFormRow("Password", makeFullWidthEntry(rf.PasswordEntry)),
		container.NewPadded(reqLabel),
		makeFormRow("Confirm", makeFullWidthEntry(rf.ConfirmEntry)),
	)

	return container.NewVBox(
		makeCenteredHeading("Create Account"),
		makeDivider(),
		container.NewPadded(fields),
		rf.ErrorLabel,
		createBtn,
	)
}

// SetError sets an error message on the form.
func (rf *RegisterForm) SetError(msg string) { rf.ErrorLabel.SetText(msg) }
