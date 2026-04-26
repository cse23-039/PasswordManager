package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// RegisterForm represents a user registration form
type RegisterForm struct {
	UsernameEntry *widget.Entry
	EmailEntry    *widget.Entry
	PasswordEntry *widget.Entry
	ConfirmEntry  *widget.Entry
	ErrorLabel    *widget.Label
	OnRegister    func(username, email, password string)
}

// NewRegisterForm creates a new registration form
func NewRegisterForm(onRegister func(username, email, password string)) *RegisterForm {
	form := &RegisterForm{
		UsernameEntry: widget.NewEntry(),
		EmailEntry:    widget.NewEntry(),
		PasswordEntry: widget.NewPasswordEntry(),
		ConfirmEntry:  widget.NewPasswordEntry(),
		ErrorLabel:    widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{}),
		OnRegister:    onRegister,
	}

	form.UsernameEntry.SetPlaceHolder("Username (min 3 characters)")
	form.EmailEntry.SetPlaceHolder("Email (optional)")
	form.PasswordEntry.SetPlaceHolder("Password (min 12 chars)")
	form.ConfirmEntry.SetPlaceHolder("Confirm Password")
	form.ErrorLabel.Importance = widget.DangerImportance

	return form
}

// GetContainer returns the registration form as a container
func (rf *RegisterForm) GetContainer() *fyne.Container {
	requirements := widget.NewLabel("Password Requirements:\n• At least 12 characters\n• Upper & lowercase letters\n• At least one number\n• At least one special character")
	requirements.Wrapping = fyne.TextWrapWord

	return container.NewVBox(
		widget.NewLabelWithStyle("Create Account", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("Username:"),
		rf.UsernameEntry,
		widget.NewLabel("Email:"),
		rf.EmailEntry,
		widget.NewLabel("Password:"),
		rf.PasswordEntry,
		widget.NewLabel("Confirm Password:"),
		rf.ConfirmEntry,
		requirements,
		rf.ErrorLabel,
		widget.NewButtonWithIcon("Create Account", theme.ContentAddIcon(), func() {
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
			if password != confirm {
				rf.ErrorLabel.SetText("Passwords do not match")
				return
			}

			if rf.OnRegister != nil {
				rf.OnRegister(username, email, password)
			}
		}),
	)
}

// SetError sets an error message on the form
func (rf *RegisterForm) SetError(msg string) {
	rf.ErrorLabel.SetText(msg)
}
