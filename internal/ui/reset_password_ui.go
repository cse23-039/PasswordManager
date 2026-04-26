package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ResetPasswordForm represents a password reset form
type ResetPasswordForm struct {
	UsernameEntry   *widget.Entry
	CurrentPwdEntry *widget.Entry
	NewPwdEntry     *widget.Entry
	ConfirmPwdEntry *widget.Entry
	ErrorLabel      *widget.Label
	SuccessLabel    *widget.Label
	OnReset         func(username, currentPwd, newPwd string)
}

// NewResetPasswordForm creates a new password reset form
func NewResetPasswordForm(onReset func(username, currentPwd, newPwd string)) *ResetPasswordForm {
	form := &ResetPasswordForm{
		UsernameEntry:   widget.NewEntry(),
		CurrentPwdEntry: widget.NewPasswordEntry(),
		NewPwdEntry:     widget.NewPasswordEntry(),
		ConfirmPwdEntry: widget.NewPasswordEntry(),
		ErrorLabel:      widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{}),
		SuccessLabel:    widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{}),
		OnReset:         onReset,
	}

	form.UsernameEntry.SetPlaceHolder("Username")
	form.CurrentPwdEntry.SetPlaceHolder("Current Password")
	form.NewPwdEntry.SetPlaceHolder("New Password (min 12 chars)")
	form.ConfirmPwdEntry.SetPlaceHolder("Confirm New Password")
	form.ErrorLabel.Importance = widget.DangerImportance
	form.SuccessLabel.Importance = widget.SuccessImportance

	return form
}

// GetContainer returns the password reset form as a container
func (rpf *ResetPasswordForm) GetContainer() *fyne.Container {
	return container.NewVBox(
		widget.NewLabelWithStyle("Reset Password", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("Username:"),
		rpf.UsernameEntry,
		widget.NewLabel("Current Password:"),
		rpf.CurrentPwdEntry,
		widget.NewLabel("New Password:"),
		rpf.NewPwdEntry,
		widget.NewLabel("Confirm New Password:"),
		rpf.ConfirmPwdEntry,
		rpf.ErrorLabel,
		rpf.SuccessLabel,
		widget.NewButtonWithIcon("Reset Password", theme.ViewRefreshIcon(), func() {
			username := strings.TrimSpace(rpf.UsernameEntry.Text)
			currentPwd := rpf.CurrentPwdEntry.Text
			newPwd := rpf.NewPwdEntry.Text
			confirmPwd := rpf.ConfirmPwdEntry.Text

			rpf.ErrorLabel.SetText("")
			rpf.SuccessLabel.SetText("")

			if username == "" || currentPwd == "" || newPwd == "" {
				rpf.ErrorLabel.SetText("All fields are required")
				return
			}

			if len(newPwd) < 12 {
				rpf.ErrorLabel.SetText("New password must be at least 12 characters")
				return
			}

			if newPwd != confirmPwd {
				rpf.ErrorLabel.SetText("New passwords do not match")
				return
			}

			if newPwd == currentPwd {
				rpf.ErrorLabel.SetText("New password must be different from current password")
				return
			}

			if rpf.OnReset != nil {
				rpf.OnReset(username, currentPwd, newPwd)
			}
		}),
	)
}

// SetError sets an error message
func (rpf *ResetPasswordForm) SetError(msg string) {
	rpf.ErrorLabel.SetText(msg)
	rpf.SuccessLabel.SetText("")
}

// SetSuccess sets a success message
func (rpf *ResetPasswordForm) SetSuccess(msg string) {
	rpf.SuccessLabel.SetText(msg)
	rpf.ErrorLabel.SetText("")
}
