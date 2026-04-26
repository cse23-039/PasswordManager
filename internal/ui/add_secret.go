package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// AddSecretForm represents a form for adding a new secret
type AddSecretForm struct {
	NameEntry     *widget.Entry
	UsernameEntry *widget.Entry
	PasswordEntry *widget.Entry
	URLEntry      *widget.Entry
	NotesEntry    *widget.Entry
	CategoryEntry *widget.Entry
	TagsEntry     *widget.Entry
	ErrorLabel    *widget.Label
	OnSave        func(name, username, password, url, notes, category string, tags []string)
	OnCancel      func()
}

// NewAddSecretForm creates a new add secret form
func NewAddSecretForm(onSave func(name, username, password, url, notes, category string, tags []string), onCancel func()) *AddSecretForm {
	form := &AddSecretForm{
		NameEntry:     widget.NewEntry(),
		UsernameEntry: widget.NewEntry(),
		PasswordEntry: widget.NewPasswordEntry(),
		URLEntry:      widget.NewEntry(),
		NotesEntry:    widget.NewMultiLineEntry(),
		CategoryEntry: widget.NewEntry(),
		TagsEntry:     widget.NewEntry(),
		ErrorLabel:    widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{}),
		OnSave:        onSave,
		OnCancel:      onCancel,
	}

	form.NameEntry.SetPlaceHolder("Secret Name (required)")
	form.UsernameEntry.SetPlaceHolder("Username/Email")
	form.PasswordEntry.SetPlaceHolder("Password (required)")
	form.URLEntry.SetPlaceHolder("URL (optional)")
	form.NotesEntry.SetPlaceHolder("Notes (optional)")
	form.NotesEntry.SetMinRowsVisible(3)
	form.CategoryEntry.SetPlaceHolder("Category (e.g., Social, Email, Finance)")
	form.TagsEntry.SetPlaceHolder("Tags (comma separated)")
	form.ErrorLabel.Importance = widget.DangerImportance

	return form
}

// GetContainer returns the add secret form as a container
func (asf *AddSecretForm) GetContainer() *fyne.Container {
	return container.NewVBox(
		widget.NewLabelWithStyle("Add New Secret", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("Name:"),
		asf.NameEntry,
		widget.NewLabel("Username:"),
		asf.UsernameEntry,
		widget.NewLabel("Password:"),
		asf.PasswordEntry,
		widget.NewLabel("URL:"),
		asf.URLEntry,
		widget.NewLabel("Category:"),
		asf.CategoryEntry,
		widget.NewLabel("Tags:"),
		asf.TagsEntry,
		widget.NewLabel("Notes:"),
		asf.NotesEntry,
		asf.ErrorLabel,
		container.NewHBox(
			widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
				name := strings.TrimSpace(asf.NameEntry.Text)
				username := strings.TrimSpace(asf.UsernameEntry.Text)
				password := asf.PasswordEntry.Text
				url := strings.TrimSpace(asf.URLEntry.Text)
				notes := strings.TrimSpace(asf.NotesEntry.Text)
				category := strings.TrimSpace(asf.CategoryEntry.Text)
				tagsStr := strings.TrimSpace(asf.TagsEntry.Text)

				if name == "" {
					asf.ErrorLabel.SetText("Name is required")
					return
				}
				if password == "" {
					asf.ErrorLabel.SetText("Password is required")
					return
				}

				var tags []string
				if tagsStr != "" {
					for _, tag := range strings.Split(tagsStr, ",") {
						tag = strings.TrimSpace(tag)
						if tag != "" {
							tags = append(tags, tag)
						}
					}
				}

				if asf.OnSave != nil {
					asf.OnSave(name, username, password, url, notes, category, tags)
				}
			}),
			widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
				if asf.OnCancel != nil {
					asf.OnCancel()
				}
			}),
		),
	)
}

// SetError sets an error message on the form
func (asf *AddSecretForm) SetError(msg string) {
	asf.ErrorLabel.SetText(msg)
}

// Clear clears all form fields
func (asf *AddSecretForm) Clear() {
	asf.NameEntry.SetText("")
	asf.UsernameEntry.SetText("")
	asf.PasswordEntry.SetText("")
	asf.URLEntry.SetText("")
	asf.NotesEntry.SetText("")
	asf.CategoryEntry.SetText("")
	asf.TagsEntry.SetText("")
	asf.ErrorLabel.SetText("")
}
