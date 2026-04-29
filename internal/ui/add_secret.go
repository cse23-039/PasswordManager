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
	NameEntry       *widget.Entry
	UsernameEntry   *widget.Entry
	PasswordEntry   *widget.Entry
	URLEntry        *widget.Entry
	NotesEntry      *widget.Entry
	CategoryEntry   *widget.Entry
	TagsEntry       *widget.Entry
	ErrorLabel      *widget.Label
	OnSave          func(name, username, password, url, notes, category string, tags []string)
	OnCancel        func()
	CheckDuplicate  func(name string) bool // optional; returns true if name already exists
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
		ErrorLabel:    makeErrorLabel(),
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

	return form
}

// GetContainer returns the add secret form as a container
func (asf *AddSecretForm) GetContainer() *fyne.Container {
	return container.NewVBox(
		makeCenteredHeading("Add New Secret"),
		makeDivider(),
		makeFormRow("Name:", makeFullWidthEntry(asf.NameEntry)),
		makeFormRow("Username:", makeFullWidthEntry(asf.UsernameEntry)),
		makeFormRow("Password:", makeFullWidthEntry(asf.PasswordEntry)),
		makeFormRow("URL:", makeFullWidthEntry(asf.URLEntry)),
		makeFormRow("Category:", makeFullWidthEntry(asf.CategoryEntry)),
		makeFormRow("Tags:", makeFullWidthEntry(asf.TagsEntry)),
		makeFormRow("Notes:", makeFullWidthEntry(asf.NotesEntry)),
		asf.ErrorLabel,
		makeButtonBar(
			makePrimaryBtn("Save", theme.DocumentSaveIcon(), func() {
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
				if len(name) > 256 {
					asf.ErrorLabel.SetText("Name must be 256 characters or fewer")
					return
				}
				if len(username) > 256 {
					asf.ErrorLabel.SetText("Username must be 256 characters or fewer")
					return
				}
				if password == "" {
					asf.ErrorLabel.SetText("Password is required")
					return
				}
				if len(url) > 2048 {
					asf.ErrorLabel.SetText("URL must be 2048 characters or fewer")
					return
				}
				if len(notes) > 65536 {
					asf.ErrorLabel.SetText("Notes must be 65 536 characters or fewer")
					return
				}
				if len(category) > 128 {
					asf.ErrorLabel.SetText("Category must be 128 characters or fewer")
					return
				}
				if asf.CheckDuplicate != nil && asf.CheckDuplicate(name) {
					asf.ErrorLabel.SetText("A secret with this name already exists")
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
			makeLowBtn("Cancel", theme.CancelIcon(), func() {
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
