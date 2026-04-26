package ui

import (
	"fmt"
	"password-manager/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// SecretsListUI provides a reusable secrets list view component.
// The primary list rendering lives in local_vault_ui.go (showSecretsList);
// this helper is used for embedding a compact list in dialogs or other panels.
type SecretsListUI struct {
	vault    *vault.VaultWithUser
	window   fyne.Window
	onSelect func(name string)
}

// NewSecretsListUI creates a new secrets list UI component.
func NewSecretsListUI(v *vault.VaultWithUser, window fyne.Window) *SecretsListUI {
	return &SecretsListUI{
		vault:  v,
		window: window,
	}
}

// SetOnSelect sets the callback for when a secret is selected.
func (s *SecretsListUI) SetOnSelect(fn func(name string)) {
	s.onSelect = fn
}

// GetSecretsTable creates a scrollable list showing all provided secrets.
// onCopy is called with the secret's password; onDelete with the secret name.
func (s *SecretsListUI) GetSecretsTable(
	secrets []*vault.SecretData,
	onCopy func(password string),
	onDelete func(name string),
) *fyne.Container {

	if len(secrets) == 0 {
		empty := widget.NewLabelWithStyle(
			"No secrets found. Click 'Add Secret' to get started.",
			fyne.TextAlignCenter,
			fyne.TextStyle{Italic: true},
		)
		return container.NewVBox(empty)
	}

	list := widget.NewList(
		func() int { return len(secrets) },
		func() fyne.CanvasObject {
			// Template row: icon | name + category | copy btn | delete btn
			copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {})
			deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {})
			copyBtn.Importance = widget.LowImportance
			deleteBtn.Importance = widget.DangerImportance
			return container.NewBorder(
				nil, nil,
				container.NewHBox(widget.NewIcon(theme.DocumentIcon())),
				container.NewHBox(copyBtn, deleteBtn),
				container.NewHBox(
					widget.NewLabel("Secret Name"),
					widget.NewLabel(" · "),
					widget.NewLabelWithStyle("category", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
				),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(secrets) {
				return
			}
			sec := secrets[id]
			border := obj.(*fyne.Container)

			// Centre: name + separator + category
			centre := border.Objects[0].(*fyne.Container)
			centre.Objects[0].(*widget.Label).SetText(sec.Name)
			centre.Objects[2].(*widget.Label).SetText(sec.Category)

			// Right side buttons (index 1 in border objects is the trailing object)
			btns := border.Objects[1].(*fyne.Container)
			password := sec.Password
			name := sec.Name
			btns.Objects[0].(*widget.Button).OnTapped = func() {
				if onCopy != nil {
					onCopy(password)
				}
			}
			btns.Objects[1].(*widget.Button).OnTapped = func() {
				if onDelete != nil {
					onDelete(name)
				}
			}
		},
	)

	header := widget.NewLabelWithStyle(
		fmt.Sprintf("Secrets (%d)", len(secrets)),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)

	return container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		nil, nil, nil,
		list,
	)
}
