package ui

import (
	"image/color"
	"strings"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// zeroAndClearBytes overwrites every byte in b with zero before the slice is
// released. Use this instead of a plain nil assignment for sensitive byte slices
// (e.g. passwords) because Go strings/[]byte are heap-allocated and the GC
// does not zero memory on collection.
func zeroAndClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ── Typography helpers ────────────────────────────────────────────────────────

func makeHeading(text string) *widget.Label {
	l := widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	return l
}

func makeSubheading(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Importance = widget.MediumImportance
	return l
}

func makeMutedLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Importance = widget.LowImportance
	return l
}

func makeCenteredHeading(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
}

// ── Button helpers ────────────────────────────────────────────────────────────

func makePrimaryBtn(label string, icon fyne.Resource, fn func()) *widget.Button {
	var b *widget.Button
	if icon != nil {
		b = widget.NewButtonWithIcon(label, icon, fn)
	} else {
		b = widget.NewButton(label, fn)
	}
	b.Importance = widget.HighImportance
	return b
}

func makeSecondaryBtn(label string, icon fyne.Resource, fn func()) *widget.Button {
	var b *widget.Button
	if icon != nil {
		b = widget.NewButtonWithIcon(label, icon, fn)
	} else {
		b = widget.NewButton(label, fn)
	}
	b.Importance = widget.MediumImportance
	return b
}

func makeDangerBtn(label string, icon fyne.Resource, fn func()) *widget.Button {
	var b *widget.Button
	if icon != nil {
		b = widget.NewButtonWithIcon(label, icon, fn)
	} else {
		b = widget.NewButton(label, fn)
	}
	b.Importance = widget.DangerImportance
	return b
}

func makeLowBtn(label string, icon fyne.Resource, fn func()) *widget.Button {
	var b *widget.Button
	if icon != nil {
		b = widget.NewButtonWithIcon(label, icon, fn)
	} else {
		b = widget.NewButton(label, fn)
	}
	b.Importance = widget.LowImportance
	return b
}

// ── Form row helper ───────────────────────────────────────────────────────────

// makeFormRow returns a horizontal row with a fixed-width label on the left
// and the provided widget filling the remaining width on the right.
func makeFormRow(label string, w fyne.CanvasObject) fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(label, fyne.TextAlignTrailing, fyne.TextStyle{Bold: false})
	lbl.Importance = widget.MediumImportance
	spacer := canvas.NewRectangle(color.Transparent)
	spacer.SetMinSize(fyne.NewSize(110, 1))
	labelBox := container.NewStack(spacer, lbl)
	return container.NewBorder(nil, nil, labelBox, nil, w)
}

// ── Info row helper ───────────────────────────────────────────────────────────

// makeInfoRow renders: [icon]  bold-label  ···  muted-value (trailing)
// Used in settings and detail views. Value fills remaining width, right-aligned.
func makeInfoRow(icon fyne.Resource, label, value string) fyne.CanvasObject {
	var iconObj fyne.CanvasObject
	if icon != nil {
		iconObj = widget.NewIcon(icon)
	} else {
		placeholder := canvas.NewRectangle(color.Transparent)
		placeholder.SetMinSize(fyne.NewSize(20, 20))
		iconObj = placeholder
	}
	lbl := widget.NewLabelWithStyle(label, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	val := widget.NewLabel(value)
	val.Importance = widget.LowImportance
	val.Truncation = fyne.TextTruncateEllipsis
	spacer := canvas.NewRectangle(color.Transparent)
	spacer.SetMinSize(fyne.NewSize(140, 1))
	labelBox := container.NewStack(spacer, container.NewHBox(container.NewCenter(iconObj), lbl))
	return container.NewBorder(nil, nil, labelBox, nil, val)
}

// ── Badge helpers ─────────────────────────────────────────────────────────────

// makeBadge returns a pill-shaped label with the given background color.
func makeBadge(text string, bg color.Color) fyne.CanvasObject {
	lbl := widget.NewLabel(text)
	lbl.Importance = widget.LowImportance
	rect := canvas.NewRectangle(bg)
	rect.CornerRadius = 10
	return container.NewStack(rect, container.NewPadded(lbl))
}

// makeStatusBadge returns a colored badge based on a status string.
func makeStatusBadge(status string) fyne.CanvasObject {
	var bg color.Color
	switch strings.ToLower(status) {
	case "active", "success", "ok":
		c := successColor()
		bg = color.RGBA{R: c.(color.RGBA).R, G: c.(color.RGBA).G, B: c.(color.RGBA).B, A: 50}
	case "revoked", "failed", "failure", "error":
		c := dangerColor()
		bg = color.RGBA{R: c.(color.RGBA).R, G: c.(color.RGBA).G, B: c.(color.RGBA).B, A: 50}
	default:
		c := warningColor()
		bg = color.RGBA{R: c.(color.RGBA).R, G: c.(color.RGBA).G, B: c.(color.RGBA).B, A: 50}
	}
	lbl := widget.NewLabel(status)
	lbl.Importance = widget.LowImportance
	rect := canvas.NewRectangle(bg)
	rect.CornerRadius = 10
	return container.NewStack(rect, container.NewPadded(lbl))
}

// makeRoleBadge returns a color-coded pill for a role name.
func makeRoleBadge(role string) fyne.CanvasObject {
	var bg color.Color
	switch strings.ToLower(role) {
	case "admin":
		c := dangerColor()
		bg = color.RGBA{R: c.(color.RGBA).R, G: c.(color.RGBA).G, B: c.(color.RGBA).B, A: 40}
	case "security_officer":
		c := warningColor()
		bg = color.RGBA{R: c.(color.RGBA).R, G: c.(color.RGBA).G, B: c.(color.RGBA).B, A: 40}
	default:
		c := accentColor()
		bg = color.RGBA{R: c.(color.RGBA).R, G: c.(color.RGBA).G, B: c.(color.RGBA).B, A: 40}
	}
	lbl := widget.NewLabel(role)
	lbl.Importance = widget.LowImportance
	rect := canvas.NewRectangle(bg)
	rect.CornerRadius = 10
	return container.NewStack(rect, container.NewPadded(lbl))
}

// categoryColor returns a deterministic color for a category name so the same
// category always gets the same badge color regardless of insertion order.
func categoryColor(cat string) color.Color {
	palette := []color.RGBA{
		{R: 30, G: 80, B: 160, A: 130},  // steel blue
		{R: 30, G: 110, B: 50, A: 130},  // forest green
		{R: 140, G: 95, B: 15, A: 130},  // dark amber
		{R: 100, G: 50, B: 160, A: 130}, // deep purple
		{R: 160, G: 40, B: 35, A: 130},  // dark red
		{R: 15, G: 120, B: 100, A: 130}, // dark teal
		{R: 160, G: 90, B: 0, A: 130},   // burnt orange
		{R: 140, G: 30, B: 90, A: 130},  // dark rose
	}
	if cat == "" || cat == "uncategorised" {
		return color.RGBA{R: 80, G: 80, B: 80, A: 120}
	}
	hash := 0
	for _, ch := range cat {
		hash = (hash*31 + int(ch)) & 0xffff
	}
	return palette[hash%len(palette)]
}

// ── Card / section helpers ────────────────────────────────────────────────────

// makeSectionCard wraps content in a widget.Card with consistent inner padding.
func makeSectionCard(title, subtitle string, content fyne.CanvasObject) *widget.Card {
	return widget.NewCard(title, subtitle, container.NewPadded(content))
}

// makeDivider returns a styled horizontal separator with a subtle accent tint.
func makeDivider() fyne.CanvasObject {
	sep := widget.NewSeparator()
	return sep
}

// ── Reveal password entry ─────────────────────────────────────────────────────

// makeRevealEntry wraps a password Entry in a row with a show/hide toggle button
// so users can verify what they are typing. Returns the container to embed in forms.
func makeRevealEntry(entry *widget.Entry) fyne.CanvasObject {
	var revealBtn *widget.Button
	revealed := false
	revealBtn = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
		revealed = !revealed
		entry.Password = !revealed
		if revealed {
			revealBtn.SetIcon(theme.VisibilityOffIcon())
		} else {
			revealBtn.SetIcon(theme.VisibilityIcon())
		}
		entry.Refresh()
	})
	revealBtn.Importance = widget.LowImportance
	return container.NewBorder(nil, nil, nil, revealBtn, makeFullWidthEntry(entry))
}

// ── Search bar ────────────────────────────────────────────────────────────────

// makeSearchBar returns a search Entry with a search icon on the left and a
// clear (✕) button on the right that appears whenever the field is non-empty.
func makeSearchBar(placeholder string, onChange func(string)) fyne.CanvasObject {
	entry := widget.NewEntry()
	entry.SetPlaceHolder(placeholder)

	searchIcon := widget.NewIcon(theme.SearchIcon())
	clearBtn := widget.NewButtonWithIcon("", theme.CancelIcon(), func() {
		entry.SetText("")
	})
	clearBtn.Importance = widget.LowImportance

	entry.OnChanged = func(v string) {
		onChange(v)
	}

	bar := container.NewBorder(nil, nil, container.NewCenter(searchIcon), clearBtn, entry)
	return bar
}

// ── Sidebar item helper ───────────────────────────────────────────────────────

// makeSidebarItem returns a full-width button styled as a nav item.
// When active, a tinted accent rectangle is shown behind the button label.
func makeSidebarItem(icon fyne.Resource, label string, active bool, fn func()) fyne.CanvasObject {
	btn := widget.NewButtonWithIcon(label, icon, fn)
	btn.Alignment = widget.ButtonAlignLeading
	btn.Importance = widget.LowImportance

	if active {
		highlight := canvas.NewRectangle(hoverBgColor())
		highlight.CornerRadius = 6
		return container.NewStack(highlight, btn)
	}
	return btn
}

// ── Password strength bar ─────────────────────────────────────────────────────

// makePasswordStrengthBar returns a thin 5-segment colored bar + label pair.
// Call update(password) on every keystroke.
func makePasswordStrengthBar() (bar fyne.CanvasObject, update func(pwd string)) {
	label := makeMutedLabel("Enter a password")

	inactive := color.RGBA{R: 60, G: 60, B: 60, A: 255}
	scoreColors := [5]color.RGBA{
		{R: 220, G: 53, B: 69, A: 255},  // 1 — red
		{R: 255, G: 140, B: 0, A: 255},  // 2 — orange
		{R: 255, G: 193, B: 7, A: 255},  // 3 — yellow
		{R: 40, G: 167, B: 69, A: 255},  // 4 — green
		{R: 0, G: 200, B: 83, A: 255},   // 5 — bright green
	}

	rects := make([]*canvas.Rectangle, 5)
	objs := make([]fyne.CanvasObject, 5)
	for i := range rects {
		r := canvas.NewRectangle(inactive)
		r.SetMinSize(fyne.NewSize(0, 5))
		r.CornerRadius = 3
		rects[i] = r
		objs[i] = r
	}
	segRow := container.NewGridWithColumns(5, objs...)

	updateFn := func(pwd string) {
		score := 0
		if len(pwd) >= 12 {
			score++
		}
		if strings.ContainsAny(pwd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			score++
		}
		if strings.ContainsAny(pwd, "abcdefghijklmnopqrstuvwxyz") {
			score++
		}
		if strings.ContainsAny(pwd, "0123456789") {
			score++
		}
		if strings.ContainsAny(pwd, "!@#$%^&*()_+-=[]{}|;':\",./<>?") {
			score++
		}
		for i, r := range rects {
			if i < score {
				r.FillColor = scoreColors[score-1]
			} else {
				r.FillColor = inactive
			}
			r.Refresh()
		}
		switch score {
		case 0, 1:
			label.SetText("Weak")
			label.Importance = widget.DangerImportance
		case 2:
			label.SetText("Fair")
			label.Importance = widget.WarningImportance
		case 3:
			label.SetText("Good")
			label.Importance = widget.MediumImportance
		case 4:
			label.SetText("Strong")
			label.Importance = widget.SuccessImportance
		case 5:
			label.SetText("Very Strong")
			label.Importance = widget.SuccessImportance
		}
		label.Refresh()
	}

	row := container.NewBorder(nil, nil, nil, container.NewCenter(label), segRow)
	return row, updateFn
}

// ── Width enforcer ────────────────────────────────────────────────────────────

// minWidth returns an invisible rectangle that enforces a minimum width.
func minWidth(w float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(w, 1))
	return r
}

// ── Icon with fallback ────────────────────────────────────────────────────────

// categoryIcon returns a theme icon that represents a secret category.
func categoryIcon(cat string) fyne.Resource {
	switch strings.ToLower(cat) {
	case "login", "password", "account":
		return theme.AccountIcon()
	case "api", "api_key", "token", "key":
		return theme.ComputerIcon()
	case "note", "notes", "secure note":
		return theme.DocumentIcon()
	case "card", "credit_card", "bank", "payment":
		return theme.StorageIcon()
	case "wifi", "network":
		return theme.ViewRefreshIcon()
	case "email", "mail":
		return theme.MailComposeIcon()
	default:
		return theme.DocumentIcon()
	}
}

func iconOrFallback(res fyne.Resource, fallback fyne.Resource) fyne.Resource {
	if res != nil {
		return res
	}
	return fallback
}

// ── Copy-to-clipboard row ─────────────────────────────────────────────────────

// makeCopyRow renders a label row with a small copy button on the right.
func makeCopyRow(fieldLabel, value string, icon fyne.Resource, copyFn func()) fyne.CanvasObject {
	var iconObj fyne.CanvasObject
	if icon != nil {
		iconObj = container.NewCenter(widget.NewIcon(icon))
	} else {
		placeholder := canvas.NewRectangle(color.Transparent)
		placeholder.SetMinSize(fyne.NewSize(20, 20))
		iconObj = placeholder
	}
	lbl := widget.NewLabelWithStyle(fieldLabel, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	val := widget.NewLabel(value)
	val.Importance = widget.LowImportance
	val.Truncation = fyne.TextTruncateEllipsis

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), copyFn)
	copyBtn.Importance = widget.LowImportance

	return container.NewBorder(nil, nil,
		container.NewHBox(iconObj, lbl),
		copyBtn,
		val,
	)
}

// ── Error/info banner ─────────────────────────────────────────────────────────

// makeDangerBanner returns a danger-importance label, initially hidden.
func makeDangerBanner(text string) *widget.Label {
	l := widget.NewLabelWithStyle(text, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	l.Importance = widget.DangerImportance
	l.Hide()
	return l
}

// passwordComplexityError returns a non-empty error string if pwd does not meet
// the minimum complexity policy (uppercase, lowercase, digit, special char).
// Returns "" if the password is acceptable.
func passwordComplexityError(pwd string) string {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range pwd {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return "Password must contain at least one uppercase letter"
	}
	if !hasLower {
		return "Password must contain at least one lowercase letter"
	}
	if !hasDigit {
		return "Password must contain at least one digit"
	}
	if !hasSpecial {
		return "Password must contain at least one special character"
	}
	return ""
}

// makeErrorLabel returns a centered danger-importance label for form errors.
func makeErrorLabel() *widget.Label {
	l := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	l.Importance = widget.DangerImportance
	return l
}

// ── Action button bar ─────────────────────────────────────────────────────────

// makeButtonBar returns a centered HBox of buttons with spacers on each side.
func makeButtonBar(btns ...fyne.CanvasObject) fyne.CanvasObject {
	items := []fyne.CanvasObject{layout.NewSpacer()}
	items = append(items, btns...)
	items = append(items, layout.NewSpacer())
	return container.NewHBox(items...)
}

// ── Page / auth card helpers ──────────────────────────────────────────────────

// makePageHeader returns the standard page header used by all main-pane screens.
// action is an optional CTA widget placed at the far right; pass nil to omit.
func makePageHeader(title, subtitle string, action fyne.CanvasObject) fyne.CanvasObject {
	titleLbl := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subLbl := makeMutedLabel(subtitle)
	left := container.NewVBox(titleLbl, subLbl)
	if action != nil {
		return container.NewPadded(container.NewVBox(
			container.NewBorder(nil, nil, nil, action, left),
			widget.NewSeparator(),
		))
	}
	return container.NewPadded(container.NewVBox(left, widget.NewSeparator()))
}

// makeAuthCard wraps auth-screen content in a card-style container without
// the double-border caused by nesting widget.Card inside another card layout.
func makeAuthCard(headingText, subText string, body fyne.CanvasObject) fyne.CanvasObject {
	heading := widget.NewLabelWithStyle(headingText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	var headerContent fyne.CanvasObject
	if subText != "" {
		headerContent = container.NewVBox(heading, makeMutedLabel(subText))
	} else {
		headerContent = heading
	}
	return widget.NewCard("", "", container.NewVBox(
		container.NewPadded(headerContent),
		widget.NewSeparator(),
		body,
	))
}

// makeFullWidthEntry wraps an entry in a Border layout so it expands to fill
// available width instead of collapsing to its intrinsic minimum size.
func makeFullWidthEntry(e fyne.CanvasObject) fyne.CanvasObject {
	return container.NewBorder(nil, nil, nil, nil, e)
}

// makeSectionTitle returns a bold label followed by a separator — used as an
// inline section divider inside form cards.
func makeSectionTitle(text string) fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	lbl.Importance = widget.MediumImportance
	return container.NewVBox(lbl, widget.NewSeparator())
}

// ── Scroll helpers ────────────────────────────────────────────────────────────

// boundedScroll wraps content in a VScroll whose MinSize height is 1 px so
// AppTabs never grows the window when more rows are added.
func boundedScroll(content fyne.CanvasObject) *container.Scroll {
	s := container.NewVScroll(content)
	s.SetMinSize(fyne.NewSize(0, 1))
	return s
}

// boundedTabContent wraps a tab's root widget in a bidirectional scroll with
// min-size (1,1) to prevent wide headers from locking the window's minimum width.
func boundedTabContent(content fyne.CanvasObject) fyne.CanvasObject {
	s := container.NewScroll(content)
	s.SetMinSize(fyne.NewSize(1, 1))
	return s
}

// ── Category filter chip row ──────────────────────────────────────────────────

// makeCategoryFilterRow builds a scrollable row of filter buttons.
// The active button is highlighted; "All" is active by default.
func makeCategoryFilterRow(categories []string, onSelect func(cat string)) fyne.CanvasObject {
	items := make([]fyne.CanvasObject, 0, len(categories)+1)
	var allBtns []*widget.Button

	setActive := func(idx int) {
		for i, b := range allBtns {
			if i == idx {
				b.Importance = widget.HighImportance
			} else {
				b.Importance = widget.LowImportance
			}
			b.Refresh()
		}
	}

	allBtn := widget.NewButton("All", nil)
	allBtn.Importance = widget.HighImportance
	allBtns = append(allBtns, allBtn)
	allBtn.OnTapped = func() { setActive(0); onSelect("") }
	items = append(items, allBtn)

	for i, cat := range categories {
		cat := cat
		idx := i + 1
		btn := widget.NewButton(cat, nil)
		btn.Importance = widget.LowImportance
		allBtns = append(allBtns, btn)
		btn.OnTapped = func() { setActive(idx); onSelect(cat) }
		items = append(items, btn)
	}

	return container.NewHScroll(container.NewHBox(items...))
}
