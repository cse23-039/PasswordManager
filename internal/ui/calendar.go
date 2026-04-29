package ui

// calendar.go — a month-navigation calendar dialog with integrated time picker.
// Fyne has no built-in datetime picker; this builds one from grid layouts,
// flat buttons and Select widgets.

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// showCalendarDialog opens a month-view calendar dialog with an integrated
// time picker (hour + minute selects).  The user picks a day, adjusts the
// time, then clicks "Apply".
//
// initial sets the pre-selected datetime (pass time.Time{} to default to now).
// onPick is called with the chosen datetime in UTC; it is NOT called on dismiss.
func showCalendarDialog(title string, initial time.Time, win fyne.Window, onPick func(time.Time)) {
	now := time.Now().UTC()
	if initial.IsZero() {
		initial = now
	}
	initial = initial.UTC()

	// cur is always the 1st of the displayed month
	cur := time.Date(initial.Year(), initial.Month(), 1, 0, 0, 0, 0, time.UTC)

	// selectedDay tracks which day-of-month (1–lastDay) is highlighted.
	// Starts on initial's day, clamped to the current month if needed.
	selectedDay := initial.Day()

	body := container.NewMax()
	monthLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	// ── Hour select ─────────────────────────────────────────────
	hours := make([]string, 24)
	for i := range hours {
		hours[i] = fmt.Sprintf("%02d", i)
	}
	hourSel := widget.NewSelect(hours, nil)
	hourSel.Selected = fmt.Sprintf("%02d", initial.Hour())

	// ── Minute select ──────────────────────────────────────────
	mins := make([]string, 60)
	for i := range mins {
		mins[i] = fmt.Sprintf("%02d", i)
	}
	minSel := widget.NewSelect(mins, nil)
	minSel.Selected = fmt.Sprintf("%02d", initial.Minute())

	// dlg assigned below; closures capture by reference.
	var dlg dialog.Dialog
	var renderMonth func()

	renderMonth = func() {
		monthLabel.SetText(fmt.Sprintf("%s %d", cur.Month().String(), cur.Year()))

		dayNames := []string{"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"}
		dayHeaders := make([]fyne.CanvasObject, 7)
		for i, dn := range dayNames {
			dayHeaders[i] = widget.NewLabelWithStyle(dn, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		}

		offset := int(cur.Weekday()) // 0 = Sunday
		lastDay := time.Date(cur.Year(), cur.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()

		// Clamp selected day to valid range for this month
		if selectedDay > lastDay {
			selectedDay = lastDay
		}

		cells := make([]fyne.CanvasObject, 0, offset+lastDay)
		for i := 0; i < offset; i++ {
			cells = append(cells, widget.NewLabel(""))
		}
		for d := 1; d <= lastDay; d++ {
			d := d
			btn := widget.NewButton(fmt.Sprintf("%d", d), func() {
				selectedDay = d
				renderMonth() // re-render to move highlight
			})
			if d == selectedDay {
				btn.Importance = widget.HighImportance
			} else {
				btn.Importance = widget.LowImportance
			}
			cells = append(cells, btn)
		}
		for len(cells)%7 != 0 {
			cells = append(cells, widget.NewLabel(""))
		}

		body.Objects = []fyne.CanvasObject{
			container.NewVBox(
				container.New(layout.NewGridLayout(7), dayHeaders...),
				widget.NewSeparator(),
				container.New(layout.NewGridLayout(7), cells...),
			),
		}
		body.Refresh()
	}

	prevBtn := widget.NewButton("<", func() {
		cur = cur.AddDate(0, -1, 0)
		renderMonth()
	})
	nextBtn := widget.NewButton(">", func() {
		cur = cur.AddDate(0, 1, 0)
		renderMonth()
	})

	navRow := container.NewBorder(nil, nil, prevBtn, nextBtn, monthLabel)
	renderMonth()

	applyBtn := widget.NewButton("Apply", func() {
		h := 0
		m := 0
		if n, _ := fmt.Sscanf(hourSel.Selected, "%d", &h); n != 1 {
			h = 0 // fallback to midnight on parse failure
		}
		if n, _ := fmt.Sscanf(minSel.Selected, "%d", &m); n != 1 {
			m = 0
		}
		picked := time.Date(cur.Year(), cur.Month(), selectedDay, h, m, 0, 0, time.UTC)
		onPick(picked)
		dlg.Hide()
	})
	applyBtn.Importance = widget.HighImportance

	timeRow := container.NewHBox(
		widget.NewLabelWithStyle("Time:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		hourSel,
		widget.NewLabel(":"),
		minSel,
		layout.NewSpacer(),
		applyBtn,
	)

	content := container.NewVBox(
		navRow,
		widget.NewSeparator(),
		body,
		widget.NewSeparator(),
		timeRow,
	)
	dlg = dialog.NewCustom(title, "Cancel", content, win)
	dlg.Resize(fyne.NewSize(380, 380))
	dlg.Show()
}
