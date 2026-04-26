package ui

// resizable_cols.go — drag-to-resize column headers for tabular views.
//
// Design: every header cell and every data-row container uses a layout that
// reads cw.widths on EVERY layout pass.  A drag therefore only needs to:
//   1. update cw.widths[i] / cw.widths[next]
//   2. call cw.RefreshAll()   ← Refresh on each registered container
//
// No container rebuild is needed; the existing objects just re-layout.

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const minColWidth float32 = 50

// ── colWidths ────────────────────────────────────────────────────────────────

type colWidths struct {
	widths            []float32
	tracked           []*fyne.Container        // all live containers (header cells + row containers)
	onResize          func()                   // optional: called when filter needs to reload data
	lastRefresh       time.Time                // throttle: skip frames closer than 16ms
	onColWidthChanged func(col int, w float32) // optional: notified on every width change (e.g. to drive widget.Table)
}

func newColWidths(widths []float32) *colWidths {
	cp := make([]float32, len(widths))
	copy(cp, widths)
	return &colWidths{widths: cp}
}

// track registers a container so RefreshAll can reach it.
func (cw *colWidths) track(c *fyne.Container) {
	cw.tracked = append(cw.tracked, c)
}

// clearRows removes all tracked row containers (call before rebuilding rows on
// filter change).  Header cells stay registered — they are created once.
func (cw *colWidths) clearRows(keepFirst int) {
	cw.tracked = cw.tracked[:keepFirst]
}

// RefreshAll calls Refresh on every registered container so they all re-layout
// with the current widths values. Calls during a drag are throttled to ~60 fps
// to avoid saturating the renderer; call forceRefresh() to bypass the throttle
// (used by DragEnd to guarantee the final position is always rendered).
func (cw *colWidths) RefreshAll() {
	if time.Since(cw.lastRefresh) < 16*time.Millisecond {
		return
	}
	cw.forceRefresh()
}

func (cw *colWidths) forceRefresh() {
	cw.lastRefresh = time.Now()
	for _, c := range cw.tracked {
		c.Refresh()
	}
}

// ── colLayout ────────────────────────────────────────────────────────────────

// colLayout lays out N children left-to-right; child i gets width cw.widths[i]
// and full container height.  MinSize reports the total width × max cell height.
// Because it reads cw.widths (not a cached value) on every call, calling
// container.Refresh() after a width change is sufficient to re-layout.
type colLayout struct {
	cw    *colWidths
	start int // index of the first column this container covers
}

func (l *colLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	x := float32(0)
	for i, o := range objs {
		col := l.start + i
		w := float32(0)
		if col < len(l.cw.widths) {
			w = l.cw.widths[col]
		}
		o.Move(fyne.NewPos(x, 0))
		o.Resize(fyne.NewSize(w, size.Height))
		x += w
	}
}

func (l *colLayout) MinSize(objs []fyne.CanvasObject) fyne.Size {
	totalW := float32(0)
	maxH := float32(0)
	for i, o := range objs {
		col := l.start + i
		if col < len(l.cw.widths) {
			totalW += l.cw.widths[col]
		} else {
			totalW += o.MinSize().Width
		}
		if h := o.MinSize().Height; h > maxH {
			maxH = h
		}
	}
	return fyne.NewSize(totalW, maxH)
}

// ── resizeHandle ─────────────────────────────────────────────────────────────

type resizeHandle struct {
	widget.BaseWidget
	onDrag func(dx float32)
	onEnd  func()
}

func newResizeHandle(onDrag func(dx float32), onEnd func()) *resizeHandle {
	h := &resizeHandle{onDrag: onDrag, onEnd: onEnd}
	h.ExtendBaseWidget(h)
	return h
}

func (h *resizeHandle) CreateRenderer() fyne.WidgetRenderer {
	bar := canvas.NewRectangle(theme.DisabledColor())
	bar.SetMinSize(fyne.NewSize(2, 0))
	return widget.NewSimpleRenderer(bar)
}

func (h *resizeHandle) MinSize() fyne.Size         { return fyne.NewSize(8, 0) }
func (h *resizeHandle) Dragged(ev *fyne.DragEvent) { h.onDrag(ev.Dragged.DX) }
func (h *resizeHandle) DragEnd() {
	if h.onEnd != nil {
		h.onEnd()
	}
}
func (h *resizeHandle) Cursor() desktop.Cursor { return desktop.HResizeCursor }

// ── handleOverlayLayout ──────────────────────────────────────────────────────

// handleOverlayLayout positions N-1 resize handles at each column's right edge
// so they overlay the header cells without contributing to row positioning.
type handleOverlayLayout struct {
	cw *colWidths
}

func (l *handleOverlayLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	x := float32(0)
	for i, o := range objs {
		if i < len(l.cw.widths) {
			x += l.cw.widths[i]
		}
		hw := o.MinSize().Width
		o.Move(fyne.NewPos(x-hw/2, 0))
		o.Resize(fyne.NewSize(hw, size.Height))
	}
}

func (l *handleOverlayLayout) MinSize(_ []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(0, 0)
}

// ── buildResizableHeader ─────────────────────────────────────────────────────

// buildResizableHeader creates a header row whose cells use the same colLayout
// as data rows — guaranteeing pixel-perfect column alignment.  Resize handles
// are overlaid at column edges so they don't shift cell positions.
//
// Returns:
//   - hdrRow: a Stack of the cell row and handle overlay
//   - hdrCellCount: number of containers registered in cw (always 2) so the
//     caller can pass this to cw.clearRows(hdrCellCount) before rebuilding rows
func buildResizableHeader(cols []string, cw *colWidths) (hdrRow *fyne.Container, hdrCellCount int) {
	cells := make([]fyne.CanvasObject, len(cols))
	for i, col := range cols {
		cells[i] = bold(col)
	}
	return buildResizableHeaderCustom(cells, cw)
}

// ── buildResizableHeaderCustom ───────────────────────────────────────────────

// buildResizableHeaderCustom is like buildResizableHeader but accepts
// pre-built fyne.CanvasObject items as header cells instead of plain strings.
// Use this when you need clickable buttons (e.g. sortable columns) in the header.
func buildResizableHeaderCustom(cells []fyne.CanvasObject, cw *colWidths) (hdrRow *fyne.Container, hdrCellCount int) {
	// Header cells use the identical colLayout as data rows — perfect alignment.
	headerRow := container.New(&colLayout{cw: cw, start: 0}, cells...)
	cw.track(headerRow)

	// Overlay resize handles at column right edges without displacing cells.
	handles := make([]fyne.CanvasObject, len(cells)-1)
	for i := range handles {
		i := i
		next := i + 1
		handle := newResizeHandle(
			func(dx float32) {
				if dx > 0 {
					if avail := cw.widths[next] - minColWidth; dx > avail {
						dx = avail
					}
				} else {
					if avail := cw.widths[i] - minColWidth; -dx > avail {
						dx = -avail
					}
				}
				cw.widths[i] += dx
				cw.widths[next] -= dx
				if cw.onColWidthChanged != nil {
					cw.onColWidthChanged(i, cw.widths[i])
					cw.onColWidthChanged(next, cw.widths[next])
				}
				cw.RefreshAll()
			},
			func() { cw.forceRefresh() },
		)
		handles[i] = handle
	}
	overlay := container.New(&handleOverlayLayout{cw: cw}, handles...)
	cw.track(overlay)

	// 2 containers tracked: headerRow + overlay
	return container.NewStack(headerRow, overlay), 2
}

// ── rowWithWidths ─────────────────────────────────────────────────────────────

// rowWithWidths creates a single data row container using colLayout.
// The container is registered with cw so RefreshAll() re-layouts it on drag.
// Call cw.clearRows(hdrCellCount) before rebuilding all rows on a filter change.
func rowWithWidths(cells []fyne.CanvasObject, cw *colWidths) *fyne.Container {
	c := container.New(&colLayout{cw: cw, start: 0}, cells...)
	cw.track(c)
	return c
}

// truncLabel returns a label that truncates with an ellipsis when its
// allocated width is smaller than the text.  Use this for all data-row cells
// so long content never bleeds into the next column.
func truncLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Truncation = fyne.TextTruncateEllipsis
	return l
}
