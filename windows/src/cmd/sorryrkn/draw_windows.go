//go:build windows

package main

import (
	"math"
	"unsafe"
)

type paintstruct struct {
	Hdc                uintptr
	Erase              int32
	Rect               rect
	Restore, IncUpdate int32
	Reserved           [32]byte
}

func font(size, weight int) uintptr {
	key := size*1000 + weight
	if f := fonts[key]; f != 0 {
		return f
	}
	height := -dp(size)
	f := call(gdi, "CreateFontW", uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(u("Segoe UI"))))
	fonts[key] = f
	return f
}
func text(dc uintptr, value string, x, y, w, h, size, color, weight int, center bool) {
	old := call(gdi, "SelectObject", dc, font(size, weight))
	defer call(gdi, "SelectObject", dc, old)
	call(gdi, "SetBkMode", dc, 1)
	call(gdi, "SetTextColor", dc, uintptr(color))
	r := rect{dp(x), dp(y), dp(x + w), dp(y + h)}
	flags := uintptr(0x20 | 0x800)
	if center {
		flags |= 1
	}
	call(user, "DrawTextW", dc, uintptr(unsafe.Pointer(u(value))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags)
}
func fill(dc uintptr, r rect, color int) {
	b := call(gdi, "CreateSolidBrush", uintptr(color))
	call(user, "FillRect", dc, uintptr(unsafe.Pointer(&r)), b)
	call(gdi, "DeleteObject", b)
}
func rounded(dc uintptr, r rect, color, stroke, radius int) {
	b := call(gdi, "CreateSolidBrush", uintptr(color))
	p := call(gdi, "CreatePen", 0, uintptr(dp(1)), uintptr(stroke))
	oldB := call(gdi, "SelectObject", dc, b)
	oldP := call(gdi, "SelectObject", dc, p)
	call(gdi, "RoundRect", dc, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom), uintptr(dp(radius*2)), uintptr(dp(radius*2)))
	call(gdi, "SelectObject", dc, oldB)
	call(gdi, "SelectObject", dc, oldP)
	call(gdi, "DeleteObject", b)
	call(gdi, "DeleteObject", p)
}
func ellipse(dc uintptr, r rect, color, stroke int) {
	b := call(gdi, "CreateSolidBrush", uintptr(color))
	p := call(gdi, "CreatePen", 0, uintptr(dp(1)), uintptr(stroke))
	oldB := call(gdi, "SelectObject", dc, b)
	oldP := call(gdi, "SelectObject", dc, p)
	call(gdi, "Ellipse", dc, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom))
	call(gdi, "SelectObject", dc, oldB)
	call(gdi, "SelectObject", dc, oldP)
	call(gdi, "DeleteObject", b)
	call(gdi, "DeleteObject", p)
}
func line(dc uintptr, x1, y1, x2, y2 int, color int) {
	p := call(gdi, "CreatePen", 0, uintptr(dp(1)), uintptr(color))
	old := call(gdi, "SelectObject", dc, p)
	call(gdi, "MoveToEx", dc, uintptr(dp(x1)), uintptr(dp(y1)), 0)
	call(gdi, "LineTo", dc, uintptr(dp(x2)), uintptr(dp(y2)))
	call(gdi, "SelectObject", dc, old)
	call(gdi, "DeleteObject", p)
}
func logicalRect(x, y, w, h int) rect { return rect{dp(x), dp(y), dp(x + w), dp(y + h)} }
func paint(window uintptr) {
	var ps paintstruct
	dc := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
	defer call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
	var bounds rect
	call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
	fill(dc, bounds, BG)
	text(dc, "ЛОКАЛЬНОЕ СОЕДИНЕНИЕ", 28, 26, 350, 20, 10, GRAY, 400, false)
	text(dc, "SorryRKN", 28, 50, 345, 44, 31, WHITE, 600, false)
	status, detail := "Выключено", "Нажмите, чтобы подключиться"
	if engine != nil {
		s := engine.Snapshot()
		switch s.Status {
		case "starting":
			status = "Подключение…"
			detail = s.Detail
		case "stopping":
			status = "Выключение…"
			detail = s.Detail
		case "on":
			status = "Соединение включено"
			detail = s.Detail
		case "partial":
			status = "Частичный доступ"
			if !s.DPI && s.Telegram && !s.Extras {
				status = "Только Telegram"
			}
			detail = s.Detail
		case "error":
			status = "Не удалось включить"
			detail = s.Error
		}
	}
	text(dc, status, 28, 311, 404, 32, 24, WHITE, 600, true)
	text(dc, detail, 24, 348, 412, 28, 12, GRAY, 400, true)
	rounded(dc, logicalRect(28, 386, 404, 181), PANEL, BORDER, 20)
	line(dc, 44, 447, 416, 447, BORDER)
	line(dc, 44, 507, 416, 507, BORDER)
	text(dc, "Telegram", 44, 458, 296, 24, 15, WHITE, 600, false)
	text(dc, "MTProto / WebSocket", 44, 482, 296, 18, 11, GRAY, 400, false)
	text(dc, "Нейросети и Instagram", 44, 518, 310, 24, 15, WHITE, 600, false)
	text(dc, "ChatGPT · Claude · Gemini · Instagram", 44, 542, 304, 18, 10, GRAY, 400, false)
	text(dc, "Закрытие окна — свернуть в трей", 28, 649, 404, 22, 11, GRAY, 400, true)
	text(dc, "WINDOWS  /  ЛОКАЛЬНЫЙ ОБХОД", 28, 682, 404, 18, 9, GRAY, 400, true)
}
func drawButton(d *drawitem) {
	dc := d.Hdc
	if dc == 0 {
		return
	}
	width := int(float64(d.Rect.Right-d.Rect.Left) / scale)
	height := int(float64(d.Rect.Bottom-d.Rect.Top) / scale)
	c := currentConfig()
	state := "off"
	if engine != nil {
		state = engine.Snapshot().Status
	}
	switch int(d.ID) {
	case PowerID:
		fill(dc, d.Rect, BG)
		on := state == "on" || state == "partial"
		color, mark := PANEL, WHITE
		if on {
			color, mark = WHITE, BG
		}
		ellipse(dc, logicalRect(2, 2, width-4, height-4), BG, BORDER)
		ellipse(dc, logicalRect(9, 9, width-18, height-18), color, color)
		drawMark(dc, width/2, height/2, mark)
	case DpiID, TelegramID, ExtrasID:
		fill(dc, d.Rect, PANEL)
		enabled := c.DPI
		if d.ID == TelegramID {
			enabled = c.Telegram
		}
		if d.ID == ExtrasID {
			enabled = c.Extras
		}
		track, thumb := BORDER, GRAY
		x := 3
		if enabled {
			track = WHITE
			thumb = BG
			x = 26
		}
		rounded(dc, logicalRect(1, 1, 55, 30), track, track, 16)
		ellipse(dc, logicalRect(x, 3, 25, 26), thumb, thumb)
	case LinkID:
		fill(dc, d.Rect, BG)
		rounded(dc, d.Rect, PANEL, BORDER, 14)
		color := GRAY
		if engine != nil && engine.Snapshot().Telegram {
			color = WHITE
		}
		text(dc, "Подключить Telegram  ↗", 0, 12, width, 24, 14, color, 500, true)
	case MenuID:
		fill(dc, d.Rect, BG)
		text(dc, "···", 0, 4, width, height, 28, GRAY, 500, true)
	case ProfileID:
		fill(dc, d.Rect, PANEL)
		text(dc, "Обход DPI", 0, 4, width, 24, 15, WHITE, 600, false)
		method := "Авто"
		if c.Method != "auto" {
			method = "Вручную"
		}
		if engine != nil && engine.Snapshot().Profile != "" {
			method = engine.Snapshot().Profile
		}
		text(dc, "YouTube · Discord · "+method, 0, 29, width, 17, 10, GRAY, 400, false)
	}
	if d.State&16 != 0 {
		r := d.Rect
		r.Left += dp(2)
		r.Top += dp(2)
		r.Right -= dp(2)
		r.Bottom -= dp(2)
		call(user, "DrawFocusRect", dc, uintptr(unsafe.Pointer(&r)))
	}
}
func drawMark(dc uintptr, cx, cy, color int) {
	b := call(gdi, "CreateSolidBrush", uintptr(color))
	oldB := call(gdi, "SelectObject", dc, b)
	oldP := call(gdi, "SelectObject", dc, call(gdi, "GetStockObject", 8))
	factor := 1.55
	xy := func(x, y float64) point { return point{dp(cx + int((x-24)*factor)), dp(cy + int((y-24)*factor))} }
	for _, shape := range [][][2]float64{{{31, 7}, {27, 16}, {18, 23}, {25, 29}, {22, 32}, {13, 25}, {14, 21}}, {{24, 22}, {34, 29}, {33, 33}, {16, 43}, {21, 34}, {29, 30}, {21, 25}}} {
		var points []point
		for _, v := range shape {
			points = append(points, xy(v[0], v[1]))
		}
		call(gdi, "Polygon", dc, uintptr(unsafe.Pointer(&points[0])), uintptr(len(points)))
	}
	call(gdi, "SelectObject", dc, oldB)
	call(gdi, "SelectObject", dc, oldP)
	call(gdi, "DeleteObject", b)
	p := call(gdi, "CreatePen", 0, uintptr(dp(3)), uintptr(color))
	oldP = call(gdi, "SelectObject", dc, p)
	for _, arc := range [][2]float64{{-90, -240}, {-63, 88}} {
		var points []point
		for i := 0; i < 40; i++ {
			a := (arc[0] + float64(i)*(arc[1]-arc[0])/39) * math.Pi / 180
			points = append(points, xy(24+17*math.Cos(a), 24+17*math.Sin(a)))
		}
		call(gdi, "Polyline", dc, uintptr(unsafe.Pointer(&points[0])), uintptr(len(points)))
	}
	call(gdi, "SelectObject", dc, oldP)
	call(gdi, "DeleteObject", p)
}
