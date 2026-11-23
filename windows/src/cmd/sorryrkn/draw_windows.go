//go:build windows

package main

import (
	"fmt"
	"math"
	"sorryrkn/internal/core"
	"strings"
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
	flags := uintptr(0x20 | 0x800 | 0x8000) // DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS
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
	screenDC := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
	defer call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
	var bounds rect
	call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
	w := bounds.Right - bounds.Left
	h := bounds.Bottom - bounds.Top
	dc := screenDC
	var memDC, memBM, oldBM uintptr
	if w > 0 && h > 0 {
		memDC = call(gdi, "CreateCompatibleDC", screenDC)
		if memDC != 0 {
			memBM = call(gdi, "CreateCompatibleBitmap", screenDC, uintptr(w), uintptr(h))
			if memBM != 0 {
				oldBM = call(gdi, "SelectObject", memDC, memBM)
				dc = memDC
			} else {
				call(gdi, "DeleteDC", memDC)
				memDC = 0
			}
		}
	}
	paintScene(window, dc, bounds)
	if memDC != 0 {
		call(gdi, "BitBlt", screenDC, 0, 0, uintptr(w), uintptr(h), memDC, 0, 0, 0x00CC0020)
		call(gdi, "SelectObject", memDC, oldBM)
		call(gdi, "DeleteObject", memBM)
		call(gdi, "DeleteDC", memDC)
	}
}

func paintDC(window, dc uintptr) {
	if dc == 0 {
		return
	}
	var bounds rect
	call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
	paintScene(window, dc, bounds)
}

func paintScene(window, dc uintptr, bounds rect) {
	fill(dc, bounds, BG)

	// 1. Header: SorryRKN + version badge
	text(dc, "SorryRKN", 22, 16, 114, 32, 22, WHITE, 600, false)
	rounded(dc, logicalRect(136, 21, 52, 22), PANEL_ELEV, BORDER, 6)
	text(dc, "v"+core.Version, 136, 23, 52, 18, 11, GRAY, 500, true)

	// 2. Top 3-Segment Mode Bar background
	rounded(dc, logicalRect(22, 60, 408, 38), PANEL, BORDER, 11)

	if currentConfig().VPNMode {
		paintVPN(dc)
		return
	}

	// 3. Tactical Hero Card
	statusTitle, detail := "Выключено", "Нажмите кнопку для запуска"
	dotColor := DIM
	heroStroke := BORDER
	if engine != nil {
		s := engine.Snapshot()
		switch s.Status {
		case "starting":
			statusTitle = "Подключение…"
			detail = s.Detail
			dotColor = AMBER
			heroStroke = AMBER
		case "stopping":
			statusTitle = "Выключение…"
			detail = s.Detail
			dotColor = AMBER
		case "on":
			statusTitle = "Подключено"
			detail = "Работает в фоне · переключение на лету"
			dotColor = GREEN
			heroStroke = GREEN
		case "partial":
			statusTitle = "Частичный доступ"
			if !s.DPI && s.Telegram && !s.Extras && !s.Instagram {
				statusTitle = "Только Telegram"
			}
			detail = s.Detail
			dotColor = AMBER
			heroStroke = AMBER
		case "error":
			statusTitle = "Не удалось включить"
			detail = s.Error
			dotColor = RED
			heroStroke = RED
		}
	}
	rounded(dc, logicalRect(22, 110, 408, 96), PANEL, heroStroke, 18)
	ellipse(dc, logicalRect(118, 141, 8, 8), dotColor, dotColor)
	text(dc, statusTitle, 132, 132, 240, 26, 18, WHITE, 600, false)
	text(dc, detail, 118, 160, 254, 22, 12, GRAY, 400, false)

	// 4. 4-Row Tactical Service Panel
	rounded(dc, logicalRect(22, 218, 408, 248), PANEL, BORDER, 18)
	line(dc, 38, 280, 414, 280, BORDER)
	line(dc, 38, 342, 414, 342, BORDER)
	line(dc, 38, 404, 414, 404, BORDER)

	// Telegram Row static text (row 3)
	text(dc, "Telegram MTProto", 38, 350, 314, 22, 14, WHITE, 600, false)
	telegramDetail := "Локальный прокси · 127.0.0.1:1443"
	if engine != nil && (engine.Snapshot().Status == "on" || engine.Snapshot().Status == "partial") && engine.Snapshot().Telegram {
		health := engine.Snapshot().TelegramHealth
		switch health.State {
		case "ready":
			telegramDetail = fmt.Sprintf("Ответ получен · %.0f мс", health.LatencyMS)
		case "degraded":
			telegramDetail = "Доступна часть дата-центров"
		case "unavailable":
			telegramDetail = "Нет ответа · ищем маршрут"
		default:
			telegramDetail = "Проверяем DC1–DC5…"
		}
	}
	text(dc, telegramDetail, 38, 374, 314, 18, 11, GRAY, 400, false)

	// 5. Subtle footer
	text(dc, "Закрытие окна сворачивает пульт в системный трей", 22, 533, 408, 20, 11, DIM, 400, true)
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
	if drawVPNButton(d, width, height) {
		return
	}
	if c.VPNMode && vpnSession.Active() {
		state = "on"
	}
	switch int(d.ID) {
	case PowerID:
		fill(dc, d.Rect, PANEL)
		on := state == "on" || state == "partial"
		ring := BORDER_STRONG
		if on {
			ring = GREEN
		} else if state == "starting" || state == "stopping" {
			ring = AMBER
		}
		color, mark := PANEL_ELEV, WHITE
		if on {
			color, mark = WHITE, BG
		}
		ellipse(dc, logicalRect(1, 1, width-2, height-2), PANEL, ring)
		ellipse(dc, logicalRect(5, 5, width-10, height-10), color, color)
		drawMark(dc, width/2, height/2, width, mark)
	case QuickRetestID:
		fill(dc, d.Rect, PANEL)
		rounded(dc, logicalRect(0, 0, width, height), PANEL_ELEV, BORDER_STRONG, 11)
		text(dc, "↻", 0, 5, width, height-6, 18, WHITE, 600, true)
	case QuickAppsID:
		fill(dc, d.Rect, BG)
		label := "Приложения"
		stroke := BORDER
		fg := WHITE
		if n := len(c.ExcludedApps); n > 0 {
			label = fmt.Sprintf("Прилож. (%d)", n)
			stroke = GREEN
			fg = GREEN
		}
		rounded(dc, logicalRect(0, 0, width, height), PANEL, stroke, 10)
		text(dc, label, 0, 7, width, height-8, 12, fg, 600, true)
	case QuickRulesID:
		fill(dc, d.Rect, BG)
		rounded(dc, logicalRect(0, 0, width, height), PANEL, BORDER, 10)
		text(dc, "Правила", 0, 7, width, height-8, 12, WHITE, 600, true)
	case MenuID:
		fill(dc, d.Rect, BG)
		rounded(dc, logicalRect(0, 0, width, height), PANEL, BORDER, 10)
		text(dc, "···", 0, 2, width, height-4, 20, GRAY, 600, true)
	case DpiID, InstagramID, TelegramID, ExtrasID:
		fill(dc, d.Rect, PANEL)
		enabled := c.DPI
		switch int(d.ID) {
		case InstagramID:
			enabled = c.InstagramEnabled()
		case TelegramID:
			enabled = c.Telegram
		case ExtrasID:
			enabled = c.Extras
		}
		track, thumb := BORDER, GRAY
		x := 3
		if enabled {
			track = WHITE
			thumb = BG
			x = 26
		}
		rounded(dc, logicalRect(1, 1, 52, 28), track, track, 14)
		ellipse(dc, logicalRect(x, 3, 23, 24), thumb, thumb)
	case ProfileID:
		fill(dc, d.Rect, PANEL)
		text(dc, "YouTube, Discord и сайты  ›", 0, 4, width, 22, 14, WHITE, 600, false)
		method := "Авто · локальный обход DPI"
		if c.Method != "auto" {
			method = "Вручную · " + c.Method
		}
		if engine != nil && engine.Snapshot().Profile != "" && (state == "on" || state == "partial" || state == "starting") {
			prefix := "Авто"
			if c.Method != "auto" {
				prefix = "Вручную"
			}
			method = prefix + " · " + engine.Snapshot().Profile
		}
		text(dc, method, 0, 28, width, 18, 11, GRAY, 400, false)
	case InstaRowID:
		fill(dc, d.Rect, PANEL)
		text(dc, "Instagram и Meta  ›", 0, 4, width, 22, 14, WHITE, 600, false)
		sub := "Локальный обход DPI · свой IP"
		if (state == "on" || state == "partial") && c.InstagramEnabled() {
			sub = "Активен · свой IP"
		}
		if n := len(c.DPIDomains); n > 0 {
			sub += fmt.Sprintf(" · +%d своих", n)
		}
		text(dc, sub, 0, 28, width, 18, 11, GRAY, 400, false)
	case DnsRowID:
		fill(dc, d.Rect, PANEL)
		text(dc, "Нейросети · Гео-DNS  ›", 0, 4, width, 22, 14, WHITE, 600, false)
		dnsTag := strings.ToUpper(c.DNSProfile)
		if dnsTag == "" {
			dnsTag = "COMSS"
		}
		sub := dnsTag + " · ChatGPT · Claude · Gemini"
		if engine != nil && (state == "on" || state == "partial") && c.Extras {
			for _, svc := range engine.Snapshot().Services {
				if svc.Name == "ChatGPT" {
					if svc.OK {
						sub = dnsTag + " · ChatGPT доступен"
					} else {
						sub = dnsTag + " · ChatGPT не подтверждён"
					}
					break
				}
			}
		}
		text(dc, sub, 0, 28, width, 18, 11, GRAY, 400, false)
	case LinkID:
		fill(dc, d.Rect, BG)
		rounded(dc, logicalRect(0, 0, width, height), PANEL, BORDER, 12)
		color := GRAY
		if engine != nil && engine.Snapshot().Telegram && (state == "on" || state == "partial") {
			color = WHITE
		}
		text(dc, "Telegram  ↗", 0, 11, width, 22, 13, color, 600, true)
	case DiagBtnID:
		fill(dc, d.Rect, BG)
		rounded(dc, logicalRect(0, 0, width, height), PANEL, BORDER, 12)
		text(dc, "Диагностика", 0, 11, width, 22, 13, WHITE, 600, true)
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

func drawMark(dc uintptr, cx, cy, btnWidth, color int) {
	b := call(gdi, "CreateSolidBrush", uintptr(color))
	oldB := call(gdi, "SelectObject", dc, b)
	oldP := call(gdi, "SelectObject", dc, call(gdi, "GetStockObject", 8))
	factor := float64(btnWidth) / 112.0
	if factor < 0.45 {
		factor = 0.45
	}
	xy := func(x, y float64) point {
		return point{dp(cx) + int32(math.Round((x-24)*factor*scale)), dp(cy) + int32(math.Round((y-24)*factor*scale))}
	}
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
	penW := dp(2)
	if btnWidth > 100 {
		penW = dp(3)
	}
	p := call(gdi, "CreatePen", 0, uintptr(penW), uintptr(color))
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
