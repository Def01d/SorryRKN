//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"sorryrkn/internal/core"
	"strings"
	"unsafe"
)

const RulesID = 209
const GeoEditID = 9001
const DirectEditID = 9002
const SaveRulesID = 9003
const CancelRulesID = 9004
const DpiEditID = 9005

var rulesWindow, dpiEdit, geoEdit, directEdit, ruleBrush uintptr
var rulesClassRegistered bool

func editRules() {
	if rulesWindow != 0 {
		call(user, "SetForegroundWindow", rulesWindow)
		return
	}
	if !rulesClassRegistered {
		wc := wndclass{Style: 3, WndProc: windows.NewCallback(rulesProc), Instance: instance, Icon: icon, SmallIcon: icon, Cursor: call(user, "LoadCursorW", 0, 32512), Class: u("SorryRKNRules")}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if call(user, "RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			errorMessage("Не удалось открыть редактор")
			return
		}
		rulesClassRegistered = true
	}
	ruleBrush = call(gdi, "CreateSolidBrush", PANEL)
	rulesWindow = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u("SorryRKNRules"))), uintptr(unsafe.Pointer(u("Мои ресурсы"))), 0x80c80000, 0x80000000, 0x80000000, uintptr(dp(640)), uintptr(dp(648)), hwnd, 0, instance, 0)
	if rulesWindow == 0 {
		call(gdi, "DeleteObject", ruleBrush)
		ruleBrush = 0
		errorMessage("Не удалось открыть редактор")
		return
	}
	dark := uint32(1)
	call(dwm, "DwmSetWindowAttribute", rulesWindow, 20, uintptr(unsafe.Pointer(&dark)), 4)
	c := currentConfig()
	create := func(class, label string, id, x, y, w, h int, style uintptr) uintptr {
		handle := call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(label))), 0x50010000|style, uintptr(dp(x)), uintptr(dp(y)), uintptr(dp(w)), uintptr(dp(h)), rulesWindow, uintptr(id), instance, 0)
		call(user, "SendMessageW", handle, 0x30, font(13, 400), 1)
		return handle
	}
	editStyle := uintptr(0x00800000 | 0x00200000 | 0x0004 | 0x0040 | 0x1000)
	// Multiline native edits retain keyboard, accessibility and clipboard support.
	dpiEdit = create("EDIT", strings.Join(c.DPIDomains, "\r\n"), DpiEditID, 24, 118, 576, 108, editStyle)
	geoEdit = create("EDIT", strings.Join(c.GeoDomains, "\r\n"), GeoEditID, 24, 264, 576, 108, editStyle)
	directEdit = create("EDIT", strings.Join(c.DirectDomains, "\r\n"), DirectEditID, 24, 410, 576, 108, editStyle)
	call(user, "SendMessageW", dpiEdit, 0xc5, core.MaxDomainText, 0)
	call(user, "SendMessageW", geoEdit, 0xc5, core.MaxDomainText, 0)
	call(user, "SendMessageW", directEdit, 0xc5, core.MaxDomainText, 0)
	create("BUTTON", "Сохранить", SaveRulesID, 352, 552, 120, 36, 1)
	create("BUTTON", "Отмена", CancelRulesID, 480, 552, 120, 36, 0)
	call(user, "EnableWindow", hwnd, 0)
	call(user, "ShowWindow", rulesWindow, SW_SHOW)
	call(user, "SetFocus", dpiEdit)
}
func editText(handle uintptr) string {
	count := call(user, "GetWindowTextLengthW", handle)
	if count > core.MaxDomainText {
		return strings.Repeat("x", core.MaxDomainText+1)
	}
	buffer := make([]uint16, count+1)
	call(user, "GetWindowTextW", handle, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	return windows.UTF16ToString(buffer)
}
func rulesProc(window uintptr, id uint32, w, l uintptr) uintptr {
	switch id {
	case WM_PAINT:
		var ps paintstruct
		dc := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
		var bounds rect
		call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
		fill(dc, bounds, BG)
		text(dc, "Мои ресурсы", 24, 16, 576, 32, 23, WHITE, 600, false)
		text(dc, "По одному домену или ссылке в строке (включая поддомены). Приоритет: Напрямую → Гео-DNS → Обход DPI.", 24, 56, 576, 20, 11, GRAY, 400, false)
		text(dc, "Обход DPI · свой IP (сайты, которые тормозят или заблокированы)", 24, 90, 576, 22, 14, WHITE, 600, false)
		text(dc, "Через DNS-профиль · нейросети и гео-сервисы", 24, 236, 576, 22, 14, WHITE, 600, false)
		text(dc, "Напрямую · без обработки DPI и DNS-профиля", 24, 382, 576, 22, 14, WHITE, 600, false)
		text(dc, "При сохранении правила применяются сразу, даже если пульт уже включён.", 24, 526, 576, 20, 11, GRAY, 400, false)
		call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x0133, 0x0138:
		call(gdi, "SetTextColor", w, WHITE)
		call(gdi, "SetBkColor", w, PANEL)
		return ruleBrush
	case WM_COMMAND:
		switch int(w & 0xffff) {
		case SaveRulesID, 1:
			dpiList, e := core.ParseDomains(editText(dpiEdit))
			if e != nil {
				call(user, "MessageBoxW", window, uintptr(unsafe.Pointer(u(e.Error()))), uintptr(unsafe.Pointer(u("Обход DPI · свой IP"))), 0x30)
				return 0
			}
			geo, e := core.ParseDomains(editText(geoEdit))
			if e != nil {
				call(user, "MessageBoxW", window, uintptr(unsafe.Pointer(u(e.Error()))), uintptr(unsafe.Pointer(u("Через DNS-профиль"))), 0x30)
				return 0
			}
			direct, e := core.ParseDomains(editText(directEdit))
			if e != nil {
				call(user, "MessageBoxW", window, uintptr(unsafe.Pointer(u(e.Error()))), uintptr(unsafe.Pointer(u("Напрямую"))), 0x30)
				return 0
			}
			saveConfig(func(c *core.Config) {
				if len(dpiList) == 0 {
					c.DPIDomains = nil
				} else {
					c.DPIDomains = dpiList
				}
				c.GeoDomains = geo
				c.DirectDomains = direct
			})
			call(user, "DestroyWindow", window)
			refresh()
			if currentConfig().VPNMode {
				restartVPNIfActive()
			} else {
				reloadEngineIfActive()
			}
			return 0
		case CancelRulesID, 2:
			call(user, "DestroyWindow", window)
			return 0
		}
	case WM_CLOSE:
		call(user, "DestroyWindow", window)
		return 0
	case WM_DESTROY:
		rulesWindow = 0
		dpiEdit = 0
		geoEdit = 0
		directEdit = 0
		call(gdi, "DeleteObject", ruleBrush)
		ruleBrush = 0
		call(user, "EnableWindow", hwnd, 1)
		if !quitting {
			call(user, "SetForegroundWindow", hwnd)
		}
		return 0
	}
	return call(user, "DefWindowProcW", window, uintptr(id), w, l)
}
