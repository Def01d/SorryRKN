//go:build windows

package main

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"path/filepath"
	"sorryrkn/internal/core"
	"sorryrkn/internal/tunnel"
	"sync"
	"time"
	"unsafe"
)

const (
	vpnModeID = 1100 + iota
	modeLocalID
	modeTunnelID
	vpnServerID
	vpnSourcesID
)
const modeServerTabID = 1106
const modeSubsTabID = 1107
const vpnDoneMessage = WM_APP + 44
const vpnTimer = 1105

var vpnTabFocus = "subs"

var vpnSession tunnel.Session
var vpnLibrary tunnel.Library
var libraryError error
var vpnStatus string
var vpnWindow, vpnBrush uintptr
var vpnClass bool
var vpnPage int
var fields map[int]uintptr
var cancelWork context.CancelFunc
var jobResult = make(chan func(), 1)
var linkMu sync.Mutex
var tunnelClosing bool
var wasActive bool

func libraryPath() string { return filepath.Join(data, "vpn-library.bin") }
func loadLibrary()        { vpnLibrary, libraryError = tunnel.Load(libraryPath()) }
func selectedNode() (tunnel.Profile, bool) {
	s, n := vpnLibrary.SelectedSource, vpnLibrary.SelectedNode
	if s < 0 || s >= len(vpnLibrary.Sources) || n < 0 || n >= len(vpnLibrary.Sources[s].Profiles) {
		return tunnel.Profile{}, false
	}
	return vpnLibrary.Sources[s].Profiles[n], true
}
func commitLibrary(next tunnel.Library) bool {
	if libraryError != nil {
		errorMessage(libraryError.Error())
		return false
	}
	if err := tunnel.Save(libraryPath(), next); err != nil {
		errorMessage(err.Error())
		return false
	}
	vpnLibrary = next
	refresh()
	return true
}
func copyLibrary() tunnel.Library {
	next := vpnLibrary
	next.Sources = append([]tunnel.Source(nil), next.Sources...)
	return next
}
func createModeControls() {
	createButton(modeLocalID, "Локальный", 26, 64, 132, 30)
	createButton(modeServerTabID, "Свой сервер", 160, 64, 132, 30)
	createButton(modeSubsTabID, "Подписки", 294, 64, 132, 30)
	createButton(vpnServerID, "Свой сервер", 38, 224, 376, 70)
	createButton(vpnSourcesID, "Подписки и узлы", 38, 306, 376, 70)
	loadLibrary()
	applyMode()
}
func showControl(id int, on bool) {
	h := controls[id]
	if h == 0 {
		return
	}
	var show uintptr
	if on {
		show = SW_SHOW
	}
	call(user, "ShowWindow", h, show)
}
func applyMode() {
	v := currentConfig().VPNMode
	for _, id := range []int{DpiID, InstagramID, TelegramID, ExtrasID, ProfileID, InstaRowID, DnsRowID, LinkID, DiagBtnID} {
		showControl(id, !v)
	}
	for _, id := range []int{vpnServerID, vpnSourcesID} {
		showControl(id, v)
	}
	refresh()
}
func switchVPNMode(enableVPN bool, tab string) {
	if cancelWork != nil {
		return
	}
	prev := currentConfig().VPNMode
	if enableVPN && tab != "" {
		vpnTabFocus = tab
	}
	if prev == enableVPN {
		if enableVPN {
			if tab == "server" {
				openVPNPage(vpnServerID)
			} else if tab == "subs" {
				openVPNPage(vpnSourcesID)
			}
		}
		refresh()
		return
	}
	if !enableVPN && vpnSession.Active() {
		go vpnSession.Stop()
		wasActive = false
		call(user, "KillTimer", hwnd, vpnTimer)
	}
	if enableVPN && engine != nil && engine.Busy() {
		go engine.Stop()
	}
	saveConfig(func(c *core.Config) { c.VPNMode = enableVPN })
	applyMode()
}
func modeCommand(id int) bool {
	switch id {
	case vpnModeID:
		m := call(user, "CreatePopupMenu")
		v := currentConfig().VPNMode
		locked := cancelWork != nil
		addItem(m, modeLocalID, "Локальный обход", !v, locked)
		addItem(m, modeTunnelID, "VPN и подписки", v, locked)
		popup(m)
	case modeLocalID:
		switchVPNMode(false, "")
	case modeTunnelID:
		switchVPNMode(true, "subs")
	case modeServerTabID:
		switchVPNMode(true, "server")
	case modeSubsTabID:
		switchVPNMode(true, "subs")
	case vpnServerID, vpnSourcesID:
		if currentConfig().VPNMode {
			if id == vpnServerID {
				vpnTabFocus = "server"
			} else {
				vpnTabFocus = "subs"
			}
			openVPNPage(id)
			refresh()
		}
	default:
		return false
	}
	return true
}
func paintVPN(dc uintptr) {
	title, detail := "VPN выключен", "Выберите свой сервер или подписку ниже"
	dotColor := DIM
	heroStroke := BORDER
	if p, ok := selectedNode(); ok {
		detail = p.Name
	}
	if vpnSession.Active() {
		title = "VPN включён"
		dotColor = GREEN
		heroStroke = GREEN
	}
	if cancelWork != nil {
		dotColor = AMBER
		heroStroke = AMBER
	}
	if vpnStatus != "" {
		detail = vpnStatus
	}
	rounded(dc, logicalRect(22, 110, 408, 96), PANEL, heroStroke, 18)
	ellipse(dc, logicalRect(118, 141, 8, 8), dotColor, dotColor)
	text(dc, title, 132, 132, 270, 26, 18, WHITE, 600, false)
	text(dc, detail, 118, 160, 290, 22, 12, GRAY, 400, false)

	rounded(dc, logicalRect(22, 218, 408, 164), PANEL, BORDER, 18)
	line(dc, 38, 300, 414, 300, BORDER)
	text(dc, "Закрытие окна сворачивает пульт в системный трей", 22, 533, 408, 20, 11, DIM, 400, true)
}
func drawVPNButton(d *drawitem, w, h int) bool {
	dc := d.Hdc
	c := currentConfig()
	switch int(d.ID) {
	case modeLocalID, modeServerTabID, modeSubsTabID:
		fill(dc, d.Rect, PANEL)
		active := false
		label := "Локальный"
		switch int(d.ID) {
		case modeLocalID:
			active = !c.VPNMode
		case modeServerTabID:
			label = "Свой сервер"
			active = c.VPNMode && vpnTabFocus == "server"
		case modeSubsTabID:
			label = "Подписки"
			active = c.VPNMode && vpnTabFocus != "server"
		}
		fg := GRAY
		weight := 500
		if active {
			rounded(dc, logicalRect(0, 0, w, h), PANEL_ELEV, BORDER_STRONG, 8)
			fg = WHITE
			weight = 600
		}
		text(dc, label, 0, 6, w, h-8, 12, fg, weight, true)
	case vpnServerID, vpnSourcesID:
		fill(dc, d.Rect, PANEL)
		label, note := "Свой сервер", "Мираж, VLESS, HTTPS, Hy2, SS2022 и SOCKS5"
		if d.ID == vpnSourcesID {
			label, note = "Подписки и узлы", "Импорт ссылок, проверка и выбор узла"
		}
		text(dc, label, 0, 10, w-30, 24, 15, WHITE, 600, false)
		text(dc, note, 0, 38, w-30, 20, 11, GRAY, 400, false)
		text(dc, "›", w-24, 18, 22, 28, 20, GRAY, 400, true)
	default:
		return false
	}
	return true
}

// Network and SSH operations run outside the UI thread. Only the completion
// posted to the window may change controls and publish a new library selection.
func startWork(label string, timeout time.Duration, work func(context.Context) (func(), error)) {
	if cancelWork != nil || quitting {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cancelWork = cancel
	vpnStatus = label
	setPageBusy(true)
	refresh()
	go func() {
		done, err := work(ctx)
		jobResult <- func() {
			cancel()
			cancelWork = nil
			vpnStatus = ""
			setPageBusy(false)
			if err != nil {
				errorMessage(err.Error())
			} else if done != nil {
				done()
			}
			refresh()
		}
		call(user, "PostMessageW", hwnd, vpnDoneMessage, 0, 0)
	}()
}
func finishVPNWork() {
	select {
	case done := <-jobResult:
		if !quitting {
			done()
		}
	default:
	}
}
func setPageBusy(busy bool) {
	if vpnWindow != 0 {
		for _, h := range fields {
			call(user, "EnableWindow", h, boolInt(!busy))
		}
		caption := "VPN"
		if vpnPage == vpnServerID {
			caption = "Свой сервер"
		} else {
			caption = "Подписки и узлы"
		}
		if busy {
			caption += " · " + vpnStatus
		}
		setLabel(vpnWindow, caption)
	}
}
func setLabel(h uintptr, s string) { call(user, "SetWindowTextW", h, uintptr(unsafe.Pointer(u(s)))) }
func toggleVPN() {
	if cancelWork != nil {
		return
	}
	if vpnSession.Active() {
		startWork("Отключение…", 15*time.Second, func(context.Context) (func(), error) {
			vpnSession.Stop()
			return func() { wasActive = false; call(user, "KillTimer", hwnd, vpnTimer) }, nil
		})
		return
	}
	if libraryError != nil {
		errorMessage(libraryError.Error())
		return
	}
	p, ok := selectedNode()
	if !ok {
		openVPNPage(vpnSourcesID)
		return
	}
	startWork("Подключение…", 45*time.Second, func(ctx context.Context) (func(), error) {
		linkMu.Lock()
		defer linkMu.Unlock()
		if tunnelClosing || ctx.Err() != nil {
			return nil, errors.New("Подключение отменено")
		}
		if err := vpnSession.Start(filepath.Dir(root), p); err != nil {
			return nil, err
		}
		return func() { wasActive = true; call(user, "SetTimer", hwnd, vpnTimer, 1000, 0) }, nil
	})
}
func watchTunnel() {
	if wasActive && !vpnSession.Active() && cancelWork == nil {
		wasActive = false
		vpnStatus = "Соединение завершилось. Подключитесь снова."
		call(user, "KillTimer", hwnd, vpnTimer)
		refresh()
	}
}
func closeTunnelForUpdate() {
	linkMu.Lock()
	defer linkMu.Unlock()
	tunnelClosing = true
	vpnSession.Stop()
}
func stopVPNForExit() {
	endForwardLifetime()
	replaceForward("", nil)
	if cancelWork != nil {
		cancelWork()
	}
	closeTunnelForUpdate()
}
func openVPNPage(id int) {
	if vpnWindow != 0 {
		call(user, "SetForegroundWindow", vpnWindow)
		return
	}
	if cancelWork != nil {
		return
	}
	if id == vpnServerID && vpnSession.Active() {
		message("VPN", "Для изменения настроек сервера отключите VPN.")
		return
	}
	if id == vpnSourcesID && libraryError != nil {
		errorMessage(libraryError.Error())
		return
	}
	if !vpnClass {
		wc := wndclass{Style: 3, WndProc: windows.NewCallback(vpnProc), Instance: instance, Icon: icon, SmallIcon: icon, Cursor: call(user, "LoadCursorW", 0, 32512), Class: u("SorryRKNVPN")}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if call(user, "RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			errorMessage("Не удалось открыть окно VPN")
			return
		}
		vpnClass = true
	}
	vpnPage = id
	title := "Свой сервер"
	width := 920
	height := 650
	if id == vpnSourcesID {
		title = "Подписки и узлы"
		width = 626
		height = 505
	}
	fields = map[int]uintptr{}
	vpnBrush = call(gdi, "CreateSolidBrush", PANEL)
	vpnWindow = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u("SorryRKNVPN"))), uintptr(unsafe.Pointer(u(title))), 0x80c80000, 0x80000000, 0x80000000, uintptr(dp(width)), uintptr(dp(height)), hwnd, 0, instance, 0)
	if vpnWindow == 0 {
		call(gdi, "DeleteObject", vpnBrush)
		errorMessage("Не удалось открыть окно VPN")
		return
	}
	dark := uint32(1)
	call(dwm, "DwmSetWindowAttribute", vpnWindow, 20, uintptr(unsafe.Pointer(&dark)), 4)
	if id == vpnServerID {
		createServerPage()
	} else {
		createSourcePage()
	}
	call(user, "EnableWindow", hwnd, 0)
	call(user, "ShowWindow", vpnWindow, SW_SHOW)
	call(user, "RedrawWindow", vpnWindow, 0, 0, 0x181) // invalidate and paint the window and its children now
}
func field(class, label string, id, x, y, w, h int, style uintptr) uintptr {
	handle := call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(label))), 0x50000000|style, uintptr(dp(x)), uintptr(dp(y)), uintptr(dp(w)), uintptr(dp(h)), vpnWindow, uintptr(id), instance, 0)
	call(user, "SendMessageW", handle, 0x30, font(14, 400), 1)
	if id != 0 {
		fields[id] = handle
	}
	return handle
}
func caption(label string, x, y, w int) { field("STATIC", label, 0, x, y, w, 24, 0) }
func input(id int, value string, x, y, w int, style uintptr) {
	field("EDIT", value, id, x, y, w, 28, 0x00810080|style)
}
func button(id int, label string, x, y, w int) { field("BUTTON", label, id, x, y, w, 34, 0x10000) }
func paintVPNPage(window, dc uintptr) {
	var bounds rect
	call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
	fill(dc, bounds, BG)
	if vpnPage == vpnSourcesID {
		text(dc, "Подписки и узлы", 20, 12, 560, 40, 24, WHITE, 600, false)
		return
	}
	text(dc, "Мои серверы · Флот и протоколы", 20, 12, 860, 38, 22, WHITE, 600, false)
	rounded(dc, logicalRect(16, 60, 292, 536), PANEL, BORDER, 14)
	rounded(dc, logicalRect(322, 60, 566, 90), PANEL, BORDER, 14)
	rounded(dc, logicalRect(322, 162, 566, 180), PANEL, BORDER, 14)
	rounded(dc, logicalRect(322, 354, 566, 124), PANEL, BORDER, 14)
}
func vpnProc(window uintptr, id uint32, w, l uintptr) uintptr {
	switch id {
	case WM_PAINT:
		var ps paintstruct
		dc := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
		paintVPNPage(window, dc)
		call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x0318: // WM_PRINTCLIENT
		paintVPNPage(window, w)
		return 0
	case 0x0133, 0x0134, 0x0138:
		call(gdi, "SetTextColor", w, WHITE)
		call(gdi, "SetBkColor", w, PANEL)
		return vpnBrush
	case WM_COMMAND:
		if cancelWork != nil {
			return 0
		}
		n := int(w & 0xffff)
		if n == 2 {
			call(user, "DestroyWindow", window)
		} else if vpnPage == vpnServerID {
			serverCommand(n, int(w>>16))
		} else {
			sourceCommand(n, int(w>>16))
		}
		return 0
	case WM_CLOSE:
		if cancelWork != nil {
			cancelWork()
			return 0
		}
		call(user, "DestroyWindow", window)
		return 0
	case WM_DESTROY:
		vpnWindow = 0
		fields = nil
		call(gdi, "DeleteObject", vpnBrush)
		call(user, "EnableWindow", hwnd, 1)
		call(user, "SetForegroundWindow", hwnd)
		return 0
	}
	return call(user, "DefWindowProcW", window, uintptr(id), w, l)
}
