//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"sorryrkn/internal/core"
)

const DNSProfilesID = 210
const dnsDoneMessage = 0x8000 + 71
const dnsPickID, dnsScanID, dnsSaveID, dnsAutoID, dnsCloseID = 9101, 9102, 9103, 9104, 9105
const dnsFullID = 9107

var dnsWindow, dnsPicker, dnsResults, dnsStatus, dnsBrush uintptr
var dnsClassRegistered bool
var dnsChoices []core.DNSProfile
var dnsCheckMu sync.Mutex
var dnsCheckBusy bool
var dnsCheckCancel context.CancelFunc
var dnsCheckReport core.DNSMatrix
var dnsShowAll bool

func checkDNSProfiles(force bool) {
	if !force && !currentConfig().DNSAutoCheck() {
		return
	}
	dnsCheckMu.Lock()
	if dnsCheckBusy {
		dnsCheckMu.Unlock()
		return
	}
	dnsCheckBusy = true
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	dnsCheckCancel = cancel
	dnsCheckMu.Unlock()
	call(user, "PostMessageW", hwnd, dnsDoneMessage, 0, 0)
	go func() {
		defer cancel()
		if currentConfig().AutoData {
			refreshCtx, stop := context.WithTimeout(ctx, 4*time.Second)
			core.RefreshDNSCatalog(refreshCtx, data)
			stop()
		}
		var report core.DNSMatrix
		if force {
			report = core.ScanDNSProfiles(ctx, core.LoadDNSCatalog(data))
		} else {
			report = core.CheckConfiguredDNS(ctx, currentConfig(), core.LoadDNSCatalog(data), data, false)
		}
		if ctx.Err() == nil {
			core.SaveJSON(filepath.Join(data, "dns-scan.json"), report)
		}
		dnsCheckMu.Lock()
		dnsCheckReport = report
		dnsCheckBusy = false
		dnsCheckCancel = nil
		dnsCheckMu.Unlock()
		call(user, "PostMessageW", hwnd, dnsDoneMessage, 0, 0)
	}()
}

func refreshDNSWindow() {
	if dnsWindow == 0 {
		return
	}
	dnsCheckMu.Lock()
	busy := dnsCheckBusy
	report := dnsCheckReport
	dnsCheckMu.Unlock()
	status := "Выберите DNS. Изменение применяется при следующем включении соединения."
	if busy {
		status = "Проверяем DNS-профили и восемь сервисов…"
	}
	call(user, "SetWindowTextW", dnsStatus, uintptr(unsafe.Pointer(u(status))))
	text := report.SelectedText(currentConfig(), engine.Snapshot().Routes, core.LoadDNSCatalog(data))
	if dnsShowAll {
		text = report.Text()
	}
	if len(report.Profiles) == 0 {
		text = "Результатов пока нет. Нажмите «Проверить»."
	}
	call(user, "SetWindowTextW", dnsResults, uintptr(unsafe.Pointer(u(text))))
}

func showDNSProfiles() {
	if dnsWindow != 0 {
		call(user, "SetForegroundWindow", dnsWindow)
		return
	}
	if !dnsClassRegistered {
		wc := wndclass{Style: 3, WndProc: windows.NewCallback(dnsWindowProc), Instance: instance, Icon: icon, SmallIcon: icon, Cursor: call(user, "LoadCursorW", 0, 32512), Class: u("SorryRKNDNSProfiles")}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if call(user, "RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			errorMessage("Не удалось открыть выбор DNS")
			return
		}
		dnsClassRegistered = true
	}
	dnsBrush = call(gdi, "CreateSolidBrush", PANEL)
	dnsWindow = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u("SorryRKNDNSProfiles"))), uintptr(unsafe.Pointer(u("DNS и нейросети"))), 0x80c80000, 0x80000000, 0x80000000, uintptr(dp(740)), uintptr(dp(760)), hwnd, 0, instance, 0)
	if dnsWindow == 0 {
		call(gdi, "DeleteObject", dnsBrush)
		dnsBrush = 0
		return
	}
	create := func(class, label string, id, x, y, w, h int, style uintptr) uintptr {
		handle := call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(label))), 0x50010000|style, uintptr(dp(x)), uintptr(dp(y)), uintptr(dp(w)), uintptr(dp(h)), dnsWindow, uintptr(id), instance, 0)
		call(user, "SendMessageW", handle, 0x30, font(13, 400), 1)
		return handle
	}
	dnsPicker = create("COMBOBOX", "", dnsPickID, 24, 64, 670, 260, 0x0003|0x00200000)
	dnsChoices = core.LoadDNSCatalog(data).Profiles
	chosen := currentConfig().DNSProfile
	for i, p := range dnsChoices {
		call(user, "SendMessageW", dnsPicker, 0x0143, 0, uintptr(unsafe.Pointer(u(p.Name))))
		if p.ID == chosen || chosen == "" && p.ID == "comss" {
			call(user, "SendMessageW", dnsPicker, 0x014e, uintptr(i), 0)
		}
	}
	auto := create("BUTTON", "Проверять при запуске", dnsAutoID, 24, 108, 350, 32, 3)
	full := create("BUTTON", "Вся матрица DNS", dnsFullID, 440, 108, 250, 32, 3)
	call(user, "SendMessageW", full, 0x00f1, boolInt(dnsShowAll), 0)
	call(user, "SendMessageW", auto, 0x00f1, boolInt(currentConfig().DNSAutoCheck()), 0)
	dnsStatus = create("STATIC", "", 0, 24, 148, 670, 46, 0)
	dnsResults = create("EDIT", "", 0, 24, 202, 670, 420, 0x00800000|0x00200000|0x0004|0x0040|0x0800)
	create("BUTTON", "Проверить", dnsScanID, 24, 642, 140, 36, 0)
	create("BUTTON", "Маршруты", serviceRoutesID, 180, 642, 140, 36, 0)
	create("BUTTON", "Сохранить DNS", dnsSaveID, 328, 642, 190, 36, 1)
	create("BUTTON", "Закрыть", dnsCloseID, 532, 642, 162, 36, 0)
	dnsCheckMu.Lock()
	if len(dnsCheckReport.Profiles) == 0 {
		if b, err := os.ReadFile(filepath.Join(data, "dns-scan.json")); err == nil && len(b) < 131072 {
			json.Unmarshal(b, &dnsCheckReport)
		}
	}
	dnsCheckMu.Unlock()
	refreshDNSWindow()
	call(user, "EnableWindow", hwnd, 0)
	call(user, "ShowWindow", dnsWindow, SW_SHOW)
	call(user, "SetFocus", dnsPicker)
}

func dnsWindowProc(window uintptr, id uint32, w, l uintptr) uintptr {
	switch id {
	case WM_PAINT:
		var ps paintstruct
		dc := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
		var bounds rect
		call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
		fill(dc, bounds, BG)
		text(dc, "DNS и нейросети", 24, 18, 670, 36, 25, WHITE, 600, false)
		call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x0133, 0x0138:
		call(gdi, "SetTextColor", w, WHITE)
		call(gdi, "SetBkColor", w, PANEL)
		return dnsBrush
	case WM_COMMAND:
		switch int(w & 0xffff) {
		case dnsFullID:
			dnsShowAll = !dnsShowAll
			refreshDNSWindow()
		case serviceRoutesID:
			editServiceRoutes()
		case dnsScanID:
			checkDNSProfiles(true)
		case dnsAutoID:
			saveConfig(func(c *core.Config) { value := !c.DNSAutoCheck(); c.DNSCheckStartup = &value })
		case dnsSaveID, 1:
			index := int(call(user, "SendMessageW", dnsPicker, 0x0147, 0, 0))
			if index >= 0 && index < len(dnsChoices) {
				saveConfig(func(c *core.Config) { c.DNSProfile = dnsChoices[index].ID })
				call(user, "DestroyWindow", window)
				refresh()
			}
		case dnsCloseID, 2:
			call(user, "DestroyWindow", window)
		}
		return 0
	case WM_CLOSE:
		call(user, "DestroyWindow", window)
		return 0
	case WM_DESTROY:
		dnsWindow = 0
		dnsPicker = 0
		dnsResults = 0
		dnsStatus = 0
		dnsChoices = nil
		call(gdi, "DeleteObject", dnsBrush)
		dnsBrush = 0
		call(user, "EnableWindow", hwnd, 1)
		if !quitting {
			call(user, "SetForegroundWindow", hwnd)
		}
		return 0
	}
	return call(user, "DefWindowProcW", window, uintptr(id), w, l)
}
