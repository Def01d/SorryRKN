//go:build windows

package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"sorryrkn/internal/core"
	"sorryrkn/internal/platform"
	"strings"
	"unsafe"
)

const AppsID = 212
const (
	appsSearchID = 9401 + iota
	appsRunningListID
	appsExcludedListID
	appsAddBtnID
	appsRemoveBtnID
	appsRefreshBtnID
	appsShowSysID
	appsManualEditID
	appsManualAddID
	appsClearBtnID
	appsSaveBtnID
	appsCancelBtnID
	appsExcludedTitleID
)

var (
	appsWindow           uintptr
	appsBrush            uintptr
	appsBgBrush          uintptr
	appsClassRegistered  bool
	appsCtrls            = map[int]uintptr{}
	appsAllRunning       []platform.RunningApp
	appsVisibleRunning   []platform.RunningApp
	appsWorkingExclusions []string
)

func editExcludedApps() {
	if appsWindow != 0 {
		call(user, "SetForegroundWindow", appsWindow)
		return
	}
	if !appsClassRegistered {
		wc := wndclass{
			Style:    3,
			WndProc:  windows.NewCallback(appsProc),
			Instance: instance,
			Icon:     icon,
			SmallIcon: icon,
			Cursor:   call(user, "LoadCursorW", 0, 32512),
			Class:    u("SorryRKNApps"),
		}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if call(user, "RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			errorMessage("Не удалось открыть окно исключений")
			return
		}
		appsClassRegistered = true
	}

	c := currentConfig()
	normalized, err := core.NormalizeExcludedApps(c.ExcludedApps)
	if err != nil {
		normalized = append([]string(nil), c.ExcludedApps...)
	}
	appsWorkingExclusions = normalized
	appsCtrls = map[int]uintptr{}
	appsBrush = call(gdi, "CreateSolidBrush", PANEL)
	appsBgBrush = call(gdi, "CreateSolidBrush", BG)

	appsWindow = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u("SorryRKNApps"))), uintptr(unsafe.Pointer(u("Исключения приложений"))),
		0x80c80000, 0x80000000, 0x80000000, uintptr(dp(776)), uintptr(dp(598)), hwnd, 0, instance, 0)
	if appsWindow == 0 {
		call(gdi, "DeleteObject", appsBrush)
		call(gdi, "DeleteObject", appsBgBrush)
		appsBrush = 0
		appsBgBrush = 0
		errorMessage("Не удалось открыть окно исключений")
		return
	}
	dark := uint32(1)
	if p := proc(dwm, "DwmSetWindowAttribute"); p.Find() == nil {
		p.Call(appsWindow, 20, uintptr(unsafe.Pointer(&dark)), 4)
	}

	ctrl := func(class, label string, id, x, y, w, h int, style uintptr) uintptr {
		handle := call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(label))),
			0x50000000|style, uintptr(dp(x)), uintptr(dp(y)), uintptr(dp(w)), uintptr(dp(h)), appsWindow, uintptr(id), instance, 0)
		call(user, "SendMessageW", handle, 0x30, font(13, 400), 1)
		if id != 0 {
			appsCtrls[id] = handle
		}
		return handle
	}

	// Left panel (x=20..366, y=104..486): currently running PC processes
	ctrl("STATIC", "Запущены сейчас на ПК", 0, 34, 114, 210, 22, 0)
	ctrl("BUTTON", "Обновить", appsRefreshBtnID, 258, 110, 94, 28, 0x00010000)
	ctrl("STATIC", "Поиск:", 0, 34, 150, 52, 22, 0)
	ctrl("EDIT", "", appsSearchID, 88, 146, 264, 26, 0x00810080)
	ctrl("LISTBOX", "", appsRunningListID, 34, 182, 318, 218, 0x00A10101)
	ctrl("BUTTON", "", appsShowSysID, 34, 412, 18, 18, 0x00010003)
	ctrl("STATIC", "Системные процессы", 0, 58, 411, 168, 22, 0)
	ctrl("BUTTON", "Исключить →", appsAddBtnID, 232, 438, 120, 32, 0x00010000)

	// Right panel (x=384..740, y=104..486): excluded executables
	ctrl("STATIC", "В исключениях (0)", appsExcludedTitleID, 398, 114, 224, 22, 0)
	ctrl("BUTTON", "Очистить", appsClearBtnID, 632, 110, 94, 28, 0x00010000)
	ctrl("EDIT", "", appsManualEditID, 398, 146, 204, 26, 0x00810080)
	ctrl("BUTTON", "+ Добавить", appsManualAddID, 610, 145, 116, 28, 0x00010000)
	ctrl("LISTBOX", "", appsExcludedListID, 398, 182, 328, 248, 0x00A10101)
	ctrl("BUTTON", "← Убрать", appsRemoveBtnID, 398, 438, 140, 32, 0x00010000)

	// Footer actions
	ctrl("BUTTON", "Сохранить", appsSaveBtnID, 492, 502, 120, 36, 0x00010001)
	ctrl("BUTTON", "Отмена", appsCancelBtnID, 620, 502, 120, 36, 0x00010000)

	reloadRunningApps()
	renderExcludedAppsList()

	call(user, "EnableWindow", hwnd, 0)
	call(user, "ShowWindow", appsWindow, SW_SHOW)
	call(user, "RedrawWindow", appsWindow, 0, 0, 0x0181)
	call(user, "SetFocus", appsCtrls[appsSearchID])
}

func reloadRunningApps() {
	list, err := platform.RunningApps()
	if err == nil {
		appsAllRunning = list
	} else {
		appsAllRunning = nil
	}
	renderRunningAppsList()
}

func renderRunningAppsList() {
	h := appsCtrls[appsRunningListID]
	if h == 0 {
		return
	}
	call(user, "SendMessageW", h, 0x0184, 0, 0) // LB_RESETCONTENT
	query := strings.ToLower(strings.TrimSpace(editText(appsCtrls[appsSearchID])))
	showSys := call(user, "SendMessageW", appsCtrls[appsShowSysID], 0x00F0, 0, 0) == 1
	excluded := map[string]bool{}
	for _, item := range appsWorkingExclusions {
		excluded[item] = true
	}
	appsVisibleRunning = nil
	for _, app := range appsAllRunning {
		if app.System && !showSys {
			continue
		}
		lowerExe := strings.ToLower(app.Exe)
		if query != "" {
			if !strings.Contains(lowerExe, query) && !strings.Contains(strings.ToLower(app.Title), query) {
				continue
			}
		}
		appsVisibleRunning = append(appsVisibleRunning, app)
		prefix := ""
		if excluded[lowerExe] {
			prefix = "[✓] "
		} else if app.HasWindow {
			prefix = "● "
		}
		line := prefix + app.Exe
		if app.Title != "" {
			line += " — " + app.Title
		}
		call(user, "SendMessageW", h, 0x0180, 0, uintptr(unsafe.Pointer(u(line))))
	}
}

func renderExcludedAppsList() {
	h := appsCtrls[appsExcludedListID]
	if h == 0 {
		return
	}
	call(user, "SendMessageW", h, 0x0184, 0, 0)
	for _, exe := range appsWorkingExclusions {
		call(user, "SendMessageW", h, 0x0180, 0, uintptr(unsafe.Pointer(u(exe))))
	}
	setLabel(appsCtrls[appsExcludedTitleID], fmt.Sprintf("В исключениях (%d)", len(appsWorkingExclusions)))
}

func addExcludedApp(raw string) {
	name, err := core.NormalizeAppName(raw)
	if err != nil {
		call(user, "MessageBoxW", appsWindow, uintptr(unsafe.Pointer(u(err.Error()))), uintptr(unsafe.Pointer(u("Исключения приложений"))), 0x30)
		return
	}
	for _, existing := range appsWorkingExclusions {
		if existing == name {
			return
		}
	}
	if len(appsWorkingExclusions) >= core.MaxExcludedApps {
		call(user, "MessageBoxW", appsWindow, uintptr(unsafe.Pointer(u("Достигнут лимит 256 приложений"))), uintptr(unsafe.Pointer(u("Исключения приложений"))), 0x30)
		return
	}
	appsWorkingExclusions = append(appsWorkingExclusions, name)
	appsWorkingExclusions, _ = core.NormalizeExcludedApps(appsWorkingExclusions)
	renderExcludedAppsList()
	renderRunningAppsList()
}

func addSelectedRunningApp() {
	idx := int(int32(call(user, "SendMessageW", appsCtrls[appsRunningListID], 0x0188, 0, 0)))
	if idx < 0 || idx >= len(appsVisibleRunning) {
		return
	}
	addExcludedApp(appsVisibleRunning[idx].Exe)
}

func removeSelectedExcludedApp() {
	idx := int(int32(call(user, "SendMessageW", appsCtrls[appsExcludedListID], 0x0188, 0, 0)))
	if idx < 0 || idx >= len(appsWorkingExclusions) {
		return
	}
	appsWorkingExclusions = append(appsWorkingExclusions[:idx], appsWorkingExclusions[idx+1:]...)
	renderExcludedAppsList()
	renderRunningAppsList()
}

func paintAppsWindow(window, dc uintptr) {
	var bounds rect
	call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
	fill(dc, bounds, BG)
	text(dc, "Исключения приложений", 20, 14, 720, 32, 22, WHITE, 600, false)
	text(dc, "В режиме VPN исключённые программы и локальные сети (10/8, 172.16/12, 192.168/16) идут напрямую; внутренний DNS работает с авто-резервом.", 20, 50, 720, 18, 11, GRAY, 400, false)
	text(dc, "Для публичных доменов корпоративных сервисов или отключения локального DPI используйте «Правила → Напрямую».", 20, 68, 720, 18, 11, GRAY, 400, false)
	rounded(dc, logicalRect(20, 98, 346, 386), PANEL, BORDER, 14)
	rounded(dc, logicalRect(384, 98, 356, 386), PANEL, BORDER, 14)
	text(dc, "Выберите запущенное приложение или введите имя .exe", 20, 510, 456, 20, 11, GRAY, 400, false)
}

func appsProc(window uintptr, id uint32, w, l uintptr) uintptr {
	switch id {
	case WM_PAINT:
		var ps paintstruct
		dc := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
		paintAppsWindow(window, dc)
		call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x0318: // WM_PRINTCLIENT
		paintAppsWindow(window, w)
		return 0
	case 0x0133, 0x0134, 0x0138:
		call(gdi, "SetTextColor", w, WHITE)
		call(gdi, "SetBkColor", w, PANEL)
		return appsBrush
	case WM_COMMAND:
		cmd := int(w & 0xffff)
		notify := int(w >> 16)
		switch cmd {
		case appsSearchID:
			if notify == 0x0300 { // EN_CHANGE
				renderRunningAppsList()
			}
		case appsRunningListID:
			if notify == 2 { // LBN_DBLCLK
				addSelectedRunningApp()
			}
		case appsExcludedListID:
			if notify == 2 { // LBN_DBLCLK
				removeSelectedExcludedApp()
			}
		case appsRefreshBtnID:
			if notify == 0 {
				reloadRunningApps()
			}
		case appsShowSysID:
			if notify == 0 {
				renderRunningAppsList()
			}
		case appsAddBtnID:
			if notify == 0 {
				addSelectedRunningApp()
			}
		case appsRemoveBtnID:
			if notify == 0 {
				removeSelectedExcludedApp()
			}
		case appsManualAddID:
			if notify == 0 {
				raw := strings.TrimSpace(editText(appsCtrls[appsManualEditID]))
				if raw != "" {
					addExcludedApp(raw)
					setLabel(appsCtrls[appsManualEditID], "")
				}
			}
		case appsClearBtnID:
			if notify == 0 {
				appsWorkingExclusions = nil
				renderExcludedAppsList()
				renderRunningAppsList()
			}
		case appsSaveBtnID, 1:
			if notify == 0 {
				finalList, err := core.NormalizeExcludedApps(appsWorkingExclusions)
				if err != nil {
					call(user, "MessageBoxW", window, uintptr(unsafe.Pointer(u(err.Error()))), uintptr(unsafe.Pointer(u("Исключения приложений"))), 0x30)
					return 0
				}
				saveConfig(func(c *core.Config) {
					if len(finalList) == 0 {
						c.ExcludedApps = nil
					} else {
						c.ExcludedApps = finalList
					}
				})
				call(user, "DestroyWindow", window)
				refresh()
				if currentConfig().VPNMode {
					restartVPNIfActive()
				} else {
					reloadEngineIfActive()
				}
			}
		case appsCancelBtnID, 2:
			if notify == 0 {
				call(user, "DestroyWindow", window)
			}
		}
		return 0
	case WM_CLOSE:
		call(user, "DestroyWindow", window)
		return 0
	case WM_DESTROY:
		appsWindow = 0
		appsCtrls = map[int]uintptr{}
		appsAllRunning = nil
		appsVisibleRunning = nil
		appsWorkingExclusions = nil
		if appsBrush != 0 {
			call(gdi, "DeleteObject", appsBrush)
			appsBrush = 0
		}
		if appsBgBrush != 0 {
			call(gdi, "DeleteObject", appsBgBrush)
			appsBgBrush = 0
		}
		call(user, "EnableWindow", hwnd, 1)
		if !quitting {
			call(user, "SetForegroundWindow", hwnd)
		}
		return 0
	}
	return call(user, "DefWindowProcW", window, uintptr(id), w, l)
}
