//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"sorryrkn/internal/core"
	"unsafe"
)

const serviceRoutesID = 9106

var serviceWindow, serviceBrush uintptr
var serviceClass bool
var servicePickers []uintptr
var serviceChoices []string

func editServiceRoutes() {
	if serviceWindow != 0 {
		call(user, "SetForegroundWindow", serviceWindow)
		return
	}
	if !serviceClass {
		wc := wndclass{Style: 3, WndProc: windows.NewCallback(serviceRoutesProc), Instance: instance, Icon: icon, SmallIcon: icon, Cursor: call(user, "LoadCursorW", 0, 32512), Class: u("SorryRKNServiceRoutes")}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if call(user, "RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			errorMessage("Не удалось открыть маршруты")
			return
		}
		serviceClass = true
	}
	serviceBrush = call(gdi, "CreateSolidBrush", PANEL)
	serviceWindow = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u("SorryRKNServiceRoutes"))), uintptr(unsafe.Pointer(u("Маршруты сервисов"))), 0x80c80000, 0x80000000, 0x80000000, uintptr(dp(600)), uintptr(dp(610)), dnsWindow, 0, instance, 0)
	if serviceWindow == 0 {
		call(gdi, "DeleteObject", serviceBrush)
		serviceBrush = 0
		return
	}
	create := func(class, label string, id, x, y, w, h int, style uintptr) uintptr {
		handle := call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(label))), 0x50010000|style, uintptr(dp(x)), uintptr(dp(y)), uintptr(dp(w)), uintptr(dp(h)), serviceWindow, uintptr(id), instance, 0)
		call(user, "SendMessageW", handle, 0x30, font(13, 400), 1)
		return handle
	}
	create("STATIC", "Общий DNS — по умолчанию. «Авто с резервом» разрешает смену после двух неудачных проверок. Ручной выбор закреплён. Применится после переподключения.", 0, 20, 60, 550, 70, 0)
	catalog := core.LoadDNSCatalog(data)
	serviceChoices = []string{"", "auto"}
	names := []string{"По умолчанию", "Авто с резервом"}
	for _, p := range catalog.Profiles {
		serviceChoices = append(serviceChoices, p.ID)
		names = append(names, p.Name)
	}
	c := currentConfig()
	servicePickers = nil
	for i, s := range core.ServiceDefinitions {
		create("STATIC", s.Name, 0, 20, 142+i*43, 150, 28, 0)
		picker := create("COMBOBOX", "", 9200+i, 180, 137+i*43, 370, 260, 0x0003|0x00200000)
		servicePickers = append(servicePickers, picker)
		for j, name := range names {
			call(user, "SendMessageW", picker, 0x0143, 0, uintptr(unsafe.Pointer(u(name))))
			if serviceChoices[j] == c.ServiceDNS[s.ID] {
				call(user, "SendMessageW", picker, 0x014e, uintptr(j), 0)
			}
		}
	}
	create("BUTTON", "Сохранить", 9301, 280, 510, 130, 36, 1)
	create("BUTTON", "Отмена", 9302, 425, 510, 125, 36, 0)
	call(user, "EnableWindow", dnsWindow, 0)
	call(user, "ShowWindow", serviceWindow, SW_SHOW)
}
func serviceRoutesProc(window uintptr, id uint32, w, l uintptr) uintptr {
	switch id {
	case WM_PAINT:
		var ps paintstruct
		dc := call(user, "BeginPaint", window, uintptr(unsafe.Pointer(&ps)))
		var bounds rect
		call(user, "GetClientRect", window, uintptr(unsafe.Pointer(&bounds)))
		fill(dc, bounds, BG)
		text(dc, "Маршруты сервисов", 20, 16, 550, 36, 24, WHITE, 600, false)
		call(user, "EndPaint", window, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x0133, 0x0138:
		call(gdi, "SetTextColor", w, WHITE)
		call(gdi, "SetBkColor", w, PANEL)
		return serviceBrush
	case WM_COMMAND:
		switch int(w & 0xffff) {
		case 9301, 1:
			choices := map[string]string{}
			for i, s := range core.ServiceDefinitions {
				index := int(call(user, "SendMessageW", servicePickers[i], 0x0147, 0, 0))
				if index >= 0 && index < len(serviceChoices) && serviceChoices[index] != "" {
					choices[s.ID] = serviceChoices[index]
				}
			}
			if err := core.ValidateServiceDNS(choices); err != nil {
				errorMessage(err.Error())
				return 0
			}
			saveConfig(func(c *core.Config) { c.ServiceDNS = choices })
			call(user, "DestroyWindow", window)
			refreshDNSWindow()
		case 9302, 2:
			call(user, "DestroyWindow", window)
		}
		return 0
	case WM_CLOSE:
		call(user, "DestroyWindow", window)
		return 0
	case WM_DESTROY:
		serviceWindow = 0
		servicePickers = nil
		serviceChoices = nil
		call(gdi, "DeleteObject", serviceBrush)
		serviceBrush = 0
		call(user, "EnableWindow", dnsWindow, 1)
		call(user, "SetForegroundWindow", dnsWindow)
		return 0
	}
	return call(user, "DefWindowProcW", window, uintptr(id), w, l)
}
