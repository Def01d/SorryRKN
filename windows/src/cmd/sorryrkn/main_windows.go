//go:build windows

package main

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"sorryrkn/internal/core"
	"sorryrkn/internal/platform"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var user = windows.NewLazySystemDLL("user32.dll")
var gdi = windows.NewLazySystemDLL("gdi32.dll")
var shell = windows.NewLazySystemDLL("shell32.dll")
var kernel = windows.NewLazySystemDLL("kernel32.dll")
var dwm = windows.NewLazySystemDLL("dwmapi.dll")

func proc(d *windows.LazyDLL, n string) *windows.LazyProc { return d.NewProc(n) }
func u(s string) *uint16                                  { p, _ := windows.UTF16PtrFromString(s); return p }

//go:uintptrescapes
func call(d *windows.LazyDLL, name string, a ...uintptr) uintptr {
	r, _, _ := proc(d, name).Call(a...)
	return r
}

const WM_PAINT = 0x0f
const WM_COMMAND = 0x111
const WM_DRAWITEM = 0x2b
const WM_CLOSE = 0x10
const WM_DESTROY = 2
const WM_APP = 0x8000
const TRAY = WM_APP + 1
const REFRESH = WM_APP + 2
const UPDATE = WM_APP + 3
const EXIT = WM_APP + 4
const launchCheckMessage = WM_APP + 45
const uiAlertMessage = WM_APP + 46

// Win32 COLORREF tokens (0x00BBGGRR)
const BG = 0x0d0b0b
const PANEL = 0x181414
const PANEL_ELEV = 0x221c1c
const WHITE = 0xf5f2f2
const GRAY = 0x988e8e
const DIM = 0x665c5c
const BORDER = 0x302828
const BORDER_STRONG = 0x483c3c
const GREEN = 0x99d334
const AMBER = 0x24bffb
const RED = 0x7171f8

const BS_OWNERDRAW = 0x0b
const SW_SHOW = 5
const SW_HIDE = 0

const PowerID = 100
const DpiID = 101
const TelegramID = 102
const ExtrasID = 103
const LinkID = 104
const MenuID = 105
const ProfileID = 106
const InstaRowID = 107
const InstagramID = 108
const QuickRulesID = 109
const QuickRetestID = 110
const DnsRowID = 111
const DiagBtnID = 112

const OpenID = 200
const RetestID = 201
const ExtendedID = 202
const UpdatesID = 203
const DataID = 204
const DiagnosticsID = 205
const ExitID = 206
const AutoDataID = 207
const AboutID = 208
const AutoStartID = 211

type point struct{ X, Y int32 }
type rect struct{ Left, Top, Right, Bottom int32 }
type msg struct {
	Hwnd           uintptr
	Message        uint32
	Wparam, Lparam uintptr
	Time           uint32
	Pt             point
	Private        uint32
}
type wndclass struct {
	Size                               uint32
	Style                              uint32
	WndProc                            uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Class                        *uint16
	SmallIcon                          uintptr
}
type drawitem struct {
	Type, ID, ItemID, Action, State uint32
	Hwnd, Hdc                       uintptr
	Rect                            rect
	Data                            uintptr
}
type notifyicon struct {
	Size                uint32
	Hwnd                uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Timeout             uint32
	Title               [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	Balloon             uintptr
}

var hwnd, instance, icon uintptr
var controls = map[int]uintptr{}
var fonts = map[int]uintptr{}
var scale = 1.0
var engine *core.Engine
var dns = &platform.DNS{}
var root, data, secret string
var config core.Config
var configMu sync.Mutex
var reloadMu sync.Mutex
var latest core.Release
var latestMu sync.Mutex
var updateBusy bool
var updatePrompt bool // Window thread only.
var updateMu sync.Mutex
var checkMu sync.Mutex
var trayAvailable bool
var taskbarMessage uint32
var quitting bool
var mainThreadID uint32
var alertMu sync.Mutex
var pendingAlerts [][2]string

func dp(v int) int32             { return int32(float64(v)*scale + .5) }
func currentConfig() core.Config { configMu.Lock(); defer configMu.Unlock(); return config }
func saveConfig(change func(*core.Config)) {
	configMu.Lock()
	change(&config)
	e := core.SaveJSON(filepath.Join(data, "config.json"), config)
	configMu.Unlock()
	if e != nil {
		message("Не удалось сохранить настройки", e.Error())
	}
}
func message(title, text string) {
	cur := uint32(call(kernel, "GetCurrentThreadId"))
	if hwnd != 0 && mainThreadID != 0 && cur != mainThreadID {
		alertMu.Lock()
		pendingAlerts = append(pendingAlerts, [2]string{title, text})
		alertMu.Unlock()
		call(user, "PostMessageW", hwnd, uiAlertMessage, 0, 0)
		return
	}
	owner := hwnd
	for _, modal := range []uintptr{serviceWindow, dnsWindow, rulesWindow, vpnWindow} {
		if modal != 0 {
			owner = modal
			break
		}
	}
	call(user, "MessageBoxW", owner, uintptr(unsafe.Pointer(u(text))), uintptr(unsafe.Pointer(u(title))), 0x40)
}
func errorMessage(text string) { message("SorryRKN", text) }

func reloadEngineIfActive() {
	if currentConfig().VPNMode || engine == nil {
		return
	}
	st := engine.Snapshot().Status
	if st != "on" && st != "partial" && st != "starting" {
		return
	}
	go func() {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		engine.Stop()
		c := currentConfig()
		rules, err := c.Rules()
		if err != nil {
			return
		}
		if !c.DPI && !c.Telegram && !c.Extras && !c.InstagramEnabled() && len(rules.Geo) == 0 && len(rules.DPI) == 0 {
			return
		}
		_ = engine.Start(c, secret, false, func(id string) {
			saveConfig(func(cfg *core.Config) { cfg.SavedProfile = id })
		})
	}()
}

func copyToClipboard(value string) {
	utf16, err := windows.UTF16FromString(value)
	if err != nil || call(user, "OpenClipboard", hwnd) == 0 {
		return
	}
	defer call(user, "CloseClipboard")
	call(user, "EmptyClipboard")
	size := uintptr(len(utf16) * 2)
	mem := call(kernel, "GlobalAlloc", 0x0042, size)
	if mem == 0 {
		return
	}
	ptr := call(kernel, "GlobalLock", mem)
	if ptr == 0 {
		call(kernel, "GlobalFree", mem)
		return
	}
	call(kernel, "RtlMoveMemory", ptr, uintptr(unsafe.Pointer(&utf16[0])), size)
	call(kernel, "GlobalUnlock", mem)
	call(user, "SetClipboardData", 13, mem)
}

func main() {
	runtime.LockOSThread()
	mainThreadID = uint32(call(kernel, "GetCurrentThreadId"))
	instance = call(kernel, "GetModuleHandleW", 0)
	mutex, e := windows.CreateMutex(nil, false, u("Local\\SorryRKN.Windows.1"))
	if e == windows.ERROR_ALREADY_EXISTS {
		old := call(user, "FindWindowW", uintptr(unsafe.Pointer(u("SorryRKNWindow"))), 0)
		if old != 0 {
			call(user, "ShowWindow", old, SW_SHOW)
			call(user, "SetForegroundWindow", old)
			call(user, "PostMessageW", old, launchCheckMessage, 0, 0)
		}
		return
	}
	if e != nil {
		errorMessage(e.Error())
		return
	}
	defer windows.CloseHandle(mutex)
	executable, e := os.Executable()
	if e != nil {
		errorMessage(e.Error())
		return
	}
	root = filepath.Join(filepath.Dir(executable), "runtime")
	dir, e := os.UserCacheDir()
	if e != nil {
		errorMessage(e.Error())
		return
	}
	data = filepath.Join(dir, "SorryRKN")
	// Native validation may use an isolated directory, without touching the
	// installed user's preferences, secret, or generated bypass list.
	if len(os.Args) > 2 && os.Args[1] == "--self-test" {
		data, e = filepath.Abs(os.Args[2])
		if e != nil {
			errorMessage(e.Error())
			return
		}
	}
	os.MkdirAll(data, 0700)
	if _, e = os.Stat(filepath.Join(root, "zapret", "bin", "winws.exe")); e != nil {
		errorMessage("Не найдены компоненты. Распакуйте архив целиком или установите SorryRKN через установщик.")
		return
	}
	config = core.LoadConfig(filepath.Join(data, "config.json"))
	if config.LoadError != "" {
		errorMessage(config.LoadError)
		return
	}
	if config.Recovered {
		if e = core.SaveJSON(filepath.Join(data, "config.json"), config); e != nil {
			errorMessage("Не удалось восстановить настройки: " + e.Error())
			return
		}
	}
	if config.ProtectedSecret == "" {
		secret, e = core.NewSecret()
		if e == nil {
			config.ProtectedSecret, e = platform.ProtectSecret(secret)
		}
		if e == nil {
			e = core.SaveJSON(filepath.Join(data, "config.json"), config)
		}
	} else {
		secret, e = platform.UnprotectSecret(config.ProtectedSecret)
	}
	if e != nil {
		errorMessage("Не удалось открыть защищённый секрет Telegram. Запустите приложение под тем же пользователем Windows.\n" + e.Error())
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--self-test" {
		selfTest()
		return
	}
	startMinimized := false
	for _, arg := range os.Args[1:] {
		if arg == "--minimized" {
			startMinimized = true
		}
	}
	if p := proc(user, "SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	dpi := call(user, "GetDpiForSystem")
	if dpi >= 96 {
		scale = float64(dpi) / 96
	}
	icon = call(user, "LoadImageW", instance, 1, 1, uintptr(dp(48)), uintptr(dp(48)), 0x8000)
	cursor := call(user, "LoadCursorW", 0, 32512)
	wc := wndclass{Style: 3, WndProc: windows.NewCallback(windowProc), Instance: instance, Icon: icon, SmallIcon: icon, Cursor: cursor, Class: u("SorryRKNWindow")}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if call(user, "RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
		errorMessage("Не удалось создать окно Windows")
		return
	}
	hwnd = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(wc.Class)), uintptr(unsafe.Pointer(u("SorryRKN"))), 0x02000000|0x00c80000|0x00020000|0x00080000, uintptr(0x80000000), uintptr(0x80000000), uintptr(dp(468)), uintptr(dp(608)), 0, 0, instance, 0)
	if hwnd == 0 {
		errorMessage("Не удалось открыть интерфейс")
		return
	}
	dark := uint32(1)
	if p := proc(dwm, "DwmSetWindowAttribute"); p.Find() == nil {
		p.Call(hwnd, 20, uintptr(unsafe.Pointer(&dark)), 4)
	}
	taskbarMessage = uint32(call(user, "RegisterWindowMessageW", uintptr(unsafe.Pointer(u("TaskbarCreated")))))
	engine = core.NewEngine(root, data, platform.Runner{}, dns, func() { call(user, "PostMessageW", hwnd, REFRESH, 0, 0) })

	// Tactical Remote Controls
	createButton(QuickRulesID, "Правила", 312, 16, 74, 34)
	createButton(MenuID, "Настройки", 392, 16, 38, 34)
	createButton(PowerID, "Включить соединение", 36, 124, 68, 68)
	createButton(QuickRetestID, "Подобрать стратегию заново", 378, 139, 38, 38)

	// 4 Live Service Rows
	createButton(ProfileID, "Выбрать метод обхода", 38, 223, 314, 52)
	createButton(DpiID, "YouTube, Discord и сайты", 360, 234, 54, 30)

	createButton(InstaRowID, "Instagram и сайты со своим IP", 38, 285, 314, 52)
	createButton(InstagramID, "Instagram и Meta", 360, 296, 54, 30)

	createButton(TelegramID, "Telegram MTProto", 360, 358, 54, 30)

	createButton(DnsRowID, "DNS и нейросети", 38, 409, 314, 52)
	createButton(ExtrasID, "Нейросети · Гео-DNS", 360, 420, 54, 30)

	// Bottom Tactical Action Bar
	createButton(LinkID, "Подключить Telegram", 22, 478, 199, 44)
	createButton(DiagBtnID, "Диагностика", 231, 478, 199, 44)

	createModeControls()
	addTray()
	if !startMinimized || !trayAvailable {
		call(user, "ShowWindow", hwnd, SW_SHOW)
		call(user, "UpdateWindow", hwnd)
	} else if !currentConfig().VPNMode {
		c := currentConfig()
		if rules, err := c.Rules(); err == nil && (c.DPI || c.Telegram || c.Extras || c.InstagramEnabled() || len(rules.Geo) > 0 || len(rules.DPI) > 0) {
			_ = engine.Start(c, secret, false, func(id string) { saveConfig(func(cfg *core.Config) { cfg.SavedProfile = id }) })
		}
	}
	go updateStartup()
	if !currentConfig().VPNMode {
		checkDNSProfiles(false)
	}
	var m msg
	for call(user, "GetMessageW", uintptr(unsafe.Pointer(&m)), 0, 0, 0) != 0 {
		if serviceWindow != 0 && call(user, "IsDialogMessageW", serviceWindow, uintptr(unsafe.Pointer(&m))) != 0 {
			continue
		}
		if vpnWindow != 0 && call(user, "IsDialogMessageW", vpnWindow, uintptr(unsafe.Pointer(&m))) != 0 {
			continue
		}
		if dnsWindow != 0 && call(user, "IsDialogMessageW", dnsWindow, uintptr(unsafe.Pointer(&m))) != 0 {
			continue
		}
		if rulesWindow != 0 && call(user, "IsDialogMessageW", rulesWindow, uintptr(unsafe.Pointer(&m))) != 0 {
			continue
		}
		if call(user, "IsDialogMessageW", hwnd, uintptr(unsafe.Pointer(&m))) != 0 {
			continue
		}
		call(user, "TranslateMessage", uintptr(unsafe.Pointer(&m)))
		call(user, "DispatchMessageW", uintptr(unsafe.Pointer(&m)))
	}
}
func createButton(id int, text string, x, y, w, h int) {
	controls[id] = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(u("BUTTON"))), uintptr(unsafe.Pointer(u(text))), 0x50000000|0x00010000|BS_OWNERDRAW, uintptr(dp(x)), uintptr(dp(y)), uintptr(dp(w)), uintptr(dp(h)), hwnd, uintptr(id), instance, 0)
}
func windowProc(window uintptr, messageID uint32, w, l uintptr) uintptr {
	if messageID == taskbarMessage && taskbarMessage != 0 {
		addTray()
		return 0
	}
	switch messageID {
	case launchCheckMessage:
		if !quitting {
			go checkUpdates(false)
		}
		return 0
	case uiAlertMessage:
		alertMu.Lock()
		items := append([][2]string(nil), pendingAlerts...)
		pendingAlerts = nil
		alertMu.Unlock()
		for _, item := range items {
			if !quitting {
				message(item[0], item[1])
			}
		}
		return 0
	case 0x0014: // WM_ERASEBKGND — handled in double-buffered WM_PAINT
		return 1
	case 0x02E0: // WM_DPICHANGED
		newDpi := int(w & 0xffff)
		if newDpi >= 96 {
			scale = float64(newDpi) / 96.0
			for _, f := range fonts {
				call(gdi, "DeleteObject", f)
			}
			fonts = map[int]uintptr{}
			if l != 0 {
				var suggested rect
				call(kernel, "RtlMoveMemory", uintptr(unsafe.Pointer(&suggested)), l, unsafe.Sizeof(suggested))
				call(user, "SetWindowPos", window, 0, uintptr(suggested.Left), uintptr(suggested.Top), uintptr(suggested.Right-suggested.Left), uintptr(suggested.Bottom-suggested.Top), 0x0014)
			}
			refresh()
		}
		return 0
	case vpnDoneMessage:
		finishVPNWork()
		return 0
	case 0x0113:
		if w == vpnTimer {
			watchTunnel()
		}
		return 0
	case dnsDoneMessage:
		refreshDNSWindow()
		return 0
	case WM_PAINT:
		paint(window)
		return 0
	case WM_DRAWITEM:
		if l != 0 {
			var item drawitem
			call(kernel, "RtlMoveMemory", uintptr(unsafe.Pointer(&item)), l, unsafe.Sizeof(item))
			drawButton(&item)
		}
		return 1
	case WM_COMMAND:
		command(int(w & 0xffff))
		return 0
	case REFRESH:
		refresh()
		return 0
	case UPDATE:
		showUpdate(false)
		return 0
	case EXIT:
		quitting = true
		deleteTray()
		call(user, "DestroyWindow", window)
		return 0
	case WM_CLOSE:
		if trayAvailable && !quitting {
			call(user, "ShowWindow", window, SW_HIDE)
		} else {
			shutdown()
		}
		return 0
	case WM_DESTROY:
		call(user, "PostQuitMessage", 0)
		return 0
	case TRAY:
		if uint32(l) == 0x203 || uint32(l) == 0x202 {
			showWindow()
		} else if uint32(l) == 0x205 || uint32(l) == 0x7b {
			menu(true)
		}
		return 0
	case 0x0011:
		stopVPNForExit()
		if engine != nil {
			engine.Stop()
		}
		return 1
	case 0x0016:
		if w != 0 {
			deleteTray()
		}
		return 0
	}
	return call(user, "DefWindowProcW", window, uintptr(messageID), w, l)
}
func showWindow() { call(user, "ShowWindow", hwnd, SW_SHOW); call(user, "SetForegroundWindow", hwnd) }
func refresh() {
	if engine == nil {
		return
	}
	s := engine.Snapshot()
	busy := engine.Busy()
	stopping := s.Status == "stopping"
	c := currentConfig()
	for _, id := range []int{DpiID, InstagramID, TelegramID, ExtrasID, ProfileID, InstaRowID, DnsRowID} {
		call(user, "EnableWindow", controls[id], boolInt(!stopping))
	}
	showRetest := !c.VPNMode && (s.Status == "on" || s.Status == "partial") && c.DPI
	showControl(QuickRetestID, showRetest)
	call(user, "EnableWindow", controls[LinkID], 1)
	label := "Включить соединение"
	if busy || (c.VPNMode && vpnSession.Active()) {
		label = "Выключить соединение"
	}
	call(user, "SetWindowTextW", controls[PowerID], uintptr(unsafe.Pointer(u(label))))
	call(user, "InvalidateRect", hwnd, 0, 0)
	for _, h := range controls {
		call(user, "InvalidateRect", h, 0, 0)
	}
	modifyTray()
}
func boolInt(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
func toggle(extended bool) {
	if currentConfig().VPNMode {
		toggleVPN()
		return
	}
	if engine == nil {
		return
	}
	if engine.Busy() {
		go engine.Stop()
		return
	}
	c := currentConfig()
	if e := engine.Start(c, secret, extended, func(id string) { saveConfig(func(c *core.Config) { c.SavedProfile = id }) }); e != nil {
		errorMessage(e.Error())
	}
}
func retest(extended bool) {
	if currentConfig().VPNMode {
		return
	}
	go func() {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		engine.Stop()
		saveConfig(func(c *core.Config) { c.Method = "auto"; c.SavedProfile = "" })
		_ = engine.Start(currentConfig(), secret, extended, func(id string) { saveConfig(func(c *core.Config) { c.SavedProfile = id }) })
	}()
}
func command(id int) {
	if modeCommand(id) {
		return
	}
	switch id {
	case DNSProfilesID, DnsRowID:
		showDNSProfiles()
	case RulesID, QuickRulesID, InstaRowID:
		editRules()
	case PowerID:
		toggle(false)
	case QuickRetestID:
		retest(false)
	case DpiID, InstagramID, TelegramID, ExtrasID:
		saveConfig(func(c *core.Config) {
			switch id {
			case DpiID:
				c.DPI = !c.DPI
			case InstagramID:
				next := !c.InstagramEnabled()
				c.Instagram = &next
			case TelegramID:
				c.Telegram = !c.Telegram
			case ExtrasID:
				c.Extras = !c.Extras
			}
		})
		refresh()
		reloadEngineIfActive()
	case LinkID:
		link, err := core.ProxyLink(secret)
		if err != nil {
			return
		}
		s := engine.Snapshot()
		if s.Telegram && (s.Status == "on" || s.Status == "partial") {
			openURL(link)
		} else {
			copyToClipboard(link)
			message("Telegram MTProto", "Ссылка прокси скопирована в буфер обмена.\nВключите пульт, чтобы локальный прокси 127.0.0.1:1443 начал принимать подключения.")
		}
	case DiagBtnID, DiagnosticsID:
		diagnostics()
	case MenuID:
		menu(false)
	case ProfileID:
		chooseProfile()
	case OpenID:
		showWindow()
	case RetestID:
		retest(false)
	case ExtendedID:
		retest(true)
	case UpdatesID:
		go checkUpdates(true)
	case DataID:
		go dataUpdates(true)
	case AutoDataID:
		saveConfig(func(c *core.Config) { c.AutoData = !c.AutoData })
	case AutoStartID:
		next := !platform.IsAutoStartEnabled()
		if err := platform.SetAutoStart(next, ""); err != nil {
			errorMessage("Не удалось изменить автозапуск: " + err.Error())
		} else {
			saveConfig(func(c *core.Config) { c.AutoStart = next })
		}
	case AboutID:
		message("SorryRKN "+core.Version, "Локальный обход DPI с zapret/winws, Гео-DNS и Telegram MTProto-прокси.\n\nЛюбые переключатели на пульте и настройки DNS/правил применяются на лету без ручного отключения.\n\nПубличные проверки подтверждают сетевой и HTTPS-ответ, но не проверяют вход в аккаунт, платные подписки, звонки или видеопоток на каждом операторе.\n\nЗакрытие окна сворачивает пульт в трей. «Выход» полностью останавливает соединения.")
	case ExitID:
		shutdown()
	default:
		if id >= 300 && id < 400 && !currentConfig().VPNMode {
			catalog, _ := core.LoadCatalog(core.ActiveData(data, filepath.Join(root, "zapret")))
			method := "auto"
			if id > 300 && id-301 < len(catalog.Profiles) {
				method = catalog.Profiles[id-301].ID
			}
			saveConfig(func(c *core.Config) { c.Method = method })
			refresh()
			if currentConfig().DPI {
				reloadEngineIfActive()
			}
		}
	}
}
func shutdown() {
	if quitting {
		return
	}
	quitting = true
	stopVPNForExit()
	dnsCheckMu.Lock()
	if dnsCheckCancel != nil {
		dnsCheckCancel()
	}
	dnsCheckMu.Unlock()
	go func() {
		if engine != nil {
			engine.Stop()
		}
		call(user, "PostMessageW", hwnd, EXIT, 0, 0)
	}()
}
func openURL(value string) {
	call(shell, "ShellExecuteW", hwnd, uintptr(unsafe.Pointer(u("open"))), uintptr(unsafe.Pointer(u(value))), 0, 0, SW_SHOW)
}
func addItem(menu uintptr, id int, label string, checked, disabled bool) {
	flags := uintptr(0)
	if checked {
		flags |= 8
	}
	if disabled {
		flags |= 1
	}
	call(user, "AppendMenuW", menu, flags, uintptr(id), uintptr(unsafe.Pointer(u(label))))
}
func popup(menu uintptr) {
	var p point
	call(user, "GetCursorPos", uintptr(unsafe.Pointer(&p)))
	call(user, "SetForegroundWindow", hwnd)
	id := call(user, "TrackPopupMenu", menu, 0x100|2, uintptr(p.X), uintptr(p.Y), 0, hwnd, 0)
	call(user, "DestroyMenu", menu)
	call(user, "PostMessageW", hwnd, 0, 0, 0)
	if id != 0 {
		command(int(id))
	}
}
func menu(tray bool) {
	m := call(user, "CreatePopupMenu")
	if tray {
		addItem(m, OpenID, "Открыть SorryRKN", false, false)
	}
	label := "Включить"
	if engine.Busy() || vpnSession.Active() {
		label = "Выключить"
	}
	addItem(m, PowerID, label, false, false)
	call(user, "AppendMenuW", m, 0x800, 0, 0)
	if !currentConfig().VPNMode {
		addItem(m, RetestID, "Подобрать заново", false, false)
		addItem(m, ExtendedID, "Расширенный подбор", false, false)
		addItem(m, RulesID, "Мои ресурсы", false, false)
		addItem(m, DNSProfilesID, "DNS и нейросети", false, false)
	} else {
		addItem(m, vpnServerID, "Свой сервер", false, false)
		addItem(m, vpnSourcesID, "Подписки и узлы", false, false)
	}
	addItem(m, vpnModeID, "Режим работы…", false, false)
	call(user, "AppendMenuW", m, 0x800, 0, 0)
	addItem(m, AutoStartID, "Запускать вместе с Windows", platform.IsAutoStartEnabled(), false)
	addItem(m, AutoDataID, "Обновлять списки автоматически", currentConfig().AutoData, false)
	addItem(m, DataID, "Обновить списки сейчас", false, false)
	addItem(m, UpdatesID, "Проверить обновление приложения", false, false)
	addItem(m, DiagnosticsID, "Диагностика", false, false)
	addItem(m, AboutID, "О приложении", false, false)
	call(user, "AppendMenuW", m, 0x800, 0, 0)
	addItem(m, ExitID, "Выход", false, false)
	popup(m)
}
func chooseProfile() {
	if engine != nil && engine.Snapshot().Status == "stopping" {
		return
	}
	catalog, e := core.LoadCatalog(core.ActiveData(data, filepath.Join(root, "zapret")))
	if e != nil {
		errorMessage(e.Error())
		return
	}
	m := call(user, "CreatePopupMenu")
	selected := currentConfig().Method
	addItem(m, 300, "Автоматически — быстрый подбор", selected == "auto", false)
	for i, p := range catalog.Profiles {
		addItem(m, 301+i, p.Name, p.ID == selected, false)
	}
	popup(m)
}
func trayData() notifyicon {
	n := notifyicon{Hwnd: hwnd, ID: 1, Flags: 1 | 2 | 4, Callback: TRAY, Icon: icon}
	n.Size = uint32(unsafe.Sizeof(n))
	text := "SorryRKN · Выключено"
	if engine != nil {
		s := engine.Snapshot()
		switch s.Status {
		case "on":
			text = "SorryRKN · Подключено"
		case "partial":
			text = "SorryRKN · Частично"
		case "starting":
			text = "SorryRKN · Подключение…"
		case "error":
			text = "SorryRKN · Ошибка"
		}
	}
	if currentConfig().VPNMode {
		text = "SorryRKN · VPN выключен"
		if vpnSession.Active() {
			text = "SorryRKN · VPN включён"
		}
	}
	t, _ := windows.UTF16FromString(text)
	copy(n.Tip[:], t)
	return n
}
func addTray() {
	n := trayData()
	trayAvailable = call(shell, "Shell_NotifyIconW", 0, uintptr(unsafe.Pointer(&n))) != 0
}
func modifyTray() {
	if !trayAvailable {
		return
	}
	n := trayData()
	call(shell, "Shell_NotifyIconW", 1, uintptr(unsafe.Pointer(&n)))
}
func deleteTray() {
	if !trayAvailable {
		return
	}
	n := trayData()
	call(shell, "Shell_NotifyIconW", 2, uintptr(unsafe.Pointer(&n)))
	trayAvailable = false
}
func updateStartup() {
	checkUpdates(false)
	if currentConfig().AutoData {
		var s struct {
			Time int64 `json:"time"`
		}
		b, _ := os.ReadFile(filepath.Join(data, "data-check.json"))
		json.Unmarshal(b, &s)
		if time.Now().Unix()-s.Time > 24*3600 {
			dataUpdates(false)
		}
	}
}
func checkUpdates(force bool) {
	if !checkMu.TryLock() {
		return
	}
	defer checkMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, e := core.CheckUpdate(ctx)
	// This record is diagnostic only. A new launch always contacts the feed.
	_ = core.SaveJSON(filepath.Join(data, "update-check.json"), map[string]any{
		"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
		"feed_ok":    e == nil, "offered": e == nil && r.Code > core.VersionCode,
	})
	if e != nil {
		if force {
			message("Обновление SorryRKN", "Не удалось проверить обновления. Попробуйте позже.")
		}
		return
	}
	if r.Code <= core.VersionCode {
		if force {
			message("Обновление SorryRKN", "Установлена последняя версия")
		}
		return
	}
	latestMu.Lock()
	latest = r
	latestMu.Unlock()
	call(user, "PostMessageW", hwnd, UPDATE, 0, 0)
}
func showUpdate(force bool) {
	updateMu.Lock()
	busy := updateBusy
	updateMu.Unlock()
	if updatePrompt || busy || quitting {
		return
	}
	updatePrompt = true
	defer func() { updatePrompt = false }()
	latestMu.Lock()
	r := latest
	latestMu.Unlock()
	if r.Code <= core.VersionCode {
		return
	}
	if call(user, "MessageBoxW", hwnd, uintptr(unsafe.Pointer(u(r.Notes+"\n\nСкачать и установить обновление?"))), uintptr(unsafe.Pointer(u("SorryRKN "+r.Name))), 4|0x40) != 6 {
		return
	}
	updateMu.Lock()
	if updateBusy {
		updateMu.Unlock()
		return
	}
	updateBusy = true
	updateMu.Unlock()
	go func() {
		defer func() { updateMu.Lock(); updateBusy = false; updateMu.Unlock() }()
		path := filepath.Join(data, "update-setup.exe")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if e := core.DownloadUpdate(ctx, r, path); e != nil {
			message("Обновление SorryRKN", "Не удалось скачать или проверить обновление")
			return
		}
		engine.Stop()
		closeTunnelForUpdate()
		result := call(shell, "ShellExecuteW", hwnd, uintptr(unsafe.Pointer(u("open"))), uintptr(unsafe.Pointer(u(path))), 0, 0, SW_SHOW)
		if result <= 32 {
			linkMu.Lock()
			tunnelClosing = false
			linkMu.Unlock()
			errorMessage("Не удалось открыть установщик")
			return
		}
		call(user, "PostMessageW", hwnd, EXIT, 0, 0)
	}()
}
func dataUpdates(force bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	revision, e := core.UpdateData(ctx, data)
	if e != nil {
		if force {
			message("Обновление списков", "Не удалось обновить данные. Используется сохранённый каталог.")
		}
		return
	}
	core.SaveJSON(filepath.Join(data, "data-check.json"), map[string]any{"time": time.Now().Unix(), "revision": revision})
	if force {
		reloadEngineIfActive()
		message("Обновление списков", "Списки и совместимые стратегии обновлены.")
	}
}
func diagnostics() {
	c := currentConfig()
	report := map[string]any{
		"version":            core.Version,
		"platform":           "windows-x64",
		"state":              engine.Snapshot(),
		"dns":                dns.Counters(),
		"instagram":          c.InstagramEnabled(),
		"custom_dpi_count":   len(c.DPIDomains),
		"custom_geo_count":   len(c.GeoDomains),
		"custom_direct_count": len(c.DirectDomains),
		"auto_start":         platform.IsAutoStartEnabled(),
	}
	var telegram any
	b, _ := os.ReadFile(filepath.Join(data, "telegram.log"))
	if len(b) > 65536 {
		b = b[len(b)-65536:]
	}
	lines := strings.Split(string(b), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if json.Unmarshal([]byte(lines[i]), &telegram) == nil {
			report["telegram"] = telegram
			break
		}
	}
	cat, _ := core.LoadCatalog(core.ActiveData(data, filepath.Join(root, "zapret")))
	report["data_revision"] = cat.Revision
	path := filepath.Join(data, "diagnostics.json")
	core.SaveJSON(path, report)
	openURL(path)
}
func selfTest() {
	report := map[string]any{"version": core.Version, "secret_ok": core.ValidSecret(secret)}
	catalog, e := core.LoadCatalog(filepath.Join(root, "zapret"))
	if e != nil {
		report["error"] = e.Error()
	} else {
		report["profiles"] = len(catalog.Profiles)
	}
	encoded, e := platform.ProtectSecret(secret)
	if e == nil {
		decoded, err := platform.UnprotectSecret(encoded)
		report["dpapi"] = err == nil && decoded == secret
	}
	nativeTests(report)
	core.SaveJSON(filepath.Join(data, "self-test.json"), report)
}
