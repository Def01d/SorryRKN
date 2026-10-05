//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
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
const BG = 0x0c0b0b
const PANEL = 0x171515
const WHITE = 0xeeeeee
const GRAY = 0x8c8585
const BORDER = 0x302c2c
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
const OpenID = 200
const RetestID = 201
const ExtendedID = 202
const UpdatesID = 203
const DataID = 204
const DiagnosticsID = 205
const ExitID = 206
const AutoDataID = 207
const AboutID = 208

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
var latest core.Release
var latestMu sync.Mutex
var updateBusy bool
var updateMu sync.Mutex
var trayAvailable bool
var taskbarMessage uint32
var quitting bool

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
	call(user, "MessageBoxW", hwnd, uintptr(unsafe.Pointer(u(text))), uintptr(unsafe.Pointer(u(title))), 0x40)
}
func errorMessage(text string) { message("SorryRKN", text) }
func main() {
	runtime.LockOSThread()
	instance = call(kernel, "GetModuleHandleW", 0)
	mutex, e := windows.CreateMutex(nil, false, u("Local\\SorryRKN.Windows.1"))
	if e == windows.ERROR_ALREADY_EXISTS {
		old := call(user, "FindWindowW", uintptr(unsafe.Pointer(u("SorryRKNWindow"))), 0)
		if old != 0 {
			call(user, "ShowWindow", old, SW_SHOW)
			call(user, "SetForegroundWindow", old)
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
	os.MkdirAll(data, 0700)
	if _, e = os.Stat(filepath.Join(root, "zapret", "bin", "winws.exe")); e != nil {
		errorMessage("Не найдены компоненты. Распакуйте архив целиком или установите SorryRKN через установщик.")
		return
	}
	config = core.LoadConfig(filepath.Join(data, "config.json"))
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
	hwnd = call(user, "CreateWindowExW", 0, uintptr(unsafe.Pointer(wc.Class)), uintptr(unsafe.Pointer(u("SorryRKN"))), 0x00c80000|0x00020000|0x00080000, uintptr(0x80000000), uintptr(0x80000000), uintptr(dp(476)), uintptr(dp(760)), 0, 0, instance, 0)
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
	createButton(PowerID, "Включить соединение", 142, 115, 176, 176)
	createButton(DpiID, "Обход DPI", 365, 405, 58, 32)
	createButton(TelegramID, "Telegram", 365, 465, 58, 32)
	createButton(ExtrasID, "Нейросети и Instagram", 365, 525, 58, 32)
	createButton(LinkID, "Подключить Telegram", 28, 585, 404, 46)
	createButton(MenuID, "Настройки", 389, 22, 44, 44)
	createButton(ProfileID, "Выбрать метод обхода", 44, 390, 286, 53)
	addTray()
	call(user, "ShowWindow", hwnd, SW_SHOW)
	call(user, "UpdateWindow", hwnd)
	go updateStartup()
	var m msg
	for call(user, "GetMessageW", uintptr(unsafe.Pointer(&m)), 0, 0, 0) != 0 {
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
	case WM_PAINT:
		paint(window)
		return 0
	case WM_DRAWITEM:
		drawButton((*drawitem)(unsafe.Pointer(l)))
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
	for _, id := range []int{DpiID, TelegramID, ExtrasID, ProfileID} {
		flag := uintptr(1)
		if busy {
			flag = 0
		}
		call(user, "EnableWindow", controls[id], flag)
	}
	call(user, "EnableWindow", controls[LinkID], boolInt(s.Telegram && (s.Status == "on" || s.Status == "partial")))
	label := "Включить соединение"
	if busy {
		label = "Выключить соединение"
	}
	call(user, "SetWindowTextW", controls[PowerID], uintptr(unsafe.Pointer(u(label))))
	call(user, "InvalidateRect", hwnd, 0, 1)
	for _, h := range controls {
		call(user, "InvalidateRect", h, 0, 1)
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
	go func() {
		engine.Stop()
		saveConfig(func(c *core.Config) { c.Method = "auto"; c.SavedProfile = "" })
		engine.Start(currentConfig(), secret, extended, func(id string) { saveConfig(func(c *core.Config) { c.SavedProfile = id }) })
	}()
}
func command(id int) {
	switch id {
	case PowerID:
		toggle(false)
	case DpiID, TelegramID, ExtrasID:
		if !engine.Busy() {
			saveConfig(func(c *core.Config) {
				switch id {
				case DpiID:
					c.DPI = !c.DPI
				case TelegramID:
					c.Telegram = !c.Telegram
				case ExtrasID:
					c.Extras = !c.Extras
				}
			})
			refresh()
		}
	case LinkID:
		if engine.Snapshot().Telegram {
			link, _ := core.ProxyLink(secret)
			openURL(link)
		}
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
	case DiagnosticsID:
		diagnostics()
	case AboutID:
		message("SorryRKN "+core.Version, "Локальный обход DPI с zapret/winws и Telegram-прокси Flowseal.\n\nНейросети: выборочный Comss DNS. Браузер должен использовать системный DNS; собственный защищённый DNS может обходить профиль. Доступ зависит от сети и сервиса.\n\nЗакрытие окна сворачивает приложение в трей. «Выход» выключает соединения.\n\nЛицензии открытых компонентов находятся в папке licenses рядом с приложением.")
	case ExitID:
		shutdown()
	default:
		if id >= 300 && id < 400 && !engine.Busy() {
			catalog, _ := core.LoadCatalog(core.ActiveData(data, filepath.Join(root, "zapret")))
			method := "auto"
			if id > 300 && id-301 < len(catalog.Profiles) {
				method = catalog.Profiles[id-301].ID
			}
			saveConfig(func(c *core.Config) { c.Method = method })
			refresh()
		}
	}
}
func shutdown() {
	if quitting {
		return
	}
	quitting = true
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
	if engine.Busy() {
		label = "Выключить"
	}
	addItem(m, PowerID, label, false, false)
	call(user, "AppendMenuW", m, 0x800, 0, 0)
	addItem(m, RetestID, "Подобрать заново", false, false)
	addItem(m, ExtendedID, "Расширенный подбор", false, false)
	addItem(m, UpdatesID, "Обновить приложение", false, false)
	addItem(m, DataID, "Обновить данные GitHub", false, false)
	addItem(m, AutoDataID, "Обновлять данные автоматически", currentConfig().AutoData, false)
	addItem(m, DiagnosticsID, "Диагностика", false, false)
	addItem(m, AboutID, "О приложении", false, false)
	call(user, "AppendMenuW", m, 0x800, 0, 0)
	addItem(m, ExitID, "Выход", false, false)
	popup(m)
}
func chooseProfile() {
	if engine.Busy() {
		return
	}
	catalog, e := core.LoadCatalog(core.ActiveData(data, filepath.Join(root, "zapret")))
	if e != nil {
		errorMessage(e.Error())
		return
	}
	m := call(user, "CreatePopupMenu")
	selected := currentConfig().Method
	addItem(m, 300, "Автоматически", selected == "auto", false)
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
			text = "SorryRKN · Включён"
		case "partial":
			text = "SorryRKN · Частично"
		case "starting":
			text = "SorryRKN · Подключение"
		case "error":
			text = "SorryRKN · Ошибка"
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
	var stamp struct {
		Time int64 `json:"time"`
	}
	b, _ := os.ReadFile(filepath.Join(data, "update-check.json"))
	json.Unmarshal(b, &stamp)
	if time.Now().Unix()-stamp.Time > 6*3600 {
		checkUpdates(false)
	}
	if currentConfig().AutoData {
		var s struct {
			Time int64 `json:"time"`
		}
		b, _ = os.ReadFile(filepath.Join(data, "data-check.json"))
		json.Unmarshal(b, &s)
		if time.Now().Unix()-s.Time > 24*3600 {
			dataUpdates(false)
		}
	}
}
func checkUpdates(force bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, e := core.CheckUpdate(ctx)
	if e != nil {
		if force {
			message("Обновление SorryRKN", "Не удалось проверить обновления. Попробуйте позже.")
		}
		return
	}
	core.SaveJSON(filepath.Join(data, "update-check.json"), map[string]int64{"time": time.Now().Unix()})
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
		result := call(shell, "ShellExecuteW", hwnd, uintptr(unsafe.Pointer(u("open"))), uintptr(unsafe.Pointer(u(path))), 0, 0, SW_SHOW)
		if result <= 32 {
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
			message("Данные GitHub", "Не удалось обновить данные. Используется сохранённый каталог.")
		}
		return
	}
	core.SaveJSON(filepath.Join(data, "data-check.json"), map[string]any{"time": time.Now().Unix(), "revision": revision})
	if force {
		message("Данные GitHub", "Списки и совместимые методы обновлены. Будут использованы при следующем включении.")
	}
}
func diagnostics() {
	report := map[string]any{"version": core.Version, "platform": "windows-x64", "state": engine.Snapshot(), "dns": dns.Counters()}
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
	c, _ := core.LoadCatalog(core.ActiveData(data, filepath.Join(root, "zapret")))
	report["data_revision"] = c.Revision
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
	fmt.Println("self-test", report)
}
