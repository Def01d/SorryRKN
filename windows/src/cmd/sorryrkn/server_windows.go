//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sorryrkn/internal/core"
	"sorryrkn/internal/platform"
	"sorryrkn/internal/selfhost"
	"sorryrkn/internal/tunnel"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type protocolSpec struct {
	Key        string
	Title      string
	ComboLabel string
	InstallAct selfhost.Action
	ExportAct  selfhost.Action
	StopAct    selfhost.Action
	PurgeAct   selfhost.Action
}

var vpnProtocolsList = []protocolSpec{
	{
		Key:        "mirage",
		Title:      "SRKN-Mirage v1 («Мираж»)",
		ComboLabel: "SRKN-Mirage v1 («Мираж» · TCP 2096 · Анти-DPI, uTLS Chrome + обфускация)",
		InstallAct: selfhost.InstallMirage,
		ExportAct:  selfhost.ExportMirage,
		StopAct:    selfhost.StopMirage,
		PurgeAct:   selfhost.PurgeMirage,
	},
	{
		Key:        "reality",
		Title:      "VLESS + REALITY Vision",
		ComboLabel: "VLESS + REALITY (TCP 8443 · Vision, маскировка под TLS 1.3)",
		InstallAct: selfhost.InstallTCP,
		ExportAct:  selfhost.ExportTCP,
		StopAct:    selfhost.StopTCP,
		PurgeAct:   selfhost.PurgeTCP,
	},
	{
		Key:        "https",
		Title:      "HTTPS / NaïveProxy",
		ComboLabel: "HTTPS / NaïveProxy (TCP 443 · трафик Chrome HTTP/2 + UDP)",
		InstallAct: selfhost.InstallHTTPS,
		ExportAct:  selfhost.ExportHTTPS,
		StopAct:    selfhost.StopHTTPS,
		PurgeAct:   selfhost.PurgeHTTPS,
	},
	{
		Key:        "hy2",
		Title:      "Hysteria2 + Salamander",
		ComboLabel: "Hysteria2 + Salamander (UDP 8443 · быстрый QUIC с обфускацией)",
		InstallAct: selfhost.InstallHy2,
		ExportAct:  selfhost.ExportHy2,
		StopAct:    selfhost.StopHy2,
		PurgeAct:   selfhost.PurgeHy2,
	},
	{
		Key:        "grpc",
		Title:      "VLESS + REALITY gRPC",
		ComboLabel: "VLESS + REALITY gRPC (TCP 2053 · мультиплексированный HTTP/2)",
		InstallAct: selfhost.InstallGRPC,
		ExportAct:  selfhost.ExportGRPC,
		StopAct:    selfhost.StopGRPC,
		PurgeAct:   selfhost.PurgeGRPC,
	},
	{
		Key:        "ss2022",
		Title:      "Shadowsocks 2022",
		ComboLabel: "Shadowsocks 2022 (TCP+UDP 2083 · AEAD 2022-blake3-aes-256-gcm)",
		InstallAct: selfhost.InstallSS2022,
		ExportAct:  selfhost.ExportSS2022,
		StopAct:    selfhost.StopSS2022,
		PurgeAct:   selfhost.PurgeSS2022,
	},
}

type savedServer struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	User           string            `json:"user"`
	KeyPath        string            `json:"key_path,omitempty"`
	EncPassword    string            `json:"enc_password,omitempty"`
	Fleet          map[string]string `json:"fleet,omitempty"`
	Nodes          map[string]string `json:"nodes,omitempty"`
	PublicSOCKS    string            `json:"public_socks,omitempty"`
	PublicTelegram string            `json:"public_telegram,omitempty"`
}

type serverPrefs struct {
	SchemaVersion int               `json:"schema_version,omitempty"`
	ActiveID      string            `json:"active_id,omitempty"`
	Servers       []savedServer     `json:"servers,omitempty"`
	ClientID      string            `json:"client_id,omitempty"`
	Pins          map[string]string `json:"pins,omitempty"`
	// Legacy v1 fields retained solely for seamless upgrade migration.
	Host, User, KeyPath string
	Port                int
}

var sshPrefs serverPrefs
var prefsError error
var editingNewServer bool

const (
	sshHost = 1210 + iota
	sshPort
	sshUser
	sshPass
	sshKey
	sshActions
	sshRun
	sshOutput
	sshForget
)

const (
	sshServerList      = 1220
	sshNewServer       = 1221
	sshSaveServer      = 1222
	sshDelServer       = 1223
	sshName            = 1224
	sshRememberPass    = 1225
	sshFleetCheck      = 1227
	sshPurgeAll        = 1228
	sshProtoStop       = 1229
	sshProtoPurge      = 1230
	sshProtoCopy       = 1231
	sshProtoStatusLine = 1232
	sshSocksSSH        = 1233
	sshSocksPub        = 1234
	sshSocksCopy       = 1235
	sshSocksTelegram   = 1236
	sshSocksPurge      = 1237
	sshSocksStatusLine = 1238
	sshHeaderStatus    = 1239
)

var forwardMu sync.Mutex
var activeForward *selfhost.SOCKSForward
var forwardHost string
var forwardTelegramURL string
var forwardLifetime, endForwardLifetime = context.WithCancel(context.Background())

func replaceForward(address string, f *selfhost.SOCKSForward) {
	forwardMu.Lock()
	defer forwardMu.Unlock()
	if f == nil && address != "" && address != forwardHost {
		return
	}
	if activeForward != nil {
		activeForward.Close()
	}
	activeForward, forwardHost = f, address
	forwardTelegramURL = ""
	if f != nil {
		if u, err := url.Parse(f.URL); err == nil && u.User != nil {
			pw, _ := u.User.Password()
			forwardTelegramURL = "tg://socks?" + (url.Values{
				"server": {u.Hostname()},
				"port":   {u.Port()},
				"user":   {u.User.Username()},
				"pass":   {pw},
			}).Encode()
		}
	}
}

func currentForwardLabel() string {
	forwardMu.Lock()
	defer forwardMu.Unlock()
	if activeForward == nil {
		return ""
	}
	return "SOCKS5 (SSH) через " + forwardHost + " -> " + activeForward.URL
}

func currentForwardURLs() (socksURL, tgURL string) {
	forwardMu.Lock()
	defer forwardMu.Unlock()
	if activeForward == nil {
		return "", ""
	}
	return activeForward.URL, forwardTelegramURL
}

func serverPrefsPath() string { return filepath.Join(data, "ssh-servers.json") }

func readServerPrefs() {
	sshPrefs = serverPrefs{SchemaVersion: 2, User: "root", Port: 22, Pins: map[string]string{}}
	b, e := os.ReadFile(serverPrefsPath())
	if errors.Is(e, os.ErrNotExist) {
		e = nil
	} else if e == nil {
		e = json.Unmarshal(b, &sshPrefs)
	}
	prefsError = e
	if sshPrefs.Pins == nil {
		sshPrefs.Pins = map[string]string{}
	}
	if len(sshPrefs.Servers) == 0 && strings.TrimSpace(sshPrefs.Host) != "" {
		port := sshPrefs.Port
		if port < 1 || port > 65535 {
			port = 22
		}
		user := strings.TrimSpace(sshPrefs.User)
		if user == "" {
			user = "root"
		}
		id, _ := selfhost.NewClientID()
		if id == "" {
			id = fmt.Sprintf("%x", time.Now().UnixNano())
		}
		sshPrefs.Servers = []savedServer{{
			ID:      id,
			Name:    strings.TrimSpace(sshPrefs.Host),
			Host:    strings.TrimSpace(sshPrefs.Host),
			Port:    port,
			User:    user,
			KeyPath: strings.TrimSpace(sshPrefs.KeyPath),
			Fleet:   map[string]string{},
			Nodes:   map[string]string{},
		}}
		sshPrefs.ActiveID = id
		sshPrefs.SchemaVersion = 2
	}
	for i := range sshPrefs.Servers {
		if sshPrefs.Servers[i].Port < 1 || sshPrefs.Servers[i].Port > 65535 {
			sshPrefs.Servers[i].Port = 22
		}
		if sshPrefs.Servers[i].User == "" {
			sshPrefs.Servers[i].User = "root"
		}
		if sshPrefs.Servers[i].Name == "" {
			sshPrefs.Servers[i].Name = sshPrefs.Servers[i].Host
		}
		if sshPrefs.Servers[i].Fleet == nil {
			sshPrefs.Servers[i].Fleet = map[string]string{}
		}
		if sshPrefs.Servers[i].Nodes == nil {
			sshPrefs.Servers[i].Nodes = map[string]string{}
		}
	}
	if sshPrefs.ActiveID == "" && len(sshPrefs.Servers) > 0 {
		sshPrefs.ActiveID = sshPrefs.Servers[0].ID
	}
}

func activeServerIndex() int {
	for i, s := range sshPrefs.Servers {
		if s.ID == sshPrefs.ActiveID {
			return i
		}
	}
	if len(sshPrefs.Servers) > 0 {
		return 0
	}
	return -1
}

func createServerPage() {
	readServerPrefs()
	editingNewServer = len(sshPrefs.Servers) == 0

	// Left Column: Multi-server manager (x=16..308, y=60..596)
	caption("Сохранённые серверы", 28, 70, 268)
	field("LISTBOX", "", sshServerList, 28, 94, 268, 112, 0x00A10101)
	smallBtn(sshNewServer, "+ Новый", 28, 214, 84, 30)
	smallBtn(sshSaveServer, "Сохранить", 118, 214, 90, 30)
	smallBtn(sshDelServer, "Удалить", 214, 214, 82, 30)

	caption("Название сервера", 28, 254, 268)
	input(sshName, "", 28, 276, 268, 0)
	caption("IP / домен VPS", 28, 310, 186)
	caption("Порт", 222, 310, 74)
	input(sshHost, "", 28, 332, 186, 0)
	input(sshPort, "22", 222, 332, 74, 0)
	caption("Пользователь", 28, 366, 126)
	caption("Пароль SSH", 162, 366, 134)
	input(sshUser, "root", 28, 388, 126, 0)
	input(sshPass, "", 162, 388, 134, 0x20)
	field("BUTTON", "Запомнить пароль (DPAPI)", sshRememberPass, 28, 422, 268, 22, 0x00010003)
	caption("Путь к SSH-ключу (опционально)", 28, 452, 268)
	input(sshKey, "", 28, 474, 268, 0)
	smallBtn(sshForget, "Забыть SSH-ключ", 28, 514, 268, 32)

	// Right Column Card 1: Fleet Header & Maintenance (x=322..888, y=60..150)
	field("STATIC", "Добавьте VPS слева или выберите из списка.", sshHeaderStatus, 336, 70, 538, 22, 0)
	button(sshFleetCheck, "Обновить статус всех служб", 336, 104, 260)
	button(sshPurgeAll, "Удалить всё SorryRKN с VPS", 608, 104, 266)

	// Right Column Card 2: Modern VPN Protocols (x=322..888, y=162..342)
	caption("Современные VPN-протоколы на VPS", 336, 172, 538)
	h := field("COMBOBOX", "", sshActions, 336, 196, 538, 240, 0x00210003)
	for _, p := range vpnProtocolsList {
		comboAdd(h, p.ComboLabel)
	}
	comboSelect(h, 0)
	field("STATIC", "", sshProtoStatusLine, 336, 230, 538, 22, 0)
	smallBtn(sshRun, "Установить и выбрать узел", 336, 260, 260, 32)
	smallBtn(sshProtoCopy, "Копировать VPN-ссылку", 608, 260, 266, 32)
	smallBtn(sshProtoStop, "Остановить протокол", 336, 298, 260, 32)
	smallBtn(sshProtoPurge, "Удалить протокол с VPS", 608, 298, 266, 32)

	// Right Column Card 3: SOCKS5 Proxy & Telegram (x=322..888, y=354..478)
	caption("SOCKS5-прокси (приватный через SSH или публичный с паролем)", 336, 364, 538)
	field("STATIC", "", sshSocksStatusLine, 336, 386, 538, 20, 0)
	smallBtn(sshSocksSSH, "SOCKS5 через SSH (127.0.0.1)", 336, 410, 260, 30)
	smallBtn(sshSocksPub, "Публичный SOCKS5 (10808)", 608, 410, 266, 30)
	smallBtn(sshSocksCopy, "Копировать SOCKS5", 336, 444, 172, 28)
	smallBtn(sshSocksTelegram, "Открыть в Telegram", 518, 444, 176, 28)
	smallBtn(sshSocksPurge, "Удалить SOCKS5", 704, 444, 170, 28)

	// Output Log + Close
	field("EDIT", "Готов к работе. Выберите протокол (рекомендуем SRKN-Mirage v1 «Мираж» или VLESS REALITY) либо поднимите SOCKS5.", sshOutput, 322, 488, 566, 64, 0x00810844)
	button(2, "Закрыть", 748, 562, 140)

	rebuildServerList()
	syncServerForm()

	if details := currentForwardLabel(); details != "" {
		setLabel(fields[sshOutput], details)
	}
	if prefsError != nil {
		setLabel(fields[sshOutput], "Не удалось прочитать список серверов. "+prefsError.Error())
		call(user, "EnableWindow", fields[sshRun], 0)
	}
}

func smallBtn(id int, label string, x, y, w, h int) {
	field("BUTTON", label, id, x, y, w, h, 0x10000)
}
func comboAdd(h uintptr, s string) {
	call(user, "SendMessageW", h, 0x0143, 0, uintptr(unsafe.Pointer(u(s))))
}
func comboSelect(h uintptr, n int) { call(user, "SendMessageW", h, 0x014e, uintptr(n), 0) }
func comboIndex(h uintptr) int     { return int(call(user, "SendMessageW", h, 0x0147, 0, 0)) }
func confirm(title, question string) bool {
	return call(user, "MessageBoxW", vpnWindow, uintptr(unsafe.Pointer(u(question))), uintptr(unsafe.Pointer(u(title))), 0x124) == 6
}
func checkState(id int) bool {
	return call(user, "SendMessageW", fields[id], 0x00F0, 0, 0) == 1
}
func setCheckState(id int, checked bool) {
	var state uintptr
	if checked {
		state = 1
	}
	call(user, "SendMessageW", fields[id], 0x00F1, state, 0)
}

func rebuildServerList() {
	h := fields[sshServerList]
	call(user, "SendMessageW", h, 0x0184, 0, 0) // LB_RESETCONTENT
	activeIdx := activeServerIndex()
	for i, s := range sshPrefs.Servers {
		title := s.Name
		if title == "" {
			title = s.Host
		}
		line := fmt.Sprintf("%s (%s:%d)", title, s.Host, s.Port)
		call(user, "SendMessageW", h, 0x0180, 0, uintptr(unsafe.Pointer(u(line))))
		if i == activeIdx && !editingNewServer {
			call(user, "SendMessageW", h, 0x0186, uintptr(i), 0) // LB_SETCURSEL
		}
	}
}

func syncServerForm() {
	idx := activeServerIndex()
	if editingNewServer || idx < 0 {
		setLabel(fields[sshName], "")
		setLabel(fields[sshHost], "")
		setLabel(fields[sshPort], "22")
		setLabel(fields[sshUser], "root")
		setLabel(fields[sshPass], "")
		setLabel(fields[sshKey], "")
		setCheckState(sshRememberPass, false)
		setLabel(fields[sshHeaderStatus], "Новый сервер · Заполните данные и нажмите «Сохранить»")
		setLabel(fields[sshProtoStatusLine], "Нет активного сервера")
		setLabel(fields[sshSocksStatusLine], "SOCKS5 не настроен")
		return
	}

	s := sshPrefs.Servers[idx]
	setLabel(fields[sshName], s.Name)
	setLabel(fields[sshHost], s.Host)
	setLabel(fields[sshPort], strconv.Itoa(s.Port))
	setLabel(fields[sshUser], s.User)
	setLabel(fields[sshKey], s.KeyPath)
	if s.EncPassword != "" {
		if plain, err := platform.UnprotectText(s.EncPassword); err == nil {
			setLabel(fields[sshPass], plain)
			setCheckState(sshRememberPass, true)
		} else {
			setLabel(fields[sshPass], "")
			setCheckState(sshRememberPass, false)
		}
	} else {
		setLabel(fields[sshPass], "")
		setCheckState(sshRememberPass, false)
	}

	addr := net.JoinHostPort(strings.ToLower(s.Host), strconv.Itoa(s.Port))
	pinText := "ключ SSH новый (проверится при подключении)"
	if sshPrefs.Pins[addr] != "" {
		pinText = "ключ SSH подтверждён"
	}
	setLabel(fields[sshHeaderStatus], fmt.Sprintf("%s (%s:%d) · %s", s.Name, s.Host, s.Port, pinText))

	syncProtoSummary(s)
	syncSocksSummary(s)
}

func syncProtoSummary(s savedServer) {
	badges := map[string]string{"running": "вкл", "stopped": "выкл", "missing": "нет"}
	var items []string
	for _, spec := range vpnProtocolsList {
		st := s.Fleet[spec.Key]
		label := badges[st]
		if label == "" {
			if s.Nodes[spec.Key] != "" {
				label = "сохранён"
			} else {
				label = "не уст."
			}
		}
		short := map[string]string{
			"mirage":  "Мираж",
			"reality": "REALITY",
			"https":   "HTTPS",
			"hy2":     "Hy2",
			"grpc":    "gRPC",
			"ss2022":  "SS2022",
		}[spec.Key]
		items = append(items, short+": "+label)
	}
	setLabel(fields[sshProtoStatusLine], strings.Join(items, " · "))
}

func syncSocksSummary(s savedServer) {
	sshURL, _ := currentForwardURLs()
	var parts []string
	if sshURL != "" {
		parts = append(parts, "SSH-туннель: "+sshURL)
	} else {
		st := s.Fleet["socks_ssh"]
		if st == "" {
			st = "не активен"
		}
		parts = append(parts, "SSH: "+st)
	}
	if s.PublicSOCKS != "" {
		parts = append(parts, "Публ.: "+s.PublicSOCKS)
	} else if st := s.Fleet["socks_pub"]; st != "" {
		parts = append(parts, "Публ.: "+st)
	}
	setLabel(fields[sshSocksStatusLine], strings.Join(parts, "  |  "))
}

func readFormServer(existing *savedServer) (savedServer, string, error) {
	host := strings.TrimSpace(editText(fields[sshHost]))
	port, e := strconv.Atoi(strings.TrimSpace(editText(fields[sshPort])))
	user := strings.TrimSpace(editText(fields[sshUser]))
	if user == "" {
		user = "root"
	}
	if host == "" || e != nil || port < 1 || port > 65535 {
		return savedServer{}, "", errors.New("Укажите адрес VPS и корректный порт SSH (1–65535).")
	}
	name := strings.TrimSpace(editText(fields[sshName]))
	if name == "" {
		name = host
	}
	pass := editText(fields[sshPass])
	keyPath := strings.TrimSpace(editText(fields[sshKey]))
	var out savedServer
	if existing != nil {
		out = *existing
	} else {
		id, err := selfhost.NewClientID()
		if err != nil {
			return savedServer{}, "", err
		}
		out.ID = id
		out.Fleet = map[string]string{}
		out.Nodes = map[string]string{}
	}
	out.Name = name
	out.Host = host
	out.Port = port
	out.User = user
	out.KeyPath = keyPath
	if checkState(sshRememberPass) && pass != "" {
		enc, err := platform.ProtectText(pass)
		if err != nil {
			return savedServer{}, "", err
		}
		out.EncPassword = enc
	} else if !checkState(sshRememberPass) {
		out.EncPassword = ""
	}
	return out, pass, nil
}

func saveServerEntry(s savedServer) (int, error) {
	if sshPrefs.ClientID == "" {
		cid, err := selfhost.NewClientID()
		if err != nil {
			return -1, err
		}
		sshPrefs.ClientID = cid
	}
	idx := -1
	for i := range sshPrefs.Servers {
		if sshPrefs.Servers[i].ID == s.ID {
			idx = i
			sshPrefs.Servers[i] = s
			break
		}
	}
	if idx < 0 {
		sshPrefs.Servers = append(sshPrefs.Servers, s)
		idx = len(sshPrefs.Servers) - 1
	}
	sshPrefs.ActiveID = s.ID
	sshPrefs.SchemaVersion = 2
	if err := core.SaveJSON(serverPrefsPath(), sshPrefs); err != nil {
		return -1, err
	}
	editingNewServer = false
	return idx, nil
}

func removeSourcesForServer(lib *tunnel.Library, srv savedServer, onlyProto string) {
	targetPrefix := "vps/" + srv.ID + "/"
	legacyAddr := "/" + net.JoinHostPort(strings.ToLower(srv.Host), strconv.Itoa(srv.Port))
	var selectedLink string
	if lib.SelectedSource >= 0 && lib.SelectedSource < len(lib.Sources) {
		src := lib.Sources[lib.SelectedSource]
		if lib.SelectedNode >= 0 && lib.SelectedNode < len(src.Profiles) {
			selectedLink = src.Profiles[lib.SelectedNode].Link
		}
	}
	kept := make([]tunnel.Source, 0, len(lib.Sources))
	for _, src := range lib.Sources {
		if onlyProto != "" {
			if src.ManagedID == targetPrefix+onlyProto {
				continue
			}
		} else if strings.HasPrefix(src.ManagedID, targetPrefix) || (src.ManagedID != "" && strings.HasSuffix(src.ManagedID, legacyAddr)) {
			continue
		}
		kept = append(kept, src)
	}
	lib.Sources = kept
	if len(lib.Sources) == 0 {
		lib.SelectedSource, lib.SelectedNode = -1, -1
		return
	}
	for si, src := range lib.Sources {
		for ni, p := range src.Profiles {
			if p.Link == selectedLink {
				lib.SelectedSource, lib.SelectedNode = si, ni
				return
			}
		}
	}
	lib.SelectedSource, lib.SelectedNode = 0, 0
}

func serverCommand(n, notify int) {
	if prefsError != nil {
		errorMessage(prefsError.Error())
		return
	}

	switch n {
	case sshServerList:
		if notify != 1 { // LBN_SELCHANGE
			return
		}
		sel := int(call(user, "SendMessageW", fields[sshServerList], 0x0188, 0, 0))
		if sel >= 0 && sel < len(sshPrefs.Servers) {
			editingNewServer = false
			sshPrefs.ActiveID = sshPrefs.Servers[sel].ID
			_ = core.SaveJSON(serverPrefsPath(), sshPrefs)
			syncServerForm()
		}
		return

	case sshNewServer:
		editingNewServer = true
		call(user, "SendMessageW", fields[sshServerList], 0x0186, ^uintptr(0), 0)
		syncServerForm()
		setLabel(fields[sshOutput], "Заполните параметры нового сервера и нажмите «Сохранить» или сразу установите протокол.")
		return

	case sshSaveServer:
		var cur *savedServer
		if !editingNewServer {
			if idx := activeServerIndex(); idx >= 0 {
				cur = &sshPrefs.Servers[idx]
			}
		}
		srv, _, err := readFormServer(cur)
		if err != nil {
			errorMessage(err.Error())
			return
		}
		if _, err := saveServerEntry(srv); err != nil {
			errorMessage(err.Error())
			return
		}
		rebuildServerList()
		syncServerForm()
		setLabel(fields[sshOutput], "Сервер «"+srv.Name+"» сохранён.")
		return

	case sshDelServer:
		idx := activeServerIndex()
		if editingNewServer || idx < 0 {
			return
		}
		srv := sshPrefs.Servers[idx]
		if !confirm("Удалить сервер", "Удалить «"+srv.Name+"» и его узлы из приложения?\n\nЧтобы удалить службы с самого VPS, сначала нажмите «Удалить всё SorryRKN с VPS».") {
			return
		}
		addr := net.JoinHostPort(strings.ToLower(srv.Host), strconv.Itoa(srv.Port))
		replaceForward(addr, nil)
		sshPrefs.Servers = append(sshPrefs.Servers[:idx], sshPrefs.Servers[idx+1:]...)
		if len(sshPrefs.Servers) > 0 {
			sshPrefs.ActiveID = sshPrefs.Servers[0].ID
		} else {
			sshPrefs.ActiveID = ""
			editingNewServer = true
		}
		if err := core.SaveJSON(serverPrefsPath(), sshPrefs); err != nil {
			errorMessage(err.Error())
			return
		}
		next := copyLibrary()
		removeSourcesForServer(&next, srv, "")
		commitLibrary(next)
		rebuildServerList()
		syncServerForm()
		setLabel(fields[sshOutput], "Сервер «"+srv.Name+"» удалён из списка.")
		return

	case sshProtoCopy:
		idx := activeServerIndex()
		pIdx := comboIndex(fields[sshActions])
		if editingNewServer || idx < 0 || pIdx < 0 || pIdx >= len(vpnProtocolsList) {
			return
		}
		spec := vpnProtocolsList[pIdx]
		link := sshPrefs.Servers[idx].Nodes[spec.Key]
		if link == "" {
			errorMessage("Профиль «" + spec.Title + "» ещё не получен для этого сервера. Нажмите «Установить и выбрать узел».")
			return
		}
		copyToClipboard(link)
		setLabel(fields[sshOutput], "Ссылка "+spec.Title+" скопирована в буфер обмена.")
		return

	case sshSocksCopy:
		sshURL, _ := currentForwardURLs()
		var pubURL string
		if !editingNewServer {
			if idx := activeServerIndex(); idx >= 0 {
				pubURL = sshPrefs.Servers[idx].PublicSOCKS
			}
		}
		target := sshURL
		if target == "" {
			target = pubURL
		}
		if target == "" {
			errorMessage("Сначала запустите «SOCKS5 через SSH» или «Публичный SOCKS5 (10808)».")
			return
		}
		copyToClipboard(target)
		setLabel(fields[sshOutput], "Адрес SOCKS5 скопирован:\r\n"+target)
		return

	case sshSocksTelegram:
		_, sshTG := currentForwardURLs()
		var pubTG string
		if !editingNewServer {
			if idx := activeServerIndex(); idx >= 0 {
				pubTG = sshPrefs.Servers[idx].PublicTelegram
			}
		}
		target := sshTG
		if target == "" {
			target = pubTG
		}
		if target == "" {
			errorMessage("Сначала поднимите SOCKS5 на этом сервере.")
			return
		}
		openURL(target)
		setLabel(fields[sshOutput], "Открываем настройки прокси в Telegram…")
		return
	}

	// Operations below require valid server form data + pinned SSH execution.
	var cur *savedServer
	if !editingNewServer {
		if idx := activeServerIndex(); idx >= 0 {
			cur = &sshPrefs.Servers[idx]
		}
	}
	srv, pass, err := readFormServer(cur)
	if err != nil {
		errorMessage(err.Error())
		return
	}
	address := net.JoinHostPort(strings.ToLower(srv.Host), strconv.Itoa(srv.Port))

	if n == sshForget {
		if _, ok := sshPrefs.Pins[address]; ok && confirm("Ключ SSH", "Забыть сохранённый отпечаток SSH для "+address+"?") {
			old := sshPrefs.Pins[address]
			delete(sshPrefs.Pins, address)
			if e := core.SaveJSON(serverPrefsPath(), sshPrefs); e != nil {
				sshPrefs.Pins[address] = old
				errorMessage(e.Error())
			} else {
				syncServerForm()
				setLabel(fields[sshOutput], "Отпечаток удалён. При следующем соединении потребуется проверка.")
			}
		}
		return
	}

	pIdx := comboIndex(fields[sshActions])
	if pIdx < 0 || pIdx >= len(vpnProtocolsList) {
		pIdx = 0
	}
	spec := vpnProtocolsList[pIdx]

	var action selfhost.Action
	var confirmMsg string
	switch n {
	case sshFleetCheck:
		action = selfhost.FleetStatus
	case sshPurgeAll:
		action = selfhost.PurgeAll
		confirmMsg = "ПОЛНАЯ ОЧИСТКА VPS " + srv.Host + "\n\nБудут остановлены и удалены ВСЕ службы SorryRKN, правила iptables и файлы в /etc/sorryrkn-*.\nПродолжить?"
	case sshRun:
		if libraryError != nil {
			errorMessage(libraryError.Error())
			return
		}
		action = spec.InstallAct
	case sshProtoStop:
		action = spec.StopAct
		confirmMsg = "Остановить «" + spec.Title + "» на сервере " + srv.Host + "?"
	case sshProtoPurge:
		action = spec.PurgeAct
		confirmMsg = "Удалить «" + spec.Title + "» (юнит, конфиги и правило брандмауэра) с сервера " + srv.Host + "?"
	case sshSocksSSH:
		action = selfhost.InstallSOCKS
	case sshSocksPub:
		action = selfhost.InstallPublicSOCKS
	case sshSocksPurge:
		action = selfhost.PurgePublicSOCKS
		confirmMsg = "Остановить и удалить SSH SOCKS5 и публичный SOCKS5 (10808) на сервере " + srv.Host + "?"
	default:
		return
	}

	if confirmMsg != "" && !confirm("Свой сервер", confirmMsg) {
		return
	}

	if _, err := saveServerEntry(srv); err != nil {
		errorMessage(err.Error())
		return
	}
	rebuildServerList()

	sshTarget := selfhost.Server{
		Host:        srv.Host,
		Port:        srv.Port,
		User:        srv.User,
		Password:    pass,
		KeyPath:     srv.KeyPath,
		Fingerprint: sshPrefs.Pins[address],
		ClientID:    sshPrefs.ClientID,
	}

	executeWithPin := func(pin string) {
		sshTarget.Fingerprint = pin
		sshPrefs.Pins[address] = pin
		if err := core.SaveJSON(serverPrefsPath(), sshPrefs); err != nil {
			errorMessage(err.Error())
			return
		}
		setLabel(fields[sshOutput], "")
		startWork("Выполняется SSH-операция…", 10*time.Minute, func(ctx context.Context) (func(), error) {
			result, err := selfhost.Run(ctx, sshTarget, action)
			if err != nil {
				return nil, err
			}
			// If user requested SocksPurge, also clean legacy loopback forward service.
			if action == selfhost.PurgePublicSOCKS {
				_, _ = selfhost.Run(ctx, sshTarget, selfhost.PurgeSOCKS)
			}

			var imported tunnel.Profile
			var hasProfile bool
			if result.NodeURL != "" {
				profiles, impErr := tunnel.Import(ctx, result.NodeURL)
				if impErr != nil {
					return nil, impErr
				}
				if len(profiles) > 0 {
					imported = profiles[0]
					hasProfile = true
				}
			}

			var localSSHURL string
			if result.SOCKSURL != "" {
				c, stop := context.WithCancel(forwardLifetime)
				detach := context.AfterFunc(ctx, stop)
				forward, ferr := selfhost.OpenSOCKS(c, sshTarget, result.SOCKSURL)
				detach()
				if ferr != nil {
					stop()
					return nil, ferr
				}
				replaceForward(address, forward)
				localSSHURL = forward.URL
			}
			if action == selfhost.PurgePublicSOCKS || action == selfhost.PurgeAll {
				replaceForward(address, nil)
			}

			return func() {
				curIdx := -1
				for i := range sshPrefs.Servers {
					if sshPrefs.Servers[i].ID == srv.ID {
						curIdx = i
						break
					}
				}
				msg := result.Status
				if curIdx >= 0 {
					updated := &sshPrefs.Servers[curIdx]
					switch {
					case action == selfhost.PurgeAll:
						updated.Fleet = map[string]string{}
						updated.Nodes = map[string]string{}
						updated.PublicSOCKS = ""
						updated.PublicTelegram = ""
						next := copyLibrary()
						removeSourcesForServer(&next, *updated, "")
						commitLibrary(next)
					case action == selfhost.FleetStatus:
						updated.Fleet = result.Fleet
					case action == spec.PurgeAct:
						updated.Fleet[spec.Key] = "missing"
						delete(updated.Nodes, spec.Key)
						next := copyLibrary()
						removeSourcesForServer(&next, *updated, spec.Key)
						commitLibrary(next)
					case action == spec.StopAct:
						updated.Fleet[spec.Key] = "stopped"
					case action == selfhost.PurgePublicSOCKS:
						updated.PublicSOCKS = ""
						updated.PublicTelegram = ""
						updated.Fleet["socks_pub"] = "missing"
						updated.Fleet["socks_ssh"] = "missing"
					case action == selfhost.InstallPublicSOCKS:
						updated.PublicSOCKS = result.PublicSOCKSURL
						updated.PublicTelegram = result.TelegramURL
						updated.Fleet["socks_pub"] = "running"
						msg += "\r\nSOCKS5: " + result.PublicSOCKSURL + "\r\nTelegram: " + result.TelegramURL
					case action == selfhost.InstallSOCKS:
						updated.Fleet["socks_ssh"] = "running"
					case hasProfile:
						updated.Fleet[spec.Key] = "running"
						updated.Nodes[spec.Key] = result.NodeURL
						imported.Name = spec.Title + " · " + updated.Name
						source := tunnel.Source{
							Name:      imported.Name,
							ManagedID: "vps/" + updated.ID + "/" + spec.Key,
							Profiles:  []tunnel.Profile{imported},
						}
						next := copyLibrary()
						replaceSource(&next, source, -1)
						if commitLibrary(next) {
							msg += "\r\nУзел выбран как активный. Закройте окно и включите VPN."
						}
					}
					_ = core.SaveJSON(serverPrefsPath(), sshPrefs)
				}
				if localSSHURL != "" {
					msg += "\r\nЛокальный SOCKS5: " + localSSHURL
				}
				syncServerForm()
				setLabel(fields[sshOutput], strings.TrimSpace(msg))
			}, nil
		})
	}

	if sshTarget.Fingerprint != "" {
		executeWithPin(sshTarget.Fingerprint)
		return
	}
	startWork("Проверка ключа SSH", 20*time.Second, func(ctx context.Context) (func(), error) {
		fp, err := selfhost.ProbeFingerprint(ctx, sshTarget)
		if err != nil {
			return nil, err
		}
		return func() {
			if confirm("Первое соединение по SSH", fmt.Sprintf("Сверьте отпечаток с консолью VPS %s:\n\n%s\n\nСохранить ключ и выполнить операцию?", address, fp)) {
				executeWithPin(fp)
			}
		}, nil
	})
}
