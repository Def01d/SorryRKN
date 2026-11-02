//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sorryrkn/internal/core"
	"sorryrkn/internal/selfhost"
	"sorryrkn/internal/tunnel"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type serverPrefs struct {
	Host, User, KeyPath, ClientID string
	Port                          int
	Pins                          map[string]string
}

var sshPrefs serverPrefs
var prefsError error

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

type serverAction struct {
	label  string
	action selfhost.Action
}

var sshActionsList = []serverAction{
	{"Установить WireGuard и добавить узел", selfhost.InstallVPN},
	{"Состояние WireGuard и SOCKS5", selfhost.Status},
	{"Запустить VPN на сервере", selfhost.StartVPN},
	{"Остановить VPN на сервере", selfhost.StopVPN},
	{"Добавить узел с настроенного сервера", selfhost.ExportVPN},
	{"Включить SOCKS5 внутри VPN", selfhost.InstallSOCKS},
	{"Остановить SOCKS5", selfhost.StopSOCKS},
	{"Установить TCP · VLESS REALITY", selfhost.InstallTCP},
	{"Получить узел TCP", selfhost.ExportTCP},
	{"Состояние TCP", selfhost.TCPStatus},
	{"Остановить TCP", selfhost.StopTCP},
}

func serverPrefsPath() string { return filepath.Join(data, "ssh-servers.json") }
func readServerPrefs() {
	sshPrefs = serverPrefs{User: "root", Port: 22}
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
}
func createServerPage() {
	readServerPrefs()
	caption("Сервер Linux", 20, 62, 395)
	caption("Порт SSH", 434, 62, 135)
	input(sshHost, sshPrefs.Host, 20, 86, 395, 0)
	input(sshPort, strconv.Itoa(sshPrefs.Port), 434, 86, 143, 0)
	caption("Пользователь SSH", 20, 130, 260)
	caption("Пароль на этот сеанс", 310, 130, 275)
	input(sshUser, sshPrefs.User, 20, 154, 270, 0)
	input(sshPass, "", 310, 154, 267, 0x20)
	caption("Файл закрытого SSH-ключа (если используется)", 20, 197, 565)
	input(sshKey, sshPrefs.KeyPath, 20, 221, 557, 0)
	caption("Действие", 20, 270, 400)
	h := field("COMBOBOX", "", sshActions, 20, 295, 397, 254, 0x00210003)
	for _, a := range sshActionsList {
		comboAdd(h, a.label)
	}
	comboSelect(h, 0)
	button(sshRun, "Выполнить", 430, 292, 147)
	caption("Результат", 20, 344, 400)
	field("EDIT", "Debian или Ubuntu с systemd. WireGuard использует UDP 51823, резервный TCP — порт 443.", sshOutput, 20, 368, 557, 84, 0x00810844)
	button(sshForget, "Забыть ключ сервера", 20, 475, 210)
	button(2, "Закрыть", 447, 475, 130)
	if prefsError != nil {
		setLabel(fields[sshOutput], "Не удалось прочитать настройки SSH. "+prefsError.Error())
		call(user, "EnableWindow", fields[sshRun], 0)
	}
}
func comboAdd(h uintptr, s string) {
	call(user, "SendMessageW", h, 0x0143, 0, uintptr(unsafe.Pointer(u(s))))
}
func comboSelect(h uintptr, n int) { call(user, "SendMessageW", h, 0x014e, uintptr(n), 0) }
func comboIndex(h uintptr) int     { return int(call(user, "SendMessageW", h, 0x0147, 0, 0)) }
func confirm(title, question string) bool {
	return call(user, "MessageBoxW", vpnWindow, uintptr(unsafe.Pointer(u(question))), uintptr(unsafe.Pointer(u(title))), 0x124) == 6
}
func serverCommand(n int) {
	if n != sshRun && n != sshForget {
		return
	}
	if prefsError != nil {
		errorMessage(prefsError.Error())
		return
	}
	host := strings.TrimSpace(editText(fields[sshHost]))
	port, e := strconv.Atoi(strings.TrimSpace(editText(fields[sshPort])))
	if host == "" || e != nil || port < 1 || port > 65535 {
		errorMessage("Укажите адрес сервера и порт SSH от 1 до 65535.")
		return
	}
	address := net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))
	if n == sshForget {
		if _, ok := sshPrefs.Pins[address]; ok && confirm("Ключ SSH", "Забыть сохранённый отпечаток SSH для "+address+"?") {
			old := sshPrefs.Pins[address]
			delete(sshPrefs.Pins, address)
			if e := core.SaveJSON(serverPrefsPath(), sshPrefs); e != nil {
				sshPrefs.Pins[address] = old
				errorMessage(e.Error())
			} else {
				setLabel(fields[sshOutput], "Отпечаток удалён. При следующем соединении потребуется проверка.")
			}
		}
		return
	}
	i := comboIndex(fields[sshActions])
	if i < 0 || i >= len(sshActionsList) {
		return
	}
	action := sshActionsList[i].action
	if (action == selfhost.InstallVPN || action == selfhost.ExportVPN || action == selfhost.InstallTCP || action == selfhost.ExportTCP) && libraryError != nil {
		errorMessage(libraryError.Error())
		return
	}
	if (action == selfhost.StopVPN || action == selfhost.StopSOCKS || action == selfhost.StopTCP) && !confirm("Свой сервер", "Выполнить «"+sshActionsList[i].label+"» на "+address+"?") {
		return
	}
	if sshPrefs.ClientID == "" {
		sshPrefs.ClientID, e = selfhost.NewClientID()
		if e != nil {
			errorMessage(e.Error())
			return
		}
	}
	server := selfhost.Server{Host: host, Port: port, User: strings.TrimSpace(editText(fields[sshUser])), Password: editText(fields[sshPass]), KeyPath: strings.TrimSpace(editText(fields[sshKey])), Fingerprint: sshPrefs.Pins[address], ClientID: sshPrefs.ClientID}
	setLabel(fields[sshOutput], "")
	run := func(pin string) {
		server.Fingerprint = pin
		sshPrefs.Host = host
		sshPrefs.Port = port
		sshPrefs.User = server.User
		sshPrefs.KeyPath = server.KeyPath
		sshPrefs.Pins[address] = pin
		if e := core.SaveJSON(serverPrefsPath(), sshPrefs); e != nil {
			errorMessage(e.Error())
			return
		}
		startWork("Выполняется команда SSH", 10*time.Minute, func(ctx context.Context) (func(), error) {
			result, e := selfhost.Run(ctx, server, action)
			if e != nil {
				return nil, e
			}
			var p tunnel.Profile
			label := ""
			if result.VPNConfig != "" {
				p, e = tunnel.WireGuard(result.VPNConfig)
				label = "WireGuard"
			} else if result.NodeURL != "" {
				var profiles []tunnel.Profile
				profiles, e = tunnel.Import(ctx, result.NodeURL)
				if e == nil {
					p = profiles[0]
				}
				label = "TCP · REALITY"
			}
			if e != nil {
				return nil, e
			}
			return func() {
				msg := result.Status
				if label != "" {
					p.Name = label + " · " + host
					source := tunnel.Source{Name: p.Name, ManagedID: p.Protocol + "/" + address, Profiles: []tunnel.Profile{p}}
					next := copyLibrary()
					replaceSource(&next, source, -1)
					if !commitLibrary(next) {
						return
					}
					msg += "\r\nУзел выбран. Закройте окно и включите VPN."
				}
				if result.SOCKSURL != "" {
					msg += "\r\n" + result.SOCKSURL
				}
				setLabel(fields[sshOutput], strings.TrimSpace(msg))
			}, nil
		})
	}
	if server.Fingerprint != "" {
		run(server.Fingerprint)
		return
	}
	startWork("Проверка ключа сервера", 20*time.Second, func(ctx context.Context) (func(), error) {
		fingerprint, e := selfhost.ProbeFingerprint(ctx, server)
		if e != nil {
			return nil, e
		}
		return func() {
			if confirm("Первое соединение по SSH", fmt.Sprintf("Сверьте отпечаток с консолью сервера %s.\n\n%s\n\nСохранить ключ и продолжить?", address, fingerprint)) {
				run(fingerprint)
			}
		}, nil
	})
}
