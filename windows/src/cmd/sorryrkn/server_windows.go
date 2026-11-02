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
	"sync"
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
	{"Установить HTTPS и добавить узел", selfhost.InstallHTTPS},
	{"Состояние HTTPS и SOCKS5", selfhost.Status},
	{"Запустить HTTPS на сервере", selfhost.StartHTTPS},
	{"Получить узел HTTPS", selfhost.ExportHTTPS},
	{"Остановить HTTPS на сервере", selfhost.StopHTTPS},
	{"Включить SOCKS5 через SSH", selfhost.InstallSOCKS},
	{"Остановить SOCKS5", selfhost.StopSOCKS},
	{"Установить резервный TCP · REALITY", selfhost.InstallTCP},
	{"Получить резервный узел", selfhost.ExportTCP},
	{"Состояние резервного узла", selfhost.TCPStatus},
	{"Остановить резервный узел", selfhost.StopTCP},
}

var forwardMu sync.Mutex
var activeForward *selfhost.SOCKSForward
var forwardHost string
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
}
func currentForwardLabel() string {
	forwardMu.Lock()
	defer forwardMu.Unlock()
	if activeForward == nil {
		return ""
	}
	return "SOCKS5 через " + forwardHost + "\r\n" + activeForward.URL
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
	field("EDIT", "Debian или Ubuntu с systemd. HTTPS использует TCP 443, запасной маршрут — TCP 8443.", sshOutput, 20, 368, 557, 84, 0x00810844)
	button(sshForget, "Забыть ключ сервера", 20, 475, 210)
	button(2, "Закрыть", 447, 475, 130)
	if details := currentForwardLabel(); details != "" {
		setLabel(fields[sshOutput], details)
	}
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
	if (action == selfhost.InstallHTTPS || action == selfhost.ExportHTTPS || action == selfhost.InstallTCP || action == selfhost.ExportTCP) && libraryError != nil {
		errorMessage(libraryError.Error())
		return
	}
	if (action == selfhost.StopHTTPS || action == selfhost.StopSOCKS || action == selfhost.StopTCP) && !confirm("Свой сервер", "Выполнить «"+sshActionsList[i].label+"» на "+address+"?") {
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
			if result.NodeURL != "" {
				var profiles []tunnel.Profile
				profiles, e = tunnel.Import(ctx, result.NodeURL)
				if e == nil {
					p = profiles[0]
				}
				label = "HTTPS"
				if action == selfhost.InstallTCP || action == selfhost.ExportTCP {
					label = "TCP · REALITY"
				}
			}
			if e != nil {
				return nil, e
			}
			var localURL string
			if result.SOCKSURL != "" {
				c, stop := context.WithCancel(forwardLifetime)
				detach := context.AfterFunc(ctx, stop)
				forward, err := selfhost.OpenSOCKS(c, server, result.SOCKSURL)
				detach()
				if err != nil {
					stop()
					return nil, err
				}
				replaceForward(address, forward)
				localURL = forward.URL
			}
			if action == selfhost.StopSOCKS {
				replaceForward(address, nil)
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
				if localURL != "" {
					msg += "\r\n" + localURL
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
