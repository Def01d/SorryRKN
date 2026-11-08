//go:build windows

package main

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"sorryrkn/internal/tunnel"
	"strings"
	"sync"
	"time"
)

const (
	subInput = 1320 + iota
	subImport
	subList
	nodeList
	subRefresh
	subDelete
	subUse
	subProbe
)

func createSourcePage() {
	caption("Ссылка подписки HTTPS или ссылка на узел", 20, 62, 560)
	input(subInput, "", 20, 88, 400, 0x20)
	button(subImport, "Добавить", 433, 85, 144)
	caption("Источник", 20, 145, 560)
	field("COMBOBOX", "", subList, 20, 170, 557, 250, 0x00210003)
	caption("Узел", 20, 225, 560)
	field("COMBOBOX", "", nodeList, 20, 250, 557, 250, 0x00210003)
	button(subRefresh, "Обновить", 20, 310, 126)
	button(subDelete, "Удалить", 156, 310, 126)
	button(subProbe, "Проверить", 292, 310, 123)
	button(subUse, "Выбрать узел", 425, 310, 152)
	caption("Подключение включается кнопкой на главном экране.", 20, 380, 558)
	rebuildSources()
}
func rebuildSources() {
	h := fields[subList]
	call(user, "SendMessageW", h, 0x014b, 0, 0)
	for _, src := range vpnLibrary.Sources {
		comboAdd(h, src.Name)
	}
	comboSelect(h, vpnLibrary.SelectedSource)
	rebuildNodes()
}
func rebuildNodes() {
	h := fields[nodeList]
	call(user, "SendMessageW", h, 0x014b, 0, 0)
	idx := comboIndex(fields[subList])
	valid := idx >= 0 && idx < len(vpnLibrary.Sources)
	canRefresh := false
	if valid {
		src := vpnLibrary.Sources[idx]
		canRefresh = src.URL != ""
		for _, p := range src.Profiles {
			comboAdd(h, p.Name)
		}
		sel := 0
		if idx == vpnLibrary.SelectedSource {
			sel = vpnLibrary.SelectedNode
		}
		comboSelect(h, sel)
	}
	call(user, "EnableWindow", fields[subRefresh], boolInt(canRefresh))
	call(user, "EnableWindow", fields[subDelete], boolInt(valid))
	call(user, "EnableWindow", fields[subUse], boolInt(valid))
	call(user, "EnableWindow", fields[subProbe], boolInt(valid))
}
func replaceSource(lib *tunnel.Library, src tunnel.Source, index int) {
	if index < 0 {
		for i, other := range lib.Sources {
			sameLink := src.ManagedID == "" && src.URL == "" && other.ManagedID == "" && other.URL == "" && len(src.Profiles) == 1 && len(other.Profiles) == 1 && src.Profiles[0].Link == other.Profiles[0].Link
			if sameLink || (src.URL != "" && other.URL == src.URL) || (src.ManagedID != "" && other.ManagedID == src.ManagedID) {
				index = i
				break
			}
		}
	}
	node := 0
	if index < 0 {
		lib.Sources = append(lib.Sources, src)
		index = len(lib.Sources) - 1
	} else {
		old := lib.Sources[index]
		if index == lib.SelectedSource && lib.SelectedNode >= 0 && lib.SelectedNode < len(old.Profiles) {
			name := old.Profiles[lib.SelectedNode].Name
			for i, p := range src.Profiles {
				if p.Name == name {
					node = i
					break
				}
			}
		}
		lib.Sources[index] = src
	}
	lib.SelectedSource = index
	lib.SelectedNode = node
}
func sourceCommand(id, notification int) {
	idx := comboIndex(fields[subList])
	valid := idx >= 0 && idx < len(vpnLibrary.Sources)
	switch id {
	case subProbe:
		if valid {
			probeSources(idx, comboIndex(fields[nodeList]))
		}
	case subList:
		if notification == 1 {
			rebuildNodes()
		}
	case subUse:
		n := comboIndex(fields[nodeList])
		if !valid || n < 0 || n >= len(vpnLibrary.Sources[idx].Profiles) {
			return
		}
		next := copyLibrary()
		next.SelectedSource = idx
		next.SelectedNode = n
		if commitLibrary(next) {
			call(user, "DestroyWindow", vpnWindow)
			vpnStatus = ""
		}
	case subDelete:
		if !valid || !confirm("Удалить источник", "Удалить «"+vpnLibrary.Sources[idx].Name+"» с этого устройства?") {
			return
		}
		next := copyLibrary()
		next.Sources = append(next.Sources[:idx], next.Sources[idx+1:]...)
		if next.SelectedSource == idx {
			next.SelectedSource = 0
			next.SelectedNode = 0
		} else if next.SelectedSource > idx {
			next.SelectedSource--
		}
		if commitLibrary(next) {
			rebuildSources()
		}
	case subImport, subRefresh:
		value := strings.TrimSpace(editText(fields[subInput]))
		replace := -1
		if id == subRefresh {
			if !valid {
				return
			}
			value = vpnLibrary.Sources[idx].URL
			replace = idx
		}
		if value == "" {
			errorMessage("Введите ссылку на подписку или узел.")
			return
		}
		startWork("Загрузка узлов…", 45*time.Second, func(ctx context.Context) (func(), error) {
			report, e := tunnel.ImportWithReport(ctx, value)
			if e != nil {
				return nil, e
			}
			nodes := report.Profiles
			source := tunnel.Source{Profiles: nodes, Name: nodes[0].Name}
			if u, e := url.Parse(value); e == nil && strings.EqualFold(u.Scheme, "https") {
				source.URL = value
				source.Name = fmt.Sprintf("%s · %d узл.", u.Hostname(), len(nodes))
			}
			return func() {
				next := copyLibrary()
				replaceSource(&next, source, replace)
				if replace >= 0 && replace != vpnLibrary.SelectedSource {
					// Refreshing another provider should not change the active selection.
					next.SelectedSource, next.SelectedNode = vpnLibrary.SelectedSource, vpnLibrary.SelectedNode
				}
				if commitLibrary(next) {
					setLabel(fields[subInput], "")
					vpnStatus = ""
					rebuildSources()
					if report.Skipped > 0 {
						message("Импорт подписки", fmt.Sprintf("Добавлено узлов: %d. Пропущено неподдерживаемых записей: %d.", len(nodes), report.Skipped))
					}
				}
			}, nil
		})
	}
}

func probeSources(sourceIndex, nodeIndex int) {
	checkSystem := vpnSession.Active()
	source := vpnLibrary.Sources[sourceIndex]
	if nodeIndex < 0 || nodeIndex >= len(source.Profiles) {
		return
	}
	profiles := []tunnel.Profile{source.Profiles[nodeIndex]}
	if _, host, owned := strings.Cut(source.ManagedID, "/"); owned {
		for i, s := range vpnLibrary.Sources {
			_, other, managed := strings.Cut(s.ManagedID, "/")
			if i != sourceIndex && managed && other == host && len(s.Profiles) > 0 {
				profiles = append(profiles, s.Profiles[0])
			}
		}
	}
	startWork("Проверка соединения", 35*time.Second, func(ctx context.Context) (func(), error) {
		lines := make([]string, len(profiles))
		var waits sync.WaitGroup
		if checkSystem {
			lines = append(lines, "")
			waits.Add(1)
			go func() {
				defer waits.Done()
				lines[len(profiles)] = "Текущий системный VPN\n" + strings.Join(tunnel.DiagnoseSystem(ctx), "\n")
			}()
		}
		for i, profile := range profiles {
			waits.Add(1)
			go func(i int, p tunnel.Profile) {
				defer waits.Done()
				checks, e := tunnel.Diagnose(ctx, filepath.Dir(root), p)
				if e != nil {
					lines[i] = p.Name + " — " + e.Error()
				} else {
					lines[i] = p.Name + "\n" + strings.Join(checks, "\n")
				}
			}(i, profile)
		}
		waits.Wait()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return func() {
			message("Проверка маршрута", strings.Join(lines, "\n\n")+"\n\nПубличные проверки HTTPS, Discord WebSocket и UDP/STUN. Вход в аккаунт и голосовой звонок не проверяются. Выбор узла меняется кнопкой «Выбрать узел».")
		}, nil
	})
}
