//go:build windows

package platform

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type RunningApp struct {
	Exe       string
	Title     string
	HasWindow bool
	System    bool
}

var (
	user32DLL         = windows.NewLazySystemDLL("user32.dll")
	iphlpapiDLL       = windows.NewLazySystemDLL("iphlpapi.dll")
	procEnumWindows   = user32DLL.NewProc("EnumWindows")
	procIsWinVisible  = user32DLL.NewProc("IsWindowVisible")
	procGetWinPID     = user32DLL.NewProc("GetWindowThreadProcessId")
	procGetWinTextW   = user32DLL.NewProc("GetWindowTextW")
	procGetExtUDP     = iphlpapiDLL.NewProc("GetExtendedUdpTable")
	enumCallbackOnce  sync.Once
	enumCallbackAddr  uintptr
	enumWindowMu      sync.Mutex
	enumWindowSelfPID uint32
	enumWindowTitles  map[uint32]string
)

var internalSorryRKNExes = map[string]bool{
	"sorryrkn.exe":      true,
	"sorryrkn-tray.exe": true,
	"winws.exe":         true,
	"sing-box.exe":      true,
	"signal.exe":        true,
	"check-network.exe": true,
}

var backgroundSystemExes = map[string]bool{
	"applicationframehost.exe":    true,
	"audiodg.exe":                 true,
	"backgroundtaskhost.exe":      true,
	"conhost.exe":                 true,
	"csrss.exe":                   true,
	"ctfmon.exe":                  true,
	"dashost.exe":                 true,
	"dllhost.exe":                 true,
	"dwm.exe":                     true,
	"fontdrvhost.exe":             true,
	"lockapp.exe":                 true,
	"lsaiso.exe":                  true,
	"lsass.exe":                   true,
	"msmpeng.exe":                 true,
	"nissrv.exe":                  true,
	"runtimebroker.exe":           true,
	"searchapp.exe":               true,
	"searchhost.exe":              true,
	"searchindexer.exe":           true,
	"securityhealthsystray.exe":   true,
	"services.exe":                true,
	"shellexperiencehost.exe":     true,
	"sihost.exe":                  true,
	"smartscreen.exe":             true,
	"smss.exe":                    true,
	"spoolsv.exe":                 true,
	"sppsvc.exe":                  true,
	"startmenuexperiencehost.exe": true,
	"svchost.exe":                 true,
	"systemsettings.exe":          true,
	"taskhostw.exe":               true,
	"textinputhost.exe":           true,
	"tiworker.exe":                true,
	"trustedinstaller.exe":        true,
	"wininit.exe":                 true,
	"winlogon.exe":                true,
	"wmiprvse.exe":                true,
	"wudfhost.exe":                true,
}

func visibleWindowTitles() map[uint32]string {
	enumCallbackOnce.Do(func() {
		enumCallbackAddr = windows.NewCallback(func(hwnd, _ uintptr) uintptr {
			if vis, _, _ := procIsWinVisible.Call(hwnd); vis == 0 {
				return 1
			}
			var pid uint32
			procGetWinPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			if pid == 0 || pid == enumWindowSelfPID {
				return 1
			}
			var buf [256]uint16
			n, _, _ := procGetWinTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if n == 0 {
				return 1
			}
			title := strings.TrimSpace(windows.UTF16ToString(buf[:n]))
			if title != "" && enumWindowTitles[pid] == "" {
				enumWindowTitles[pid] = title
			}
			return 1
		})
	})
	enumWindowMu.Lock()
	defer enumWindowMu.Unlock()
	enumWindowSelfPID = uint32(os.Getpid())
	enumWindowTitles = map[uint32]string{}
	procEnumWindows.Call(enumCallbackAddr, 0)
	return enumWindowTitles
}

func RunningApps() ([]RunningApp, error) {
	titles := visibleWindowTitles()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}

	byExe := map[string]RunningApp{}
	for {
		rawExe := strings.TrimSpace(windows.UTF16ToString(entry.ExeFile[:]))
		key := strings.ToLower(rawExe)
		if strings.HasSuffix(key, ".exe") && !internalSorryRKNExes[key] {
			winTitle := titles[entry.ProcessID]
			cur, exists := byExe[key]
			if !exists {
				cur = RunningApp{
					Exe:       rawExe,
					Title:     winTitle,
					HasWindow: winTitle != "",
					System:    backgroundSystemExes[key] && winTitle == "",
				}
			} else if winTitle != "" && !cur.HasWindow {
				cur.Title = winTitle
				cur.HasWindow = true
				cur.System = false
			}
			byExe[key] = cur
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}

	out := make([]RunningApp, 0, len(byExe))
	for _, app := range byExe {
		out = append(out, app)
	}
	sort.Slice(out, func(i, j int) bool {
		rank := func(a RunningApp) int {
			if a.HasWindow {
				return 0
			}
			if !a.System {
				return 1
			}
			return 2
		}
		ri, rj := rank(out[i]), rank(out[j])
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(out[i].Exe) < strings.ToLower(out[j].Exe)
	})
	return out, nil
}

type cachedPIDExe struct {
	exe string
	exp time.Time
}

type udpOwnerResolver struct {
	mu    sync.Mutex
	cache map[uint32]cachedPIDExe
}

func newUDPOwnerResolver() *udpOwnerResolver {
	return &udpOwnerResolver{cache: map[uint32]cachedPIDExe{}}
}

func (r *udpOwnerResolver) Owner(port uint16, ipv6 bool) string {
	if port == 0 {
		return ""
	}
	af := uintptr(2) // AF_INET
	if ipv6 {
		af = 23 // AF_INET6
	}
	pid := udpPIDForPort(af, port)
	if pid == 0 || pid == 4 {
		return ""
	}
	now := time.Now()
	r.mu.Lock()
	if entry, ok := r.cache[pid]; ok && now.Before(entry.exp) {
		r.mu.Unlock()
		return entry.exe
	}
	r.mu.Unlock()

	exe := processExeByPID(pid)
	if exe == "" {
		return ""
	}
	r.mu.Lock()
	if len(r.cache) > 1024 {
		for k, v := range r.cache {
			if !now.Before(v.exp) {
				delete(r.cache, k)
			}
		}
	}
	r.cache[pid] = cachedPIDExe{exe: exe, exp: now.Add(10 * time.Second)}
	r.mu.Unlock()
	return exe
}

func udpPIDForPort(af uintptr, port uint16) uint32 {
	var size uint32
	for attempt := 0; attempt < 3; attempt++ {
		if size == 0 {
			procGetExtUDP.Call(0, uintptr(unsafe.Pointer(&size)), 0, af, 1, 0) // UDP_TABLE_OWNER_PID = 1
			if size == 0 {
				return 0
			}
			size += 1024
		}
		buf := make([]byte, size)
		ret, _, _ := procGetExtUDP.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, af, 1, 0)
		if ret == 122 { // ERROR_INSUFFICIENT_BUFFER
			size += 1024
			continue
		}
		if ret != 0 || len(buf) < 4 {
			return 0
		}
		count := int(binary.LittleEndian.Uint32(buf[0:4]))
		stride := 12 // MIB_UDPROW_OWNER_PID: addr(4)+port(4)+pid(4)
		portOff := 4
		pidOff := 8
		if af == 23 {
			stride = 28 // MIB_UDP6ROW_OWNER_PID: addr(16)+scope(4)+port(4)+pid(4)
			portOff = 20
			pidOff = 24
		}
		maxRows := (len(buf) - 4) / stride
		if count > maxRows {
			count = maxRows
		}
		var fallback uint32
		for i := 0; i < count; i++ {
			off := 4 + i*stride
			rowPort := binary.BigEndian.Uint16(buf[off+portOff : off+portOff+2])
			if rowPort != port {
				continue
			}
			pid := binary.LittleEndian.Uint32(buf[off+pidOff : off+pidOff+4])
			if pid > 4 {
				return pid
			}
			if pid != 0 && fallback == 0 {
				fallback = pid
			}
		}
		return fallback
	}
	return 0
}

func processExeByPID(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var buf [512]uint16
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil || n == 0 {
		return ""
	}
	full := windows.UTF16ToString(buf[:n])
	return strings.ToLower(strings.TrimSpace(filepath.Base(full)))
}
