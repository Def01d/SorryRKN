// Send Ctrl+Break from a separate short-lived process so the GUI never detaches
// its own console. The target engine has a private hidden console.
package main

import (
	"golang.org/x/sys/windows"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	pid, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil || pid == 0 {
		os.Exit(1)
	}
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	kernel.NewProc("FreeConsole").Call()
	ok, _, _ := kernel.NewProc("AttachConsole").Call(uintptr(pid))
	if ok == 0 {
		os.Exit(1)
	}
	if err = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0); err != nil {
		os.Exit(1)
	}
}
