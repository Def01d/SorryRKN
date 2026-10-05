//go:build windows

package platform

import (
	"bytes"
	"encoding/base64"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"sorryrkn/internal/core"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

type Runner struct{}
type child struct {
	job   windows.Handle
	cmd   *exec.Cmd
	alive atomic.Bool
	once  sync.Once
	done  chan struct{}
}

func (c *child) Alive() bool { return c.alive.Load() }
func (c *child) Stop() {
	c.once.Do(func() {
		windows.TerminateJobObject(c.job, 1)
		windows.CloseHandle(c.job)
		c.alive.Store(false)
		<-c.done
	})
}
func (Runner) Start(program string, args []string, dir string, input []byte, log string) (core.Process, error) {
	if strings.EqualFold(filepath.Base(program), "winws.exe") {
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err == nil {
			defer windows.CloseHandle(snapshot)
			entry := windows.ProcessEntry32{}
			entry.Size = uint32(unsafe.Sizeof(entry))
			for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
				if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "winws.exe") && entry.ParentProcessID != uint32(os.Getpid()) {
					return nil, errors.New("закройте другой zapret перед включением SorryRKN")
				}
			}
		}
	}
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, e
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	f, e := core.OpenLog(log)
	if e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	cmd := exec.Command(program, args...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Stdout = f
	cmd.Stderr = f
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	if e = cmd.Start(); e != nil {
		f.Close()
		windows.CloseHandle(job)
		return nil, e
	}
	process, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if e == nil {
		e = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		windows.CloseHandle(job)
		return nil, e
	}
	c := &child{job: job, cmd: cmd, done: make(chan struct{})}
	c.alive.Store(true)
	go func() { defer close(c.done); cmd.Wait(); f.Close(); c.alive.Store(false) }()
	return c, nil
}
func ProtectSecret(secret string) (string, error) {
	data := []byte(secret)
	blob := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if e := windows.CryptProtectData(&blob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return "", e
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return base64.StdEncoding.EncodeToString(unsafe.Slice(out.Data, out.Size)), nil
}
func UnprotectSecret(value string) (string, error) {
	data, e := base64.StdEncoding.DecodeString(value)
	if e != nil || len(data) == 0 {
		return "", errors.New("invalid stored secret")
	}
	blob := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if e = windows.CryptUnprotectData(&blob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return "", e
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	secret := string(unsafe.Slice(out.Data, out.Size))
	if !core.ValidSecret(secret) {
		return "", errors.New("invalid proxy secret")
	}
	return secret, nil
}
