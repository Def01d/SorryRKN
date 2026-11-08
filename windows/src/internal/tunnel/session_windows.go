package tunnel

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Session owns exactly one child engine. Credentials reach it only through stdin.
type Session struct {
	mu     sync.Mutex
	child  *engine
	active atomic.Pointer[engine]
}
type engine struct {
	done    chan struct{}
	exitErr error // read only after done is closed
	job     windows.Handle
	pid     int
	dir     string
}

func (s *Session) Active() bool {
	child := s.active.Load()
	if child == nil {
		return false
	}
	select {
	case <-child.done:
		return false
	default:
		return true
	}
}
func (s *Session) Start(appDir string, p Profile) error {
	data, err := engineConfig(context.Background(), p)
	if err != nil {
		return err
	}
	defer clear(data)
	return s.start(appDir, data)
}

type readyLog struct {
	mu    sync.Mutex
	tail  string
	ready chan struct{}
	once  sync.Once
}

func (l *readyLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line := l.tail + string(b)
	if strings.Contains(line, "sing-box started") {
		l.once.Do(func() { close(l.ready) })
	}
	if len(line) > 64 {
		line = line[len(line)-64:]
	}
	l.tail = line
	return len(b), nil
}
func (s *Session) start(appDir string, data []byte) error {
	return s.startContext(context.Background(), appDir, data)
}
func (s *Session) startContext(ctx context.Context, appDir string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.child != nil {
		select {
		case <-s.child.done:
			windows.CloseHandle(s.child.job)
			s.child = nil
		default:
			return errors.New("VPN уже подключён")
		}
	}
	dir := filepath.Join(appDir, "runtime", "tunnel")
	if !filepath.IsAbs(dir) {
		return errors.New("нужен абсолютный путь к программе")
	}
	if _, err := os.Stat(filepath.Join(dir, "signal.exe")); err != nil {
		return errors.New("установите полный пакет SorryRKN с VPN-движком")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer func() { windows.CloseHandle(job) }()
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	program := filepath.Join(dir, "sing-box.exe")
	cmd := exec.Command(program, "run", "-c", "stdin", "--disable-color")
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_CONSOLE}
	log := &readyLog{ready: make(chan struct{})}
	cmd.Stderr = log
	cmd.Stdout = log
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	if err = cmd.Start(); err != nil {
		return errors.New("не удалось запустить VPN-движок")
	}
	// The child cannot construct an interface until its entire config arrives.
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, proc)
		windows.CloseHandle(proc)
	}
	if err != nil {
		cmd.Process.Kill()
		input.Close()
		cmd.Wait()
		return err
	}
	var retained windows.Handle
	err = windows.DuplicateHandle(windows.CurrentProcess(), job, windows.CurrentProcess(), &retained, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		cmd.Process.Kill()
		input.Close()
		cmd.Wait()
		return err
	}
	c := &engine{done: make(chan struct{}), job: retained, pid: cmd.Process.Pid, dir: dir}
	go func() { c.exitErr = cmd.Wait(); close(c.done) }()
	if _, err = input.Write(data); err != nil {
		input.Close()
		c.terminate()
		return errors.New("движок не принял профиль")
	}
	input.Close()
	select {
	case <-log.ready:
		s.child = c
		s.active.Store(c)
		return nil
	case <-c.done:
		windows.CloseHandle(retained)
		return errors.New("VPN не запустился. Проверьте права администратора, настройки узла и наличие другого VPN")
	case <-time.After(12 * time.Second):
		c.terminate()
		return errors.New("VPN не создал интерфейс за 12 секунд")
	case <-ctx.Done():
		c.terminate()
		return ctx.Err()
	}
}
func (c *engine) terminate() {
	windows.TerminateJobObject(c.job, 1)
	<-c.done
	windows.CloseHandle(c.job)
}
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.child == nil {
		return
	}
	c := s.child
	s.child = nil
	s.active.Store(nil)
	select {
	case <-c.done:
		windows.CloseHandle(c.job)
		return
	default:
	}
	// Signal the hidden console so the engine can remove its own DNS and routes.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	signal := exec.CommandContext(ctx, filepath.Join(c.dir, "signal.exe"), strconv.Itoa(c.pid))
	signal.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	// Ctrl+Break can also interrupt the short-lived sender. Its exit status
	// does not tell us whether the engine received the signal. Always allow
	// the engine to finish its DNS/interface/route cleanup before killing it.
	_ = signal.Run()
	select {
	case <-c.done:
		windows.CloseHandle(c.job)
		return
	case <-time.After(5 * time.Second):
	}
	c.terminate()
}
