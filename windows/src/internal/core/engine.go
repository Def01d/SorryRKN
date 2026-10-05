package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Process interface {
	Stop()
	Alive() bool
}
type Runner interface {
	Start(program string, args []string, dir string, input []byte, log string) (Process, error)
}
type Extra interface {
	Start(context.Context, string) (func(), error)
	Alive() bool
}
type State struct {
	Status   string  `json:"state"`
	Detail   string  `json:"detail"`
	Profile  string  `json:"profile,omitempty"`
	Checks   []Check `json:"checks,omitempty"`
	Error    string  `json:"error,omitempty"`
	Telegram bool    `json:"telegram"`
	DPI      bool    `json:"dpi"`
	Extras   bool    `json:"extra_sites"`
}
type Engine struct {
	mu         sync.Mutex
	state      State
	cancel     context.CancelFunc
	done       chan struct{}
	runner     Runner
	extra      Extra
	notify     func()
	root, data string
	probe      func(context.Context, string) Check
}

func NewEngine(root, data string, r Runner, x Extra, notify func()) *Engine {
	return &Engine{root: root, data: data, runner: r, extra: x, notify: notify, state: State{Status: "off"}, probe: Probe}
}
func (e *Engine) Snapshot() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state
	s.Checks = append([]Check(nil), s.Checks...)
	return s
}
func (e *Engine) set(s State) {
	e.mu.Lock()
	e.state = s
	e.mu.Unlock()
	if e.notify != nil {
		e.notify()
	}
}
func (e *Engine) Busy() bool {
	s := e.Snapshot().Status
	return s == "starting" || s == "stopping" || s == "on" || s == "partial"
}
func (e *Engine) Start(config Config, secret string, extended bool, saved func(string)) error {
	e.mu.Lock()
	if e.cancel != nil {
		e.mu.Unlock()
		return errors.New("already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	done := e.done
	e.mu.Unlock()
	e.set(State{Status: "starting", Detail: "Запускаем локальное соединение"})
	go func() {
		defer close(done)
		e.run(ctx, config, secret, extended, saved)
		e.mu.Lock()
		e.cancel = nil
		e.mu.Unlock()
	}()
	return nil
}
func (e *Engine) Stop() {
	e.mu.Lock()
	cancel := e.cancel
	done := e.done
	e.mu.Unlock()
	if cancel == nil {
		return
	}
	s := e.Snapshot()
	s.Status = "stopping"
	s.Detail = "Закрываем соединения"
	e.set(s)
	cancel()
	if done != nil {
		<-done
	}
}
func (e *Engine) run(ctx context.Context, c Config, secret string, extended bool, saved func(string)) {
	var children []Process
	var stopExtra func()
	s := State{Status: "starting"}
	defer func() {
		if stopExtra != nil {
			stopExtra()
		}
		for _, p := range children {
			p.Stop()
		}
		if ctx.Err() != nil {
			e.set(State{Status: "off"})
		}
	}()
	fail := func(err error) {
		s.Status = "error"
		s.Error = err.Error()
		s.Detail = "Не удалось включить"
		e.set(s)
	}
	if !c.DPI && !c.Telegram && !c.Extras {
		fail(errors.New("выберите сервис для подключения"))
		return
	}
	if c.Telegram {
		domains := []string{}
		b, _ := os.ReadFile(filepath.Join(e.data, "tg-domains.json"))
		json.Unmarshal(b, &domains)
		if len(domains) == 0 {
			b, _ = os.ReadFile(filepath.Join(e.root, "app", "bundled-data.json"))
			var bundled map[string]json.RawMessage
			if json.Unmarshal(b, &bundled) == nil {
				json.Unmarshal(bundled["cf"], &domains)
			}
		}
		input, _ := json.Marshal(map[string]any{"secret": secret, "domains": domains})
		input = append(input, '\n')
		p, err := e.runner.Start(filepath.Join(e.root, "python", "python.exe"), []string{"-u", filepath.Join(e.root, "app", "tg_runner.py")}, e.root, input, filepath.Join(e.data, "telegram.log"))
		if err != nil {
			fail(err)
			return
		}
		children = append(children, p)
		if err = waitPort(ctx, p, "127.0.0.1:1443", 8*time.Second); err != nil {
			fail(fmt.Errorf("Telegram: %w", err))
			return
		}
		s.Telegram = true
	}
	if c.Extras {
		var err error
		stopExtra, err = e.extra.Start(ctx, filepath.Join(e.root, "zapret", "bin"))
		if err != nil {
			fail(fmt.Errorf("DNS-профиль: %w", err))
			return
		}
		s.Extras = true
	}
	if c.DPI {
		dir := ActiveData(e.data, filepath.Join(e.root, "zapret"))
		catalog, err := LoadCatalog(dir)
		if err != nil {
			fail(err)
			return
		}
		choices := Candidates(catalog, c, extended)
		if len(choices) == 0 {
			fail(errors.New("сохранённый метод недоступен; выберите авто"))
			return
		}
		var best *Profile
		bestScore := -1
		selected := false
		for i, p := range choices {
			if ctx.Err() != nil {
				return
			}
			s.Detail = fmt.Sprintf("Проверка %d/%d · %s", i+1, len(choices), p.Name)
			s.Profile = p.Name
			e.set(s)
			args, err := ResolveArgs(p, dir, filepath.Join(e.root, "zapret", "bin"))
			if err != nil {
				continue
			}
			if c.Extras {
				args = WithInstagram(args, filepath.Join(e.root, "zapret", "lists", "instagram.txt"))
			}
			process, err := e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), args, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
			if err != nil {
				fail(err)
				return
			}
			timer := time.NewTimer(350 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				process.Stop()
				return
			}
			if !process.Alive() {
				process.Stop()
				continue
			}
			check := e.probe(ctx, p.Name)
			s.Checks = append(s.Checks, check)
			if check.Score() > bestScore {
				copy := p
				best = &copy
				bestScore = check.Score()
			}
			if check.Complete() || c.Method != "auto" {
				children = append(children, process)
				s.DPI = true
				s.Profile = p.Name
				selected = true
				if check.Complete() {
					s.Status = "on"
					s.Detail = "Работает в фоне"
					saved(p.ID)
				} else {
					s.Status = "partial"
					s.Detail = "Метод запущен · проверки пройдены не полностью"
				}
				break
			}
			process.Stop()
		}
		if !selected && best != nil && bestScore > 0 {
			args, err := ResolveArgs(*best, dir, filepath.Join(e.root, "zapret", "bin"))
			if err == nil {
				if c.Extras {
					args = WithInstagram(args, filepath.Join(e.root, "zapret", "lists", "instagram.txt"))
				}
				p, err := e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), args, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
				if err == nil {
					children = append(children, p)
					s.DPI = true
					s.Profile = best.Name
					s.Status = "partial"
					s.Detail = "Часть проверок не пройдена"
					selected = true
				}
			}
		}
		if !selected {
			s.Status = "partial"
			s.Profile = ""
			s.Detail = "Рабочий DPI не найден · работает Telegram / DNS"
			if !s.Telegram && !s.Extras {
				fail(errors.New("рабочий метод не найден; откройте расширенный подбор"))
				return
			}
		}
	} else {
		if c.Extras {
			args := WithInstagram([]string{"--wf-tcp=80,443", "--wf-udp=443"}, filepath.Join(e.root, "zapret", "lists", "instagram.txt"))
			p, err := e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), args, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
			if err != nil {
				fail(err)
				return
			}
			children = append(children, p)
		}
		s.Status = "on"
		s.Detail = "Работает в фоне"
	}
	if ctx.Err() != nil {
		return
	}
	e.set(s)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Extras && !e.extra.Alive() {
				fail(errors.New("DNS-профиль остановился; подключитесь снова"))
				return
			}
			for _, p := range children {
				if !p.Alive() {
					fail(errors.New("сетевой процесс остановился; подключитесь снова"))
					return
				}
			}
		}
	}
}
func waitPort(ctx context.Context, p Process, address string, timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if !p.Alive() {
			return errors.New("процесс остановился")
		}
		d := net.Dialer{Timeout: 150 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("порт не открылся")
}
func WithInstagram(args []string, list string) []string {
	result := []string{args[0], args[1], "--filter-tcp=80,443", "--hostlist=" + list, "--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=badseq", "--new"}
	return append(result, args[2:]...)
}
