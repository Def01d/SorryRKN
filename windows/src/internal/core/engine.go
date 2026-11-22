package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Process interface {
	Stop()
	Alive() bool
}
type childSpec struct {
	proc    Process
	restart func() (Process, error)
}
type Runner interface {
	Start(program string, args []string, dir string, input []byte, log string) (Process, error)
}
type Extra interface {
	Start(context.Context, string, DomainRules) (func(), error)
	Alive() bool
	Resolver() *SmartDNS
}
type State struct {
	Status         string               `json:"state"`
	Detail         string               `json:"detail"`
	Profile        string               `json:"profile,omitempty"`
	Checks         []Check              `json:"checks,omitempty"`
	Error          string               `json:"error,omitempty"`
	Telegram       bool                 `json:"telegram"`
	DPI            bool                 `json:"dpi"`
	Instagram      bool                 `json:"instagram,omitempty"`
	Extras         bool                 `json:"extra_sites"`
	DNS            bool                 `json:"dns"`
	TelegramHealth TelegramHealth       `json:"telegram_health"`
	Services       []Target             `json:"services,omitempty"`
	Routes         []ServiceRouteStatus `json:"service_routes,omitempty"`
}
type Engine struct {
	mu            sync.Mutex
	state         State
	cancel        context.CancelFunc
	done          chan struct{}
	runner        Runner
	extra         Extra
	notify        func()
	root, data    string
	probe         func(context.Context, string) Check
	probeServices func(context.Context, *SmartDNS) []Target
}

func NewEngine(root, data string, r Runner, x Extra, notify func()) *Engine {
	return &Engine{root: root, data: data, runner: r, extra: x, notify: notify, state: State{Status: "off"}, probe: Probe, probeServices: ProbeExtrasWithDNS}
}
func (e *Engine) Snapshot() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state
	s.Checks = append([]Check(nil), s.Checks...)
	for i := range s.Checks {
		s.Checks[i].Targets = append([]Target(nil), s.Checks[i].Targets...)
	}
	s.Services = append([]Target(nil), s.Services...)
	s.Routes = append([]ServiceRouteStatus(nil), s.Routes...)
	if s.TelegramHealth.Datacenters != nil {
		s.TelegramHealth.Datacenters = make(map[string]TelegramDCHealth, len(e.state.TelegramHealth.Datacenters))
		for dc, health := range e.state.TelegramHealth.Datacenters {
			s.TelegramHealth.Datacenters[dc] = health
		}
	}
	return s
}
func (e *Engine) set(s State) {
	e.mu.Lock()
	unchanged := reflect.DeepEqual(e.state, s)
	e.state = s
	e.mu.Unlock()
	if !unchanged && e.notify != nil {
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
	var children []childSpec
	var stopExtra func()
	var healthPath string
	s := State{Status: "starting"}
	defer func() {
		if stopExtra != nil {
			stopExtra()
		}
		for _, ch := range children {
			if ch.proc != nil {
				ch.proc.Stop()
			}
		}
		if healthPath != "" {
			os.Remove(healthPath)
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
	rules, ruleError := c.Rules()
	rules.DNSDirectory = e.data
	if ruleError != nil {
		fail(ruleError)
		return
	}
	directList, ruleError := WriteBypassList(e.data, rules)
	if ruleError != nil {
		fail(ruleError)
		return
	}
	userDPIList, ruleError := WriteUserDPIList(e.data, rules)
	if ruleError != nil {
		fail(ruleError)
		return
	}
	instagramOn := c.InstagramEnabled()
	if !c.DPI && !c.Telegram && !c.Extras && !instagramOn && len(rules.Geo) == 0 && len(rules.DPI) == 0 {
		fail(errors.New("выберите сервис для подключения"))
		return
	}
	if c.Telegram {
		healthID, err := NewSecret()
		if err != nil {
			fail(err)
			return
		}
		healthPath = filepath.Join(e.data, "telegram-health-"+healthID+".json")
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
		input, _ := json.Marshal(map[string]any{"secret": secret, "domains": domains, "health_path": healthPath})
		input = append(input, '\n')
		startTelegram := func() (Process, error) {
			p, startErr := e.runner.Start(filepath.Join(e.root, "python", "python.exe"), []string{"-u", filepath.Join(e.root, "app", "tg_runner.py")}, e.root, input, filepath.Join(e.data, "telegram.log"))
			if startErr != nil {
				return nil, startErr
			}
			if waitErr := waitPort(ctx, p, "127.0.0.1:1443", 8*time.Second); waitErr != nil {
				p.Stop()
				return nil, fmt.Errorf("Telegram: %w", waitErr)
			}
			return p, nil
		}
		p, err := startTelegram()
		if err != nil {
			fail(err)
			return
		}
		children = append(children, childSpec{proc: p, restart: startTelegram})
		s.Telegram = true
		s.TelegramHealth = TelegramHealth{State: "checking"}
	}
	if rules.Secure || c.Extras || instagramOn || len(rules.Geo) > 0 || len(rules.DPI) > 0 {
		var err error
		stopExtra, err = e.extra.Start(ctx, filepath.Join(e.root, "zapret", "bin"), rules)
		if err != nil {
			fail(fmt.Errorf("DNS-профиль: %w", err))
			return
		}
		s.Extras = c.Extras || len(rules.Geo) > 0
		s.Instagram = instagramOn
		s.DNS = true
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
		bestSeconds := 1e9
		selected := false
		for i := 0; ; i++ {
			if i >= len(choices) && c.Method == "auto" && !extended {
				// Escalate even when the last fast candidate had missing assets
				// or exited before probing. Preserve the same candidate ordering.
				choices = Candidates(catalog, c, true)
				extended = true
			}
			if i >= len(choices) {
				break
			}
			p := choices[i]
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
			if instagramOn {
				args = WithInstagram(args, filepath.Join(e.root, "zapret", "lists", "instagram.txt"))
			}
			if userDPIList != "" {
				args = WithUserDPI(args, userDPIList)
			}
			args = WithDirect(args, directList)
			process, err := e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), args, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
			if err != nil {
				fail(err)
				return
			}
			timer := time.NewTimer(300 * time.Millisecond)
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
			if check.Score() > bestScore || (check.Score() == bestScore && best != nil && check.Seconds > 0 && check.Seconds < bestSeconds) {
				copy := p
				best = &copy
				bestScore = check.Score()
				if check.Seconds > 0 {
					bestSeconds = check.Seconds
				}
			}
			if check.Complete() || c.Method != "auto" {
				winwsArgs := append([]string(nil), args...)
				children = append(children, childSpec{proc: process, restart: func() (Process, error) {
					return e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), winwsArgs, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
				}})
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
				if instagramOn {
					args = WithInstagram(args, filepath.Join(e.root, "zapret", "lists", "instagram.txt"))
				}
				if userDPIList != "" {
					args = WithUserDPI(args, userDPIList)
				}
				args = WithDirect(args, directList)
				p, err := e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), args, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
				if err == nil {
					winwsArgs := append([]string(nil), args...)
					children = append(children, childSpec{proc: p, restart: func() (Process, error) {
						return e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), winwsArgs, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
					}})
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
			s.Detail = "Рабочий DPI не найден · см. диагностику"
			if !s.Telegram && !s.Extras && !s.Instagram && userDPIList == "" {
				fail(errors.New("рабочий метод не найден; откройте расширенный подбор"))
				return
			}
		}
	} else {
		if instagramOn || userDPIList != "" {
			args := []string{"--wf-tcp=80,443", "--wf-udp=443"}
			if instagramOn {
				args = WithInstagram(args, filepath.Join(e.root, "zapret", "lists", "instagram.txt"))
			}
			if userDPIList != "" {
				args = WithUserDPI(args, userDPIList)
			}
			args = WithDirect(args, directList)
			p, err := e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), args, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
			if err != nil {
				fail(err)
				return
			}
			winwsArgs := append([]string(nil), args...)
			children = append(children, childSpec{proc: p, restart: func() (Process, error) {
				return e.runner.Start(filepath.Join(e.root, "zapret", "bin", "winws.exe"), winwsArgs, filepath.Join(e.root, "zapret", "bin"), nil, filepath.Join(e.data, "dpi.log"))
			}})
		}
		s.Status = "on"
		s.Detail = "Работает в фоне"
	}
	if ctx.Err() != nil {
		return
	}
	baseStatus, baseDetail := s.Status, s.Detail
	if c.Extras || instagramOn {
		switch {
		case c.Extras && instagramOn:
			s.Detail = "Проверяем ChatGPT и Instagram"
		case c.Extras:
			s.Detail = "Проверяем ChatGPT"
		default:
			s.Detail = "Проверяем Instagram"
		}
		e.set(s)
		s.Services = filterActiveServices(e.probeServices(ctx, e.extra.Resolver()), c.Extras, instagramOn)
	}
	if s.Telegram {
		s.TelegramHealth = ReadTelegramHealth(healthPath, time.Now())
	}
	applyServiceHealth(&s, baseStatus, baseDetail)
	if s.DNS {
		if resolver := e.extra.Resolver(); resolver != nil {
			s.Routes = resolver.RouteStatus()
		}
	}
	e.set(s)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	// Probe in a worker so shutdown and process liveness never wait on HTTP.
	serviceResults := make(chan []Target, 1)
	serviceTimer := time.NewTicker(60 * time.Second)
	defer serviceTimer.Stop()
	serviceChecking := false
	restarts := 0
	lastRestart := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-serviceTimer.C:
			if (c.Extras || instagramOn || s.DNS && len(c.ServiceDNS) > 0) && !serviceChecking {
				serviceChecking = true
				go func() {
					if resolver := e.extra.Resolver(); resolver != nil && resolver.serviceRouter != nil {
						resolver.serviceRouter.Recover(ctx)
					}
					var result []Target
					if c.Extras || instagramOn {
						result = filterActiveServices(e.probeServices(ctx, e.extra.Resolver()), c.Extras, instagramOn)
					}
					select {
					case serviceResults <- result:
					case <-ctx.Done():
					}
				}()
			}
		case result := <-serviceResults:
			serviceChecking = false
			s.Services = result
			applyServiceHealth(&s, baseStatus, baseDetail)
			e.set(s)
		case <-ticker.C:
			if time.Since(lastRestart) > 2*time.Minute {
				restarts = 0
			}
			if s.DNS {
				if resolver := e.extra.Resolver(); resolver != nil {
					s.Routes = resolver.RouteStatus()
				}
			}
			if s.DNS && !e.extra.Alive() {
				if restarts < 3 {
					restarts++
					lastRestart = time.Now()
					if stopExtra != nil {
						stopExtra()
					}
					if nextStop, restartErr := e.extra.Start(ctx, filepath.Join(e.root, "zapret", "bin"), rules); restartErr == nil {
						stopExtra = nextStop
					} else {
						fail(errors.New("DNS-профиль остановился; подключитесь снова"))
						return
					}
				} else {
					fail(errors.New("DNS-профиль остановился; подключитесь снова"))
					return
				}
			}
			for i := range children {
				if !children[i].proc.Alive() {
					children[i].proc.Stop()
					if children[i].restart != nil && restarts < 3 {
						restarts++
						lastRestart = time.Now()
						if nextProc, restartErr := children[i].restart(); restartErr == nil {
							children[i].proc = nextProc
							continue
						}
					}
					fail(errors.New("сетевой процесс остановился; подключитесь снова"))
					return
				}
			}
			if s.Telegram {
				s.TelegramHealth = ReadTelegramHealth(healthPath, time.Now())
				applyServiceHealth(&s, baseStatus, baseDetail)
				e.set(s)
			}
			if s.DNS && !s.Telegram {
				e.set(s)
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
	var global, profiles []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--wf-") {
			global = append(global, arg)
		} else {
			profiles = append(profiles, arg)
		}
	}
	result := append(global, "--filter-udp=443", "--hostlist="+list, "--dpi-desync=fake", "--dpi-desync-repeats=6", "--new",
		"--filter-tcp=80,443", "--hostlist="+list, "--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=badseq")
	if len(profiles) > 0 {
		result = append(result, "--new")
		result = append(result, profiles...)
	}
	return result
}

func filterActiveServices(targets []Target, wantChatGPT, wantInstagram bool) []Target {
	if wantChatGPT && wantInstagram {
		return targets
	}
	var out []Target
	for _, t := range targets {
		if t.Name == "ChatGPT" && !wantChatGPT {
			continue
		}
		if t.Name == "Instagram" && !wantInstagram {
			continue
		}
		out = append(out, t)
	}
	return out
}
