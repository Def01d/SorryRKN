//go:build windows

package platform

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"sorryrkn/internal/core"
	"sync"
	"sync/atomic"
	"unsafe"
)

type DNS struct {
	handle   windows.Handle
	mu       sync.Mutex
	active   atomic.Bool
	ok       atomic.Uint64
	failed   atomic.Uint64
	resolver *core.SmartDNS
}

func (d *DNS) Alive() bool { return d.active.Load() }

// Resolver is shared by intercepted DNS replies and service health checks, so
// the UI cannot validate a different ChatGPT route from the one apps receive.
func (d *DNS) Resolver() *core.SmartDNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.active.Load() {
		return nil
	}
	return d.resolver
}
func (d *DNS) Counters() map[string]uint64 {
	return map[string]uint64{"smart_dns_ok": d.ok.Load(), "smart_dns_failed": d.failed.Load()}
}
func (d *DNS) Start(ctx context.Context, bin string, rules core.DomainRules) (func(), error) {
	dll, e := windows.LoadDLL(filepath.Join(bin, "WinDivert.dll"))
	if e != nil {
		return nil, e
	}
	open, e := dll.FindProc("WinDivertOpen")
	if e != nil {
		dll.Release()
		return nil, e
	}
	procedures := make([]*windows.Proc, 4)
	for i, name := range []string{"WinDivertRecv", "WinDivertSend", "WinDivertClose", "WinDivertHelperCalcChecksums"} {
		procedures[i], e = dll.FindProc(name)
		if e != nil {
			dll.Release()
			return nil, fmt.Errorf("%s: %w", name, e)
		}
	}
	recv, send, closeProc, checksums := procedures[0], procedures[1], procedures[2], procedures[3]
	filter := []byte("outbound and !loopback and udp.DstPort == 53\x00")
	handle, _, err := open.Call(uintptr(unsafe.Pointer(&filter[0])), 0, 200, 0)
	if handle == uintptr(windows.InvalidHandle) || handle == 0 {
		dll.Release()
		return nil, fmt.Errorf("WinDivert: %v", err)
	}
	windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache").Call()
	resolver := core.NewSmartDNS(rules)
	d.mu.Lock()
	d.handle = windows.Handle(handle)
	d.resolver = resolver
	d.mu.Unlock()
	d.active.Store(true)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			closeProc.Call(handle)
			<-done
			d.active.Store(false)
			dll.Release()
			windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache").Call()
		})
	}
	go func() {
		defer close(done)
		defer d.active.Store(false)
		defer func() {
			d.mu.Lock()
			if d.resolver == resolver {
				d.resolver = nil
			}
			d.mu.Unlock()
			resolver.Close()
		}()
		slots := make(chan struct{}, 32)
		var tasks sync.WaitGroup
		defer tasks.Wait()
		defer cancel()
		forward := func(packet, address []byte) bool {
			if len(packet) == 0 {
				return false
			}
			var n uint32
			ok, _, _ := send.Call(handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&address[0])))
			return ok != 0 && n == uint32(len(packet))
		}
		respond := func(packet, address, response []byte) bool {
			reply := core.ReplyPacket(packet, response)
			if reply == nil {
				return false
			}
			flags := binary.LittleEndian.Uint32(address[8:12])
			binary.LittleEndian.PutUint32(address[8:12], flags&^((1<<17)|(7<<21)))
			ok, _, _ := checksums.Call(uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(unsafe.Pointer(&address[0])), 0)
			return ok != 0 && forward(reply, address)
		}
		for {
			packet := make([]byte, 65535)
			address := make([]byte, 80)
			var count uint32
			ok, _, _ := recv.Call(handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&address[0])))
			if ok == 0 || count > uint32(len(packet)) {
				return
			}
			packet = packet[:count]
			query, _, valid := core.DNSPayload(packet)
			host, _, _, qe := core.Question(query)
			if !valid || qe != nil || !rules.ShouldResolveDNS(host) {
				forward(packet, address)
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				d.failed.Add(1)
				respond(packet, address, core.DNSReply(query, 2))
				continue
			}
			tasks.Add(1)
			go func(packet, address, q []byte) {
				defer tasks.Done()
				defer func() { <-slots }()
				response := resolver.Resolve(runCtx, q)
				if respond(packet, address, response) && response[3]&15 == 0 {
					d.ok.Add(1)
				} else {
					d.failed.Add(1)
				}
			}(packet, address, append([]byte(nil), query...))
		}
	}()
	return stop, nil
}
