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
	handle windows.Handle
	mu     sync.Mutex
	active atomic.Bool
	ok     atomic.Uint64
	failed atomic.Uint64
}

func (d *DNS) Alive() bool { return d.active.Load() }
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
	recv, _ := dll.FindProc("WinDivertRecv")
	send, _ := dll.FindProc("WinDivertSend")
	closeProc, _ := dll.FindProc("WinDivertClose")
	checksums, _ := dll.FindProc("WinDivertHelperCalcChecksums")
	filter := []byte("outbound and !loopback and udp.DstPort == 53\x00")
	handle, _, err := open.Call(uintptr(unsafe.Pointer(&filter[0])), 0, 200, 0)
	if handle == uintptr(windows.InvalidHandle) || handle == 0 {
		dll.Release()
		return nil, fmt.Errorf("WinDivert: %v", err)
	}
	d.active.Store(true)
	windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache").Call()
	d.mu.Lock()
	d.handle = windows.Handle(handle)
	d.mu.Unlock()
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
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
		resolver := core.NewSmartDNS(rules)
		slots := make(chan struct{}, 32)
		var tasks sync.WaitGroup
		defer tasks.Wait()
		forward := func(packet, address []byte) {
			var n uint32
			send.Call(handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&address[0])))
		}
		for {
			packet := make([]byte, 65535)
			address := make([]byte, 80)
			var count uint32
			ok, _, _ := recv.Call(handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&address[0])))
			if ok == 0 {
				return
			}
			packet = packet[:count]
			query, _, valid := core.DNSPayload(packet)
			host, _, _, qe := core.Question(query)
			if !valid || qe != nil || !rules.IsGeo(host) {
				forward(packet, address)
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				reply := core.ReplyPacket(packet, core.DNSReply(query, 2))
				if reply != nil {
					flags := binary.LittleEndian.Uint32(address[8:12])
					binary.LittleEndian.PutUint32(address[8:12], flags&^(1<<17))
					checksums.Call(uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(unsafe.Pointer(&address[0])), 0)
					forward(reply, address)
				}
				continue
			}
			tasks.Add(1)
			go func(packet, address, q []byte) {
				defer tasks.Done()
				defer func() { <-slots }()
				response := resolver.Resolve(ctx, q)
				reply := core.ReplyPacket(packet, response)
				if reply == nil {
					d.failed.Add(1)
					return
				}
				if response[3]&15 == 0 {
					d.ok.Add(1)
				} else {
					d.failed.Add(1)
				}
				flags := binary.LittleEndian.Uint32(address[8:12])
				binary.LittleEndian.PutUint32(address[8:12], flags&^((1<<17)|(7<<21)))
				checksums.Call(uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(unsafe.Pointer(&address[0])), 0)
				forward(reply, address)
			}(packet, address, append([]byte(nil), query...))
		}
	}()
	return stop, nil
}
