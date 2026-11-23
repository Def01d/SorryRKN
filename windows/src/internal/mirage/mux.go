package mirage

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// udpHandler delivers upstream UDP packets on the server side.
type udpHandler interface {
	Send(atyp byte, host string, port uint16, data []byte) error
	Close() error
}

// carrierHooks connects muxCarrier to either client or server behavior.
type carrierHooks struct {
	DialTCP func(ctx context.Context, atyp byte, host string, port uint16) (net.Conn, error)
	OpenUDP func(ctx context.Context, streamID uint32, reply func(atyp byte, host string, port uint16, data []byte) error) (udpHandler, error)
}

type muxCarrier struct {
	codec    *wireCodec
	isClient bool
	hooks    carrierHooks

	ctx    context.Context
	cancel context.CancelFunc

	nextStreamID atomic.Uint32
	activeCount  atomic.Int32
	retired      atomic.Bool
	createdAt    time.Time

	streamsMu sync.Mutex
	streams   map[uint32]*muxStream
	udpClient map[uint32]func(atyp byte, host string, port uint16, data []byte)
	udpServer map[uint32]*serverUDPSlot

	onActivity func()
	closeOnce  sync.Once
	wg         sync.WaitGroup
}

type serverUDPSlot struct {
	handler udpHandler
	ch      chan wireFrame
	closed  atomic.Bool
}

func newMuxCarrier(parent context.Context, codec *wireCodec, isClient bool, hooks carrierHooks, chaff bool, onDrain func()) *muxCarrier {
	ctx, cancel := context.WithCancel(parent)
	c := &muxCarrier{
		codec:      codec,
		isClient:   isClient,
		hooks:      hooks,
		ctx:        ctx,
		cancel:     cancel,
		createdAt:  time.Now(),
		streams:    make(map[uint32]*muxStream),
		udpClient:  make(map[uint32]func(byte, string, uint16, []byte)),
		udpServer:  make(map[uint32]*serverUDPSlot),
		onActivity: onDrain,
	}
	c.wg.Add(1)
	go c.readLoop()

	if isClient && chaff {
		c.wg.Add(1)
		go c.chaffLoop()
	}
	return c
}

func (c *muxCarrier) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.cancel()
		err = c.codec.Close()
		c.wakeAllStreams(errors.New("носитель mirage закрыт"))
		c.streamsMu.Lock()
		for id, slot := range c.udpServer {
			slot.closed.Store(true)
			close(slot.ch)
			_ = slot.handler.Close()
			delete(c.udpServer, id)
		}
		for id := range c.udpClient {
			delete(c.udpClient, id)
		}
		c.streamsMu.Unlock()
	})
	return err
}

func (c *muxCarrier) Wait() {
	c.wg.Wait()
}

func (c *muxCarrier) Done() <-chan struct{} {
	return c.ctx.Done()
}

func (c *muxCarrier) ActiveCount() int {
	return int(c.activeCount.Load())
}

func (c *muxCarrier) BytesMoved() int64 {
	return c.codec.BytesMoved()
}

func (c *muxCarrier) MarkRetired() {
	c.retired.Store(true)
}

func (c *muxCarrier) IsRetired() bool {
	return c.retired.Load()
}

// DialStream opens a new multiplexed TCP stream over this carrier (client side).
func (c *muxCarrier) DialStream(ctx context.Context, atyp byte, host string, port uint16) (*muxStream, error) {
	id := c.nextStreamID.Add(1)
	s := newMuxStream(c, id)

	c.streamsMu.Lock()
	if c.ctx.Err() != nil {
		c.streamsMu.Unlock()
		return nil, errors.New("соединение с носителем mirage разорвано")
	}
	c.streams[id] = s
	c.activeCount.Add(1)
	c.streamsMu.Unlock()

	err := c.codec.WriteFrame(wireFrame{
		Type:     FrameOpenTCP,
		StreamID: id,
		AddrType: atyp,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		c.removeStream(id, err)
		return nil, err
	}

	select {
	case <-s.openReady:
		if s.openErr != nil {
			c.removeStream(id, s.openErr)
			return nil, s.openErr
		}
		return s, nil
	case <-ctx.Done():
		_ = c.codec.WriteFrame(wireFrame{Type: FrameClose, StreamID: id, ErrMsg: "timeout"})
		c.removeStream(id, ctx.Err())
		return nil, ctx.Err()
	case <-c.ctx.Done():
		c.removeStream(id, errors.New("канал mirage закрыт"))
		return nil, errors.New("канал mirage закрыт")
	}
}

// OpenClientUDP registers a client-side UDP association stream ID.
func (c *muxCarrier) OpenClientUDP(onReply func(atyp byte, host string, port uint16, data []byte)) (uint32, func(atyp byte, host string, port uint16, data []byte) error, func()) {
	id := c.nextStreamID.Add(1)
	c.streamsMu.Lock()
	c.udpClient[id] = onReply
	c.activeCount.Add(1)
	c.streamsMu.Unlock()

	sendFn := func(atyp byte, host string, port uint16, data []byte) error {
		return c.codec.WriteFrame(wireFrame{
			Type:     FrameUDP,
			StreamID: id,
			AddrType: atyp,
			Host:     host,
			Port:     port,
			Data:     data,
		})
	}
	closeFn := func() {
		c.streamsMu.Lock()
		_, exists := c.udpClient[id]
		if exists {
			delete(c.udpClient, id)
			c.activeCount.Add(-1)
		}
		c.streamsMu.Unlock()
		if exists {
			_ = c.codec.WriteFrame(wireFrame{Type: FrameClose, StreamID: id})
			if c.onActivity != nil {
				c.onActivity()
			}
		}
	}
	return id, sendFn, closeFn
}

func (c *muxCarrier) removeStream(id uint32, reason error) {
	c.streamsMu.Lock()
	s, ok := c.streams[id]
	if ok {
		delete(c.streams, id)
		c.activeCount.Add(-1)
	}
	c.streamsMu.Unlock()
	if ok {
		s.closeLocal(reason)
		if c.onActivity != nil {
			c.onActivity()
		}
	}
}

func (c *muxCarrier) wakeAllStreams(reason error) {
	c.streamsMu.Lock()
	list := make([]*muxStream, 0, len(c.streams))
	for id, s := range c.streams {
		list = append(list, s)
		delete(c.streams, id)
		c.activeCount.Add(-1)
	}
	c.streamsMu.Unlock()
	for _, s := range list {
		s.failOpen(reason)
		s.closeLocal(reason)
	}
}

func (c *muxCarrier) readLoop() {
	defer c.wg.Done()
	defer func() { _ = c.Close() }()

	for {
		f, err := c.codec.ReadFrame()
		if err != nil {
			return
		}
		switch f.Type {
		case FrameChaff:
			// Silently discard authenticated chaff.

		case FrameRetire:
			c.retired.Store(true)

		case FrameOpenTCP:
			if c.isClient || c.hooks.DialTCP == nil {
				continue
			}
			s := newMuxStream(c, f.StreamID)
			c.streamsMu.Lock()
			if _, dup := c.streams[f.StreamID]; dup {
				c.streamsMu.Unlock()
				continue
			}
			c.streams[f.StreamID] = s
			c.activeCount.Add(1)
			c.streamsMu.Unlock()

			c.wg.Add(1)
			go c.serveServerTCP(s, f)

		case FrameOpenOK:
			c.streamsMu.Lock()
			s := c.streams[f.StreamID]
			c.streamsMu.Unlock()
			if s != nil {
				s.completeOpen(nil)
			}

		case FrameData:
			c.streamsMu.Lock()
			s := c.streams[f.StreamID]
			c.streamsMu.Unlock()
			if s != nil {
				s.pushRecv(f.Data)
			}

		case FrameCredit:
			c.streamsMu.Lock()
			s := c.streams[f.StreamID]
			c.streamsMu.Unlock()
			if s != nil {
				s.addSendCredit(int(f.Delta))
			}

		case FrameFIN:
			c.streamsMu.Lock()
			s := c.streams[f.StreamID]
			c.streamsMu.Unlock()
			if s != nil {
				s.pushEOF()
			}

		case FrameClose:
			var closeErr error = io.EOF
			if f.ErrMsg != "" && f.ErrMsg != "eof" {
				closeErr = errors.New(f.ErrMsg)
			}
			c.streamsMu.Lock()
			s := c.streams[f.StreamID]
			if s != nil {
				delete(c.streams, f.StreamID)
				c.activeCount.Add(-1)
			}
			slot := c.udpServer[f.StreamID]
			if slot != nil {
				delete(c.udpServer, f.StreamID)
				c.activeCount.Add(-1)
			}
			c.streamsMu.Unlock()
			if s != nil {
				s.failOpen(closeErr)
				s.closeLocal(closeErr)
				if c.onActivity != nil {
					c.onActivity()
				}
			}
			if slot != nil {
				slot.closed.Store(true)
				close(slot.ch)
				_ = slot.handler.Close()
			}

		case FrameUDP:
			if c.isClient {
				c.streamsMu.Lock()
				fn := c.udpClient[f.StreamID]
				c.streamsMu.Unlock()
				if fn != nil {
					fn(f.AddrType, f.Host, f.Port, f.Data)
				}
			} else if c.hooks.OpenUDP != nil {
				c.handleServerUDP(f)
			}
		}
	}
}

func (c *muxCarrier) serveServerTCP(s *muxStream, openFrame wireFrame) {
	defer c.wg.Done()

	dialCtx, dialCancel := context.WithTimeout(c.ctx, 15*time.Second)
	remote, err := c.hooks.DialTCP(dialCtx, openFrame.AddrType, openFrame.Host, openFrame.Port)
	dialCancel()
	if err != nil {
		_ = c.codec.WriteFrame(wireFrame{Type: FrameClose, StreamID: s.id, ErrMsg: err.Error()})
		c.removeStream(s.id, err)
		return
	}
	defer func() { _ = remote.Close() }()

	if err := c.codec.WriteFrame(wireFrame{Type: FrameOpenOK, StreamID: s.id}); err != nil {
		c.removeStream(s.id, err)
		return
	}

	var pumpWG sync.WaitGroup
	pumpWG.Add(2)
	go func() {
		defer pumpWG.Done()
		_, _ = io.Copy(remote, s)
		if tc, ok := remote.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = remote.Close()
		}
	}()
	go func() {
		defer pumpWG.Done()
		buf := make([]byte, StreamChunkSize)
		for {
			n, rerr := remote.Read(buf)
			if n > 0 {
				if _, werr := s.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = s.CloseWrite()
	}()
	pumpWG.Wait()
	_ = c.codec.WriteFrame(wireFrame{Type: FrameClose, StreamID: s.id, ErrMsg: "eof"})
	c.removeStream(s.id, io.EOF)
}

func (c *muxCarrier) handleServerUDP(f wireFrame) {
	c.streamsMu.Lock()
	slot := c.udpServer[f.StreamID]
	if slot == nil && c.ctx.Err() == nil {
		replyFn := func(atyp byte, host string, port uint16, data []byte) error {
			return c.codec.WriteFrame(wireFrame{
				Type:     FrameUDP,
				StreamID: f.StreamID,
				AddrType: atyp,
				Host:     host,
				Port:     port,
				Data:     data,
			})
		}
		h, err := c.hooks.OpenUDP(c.ctx, f.StreamID, replyFn)
		if err == nil {
			slot = &serverUDPSlot{
				handler: h,
				ch:      make(chan wireFrame, 64),
			}
			c.udpServer[f.StreamID] = slot
			c.activeCount.Add(1)
			c.wg.Add(1)
			go func(id uint32, sl *serverUDPSlot) {
				defer c.wg.Done()
				for pkt := range sl.ch {
					_ = sl.handler.Send(pkt.AddrType, pkt.Host, pkt.Port, pkt.Data)
				}
			}(f.StreamID, slot)
		}
	}
	c.streamsMu.Unlock()

	if slot != nil && !slot.closed.Load() {
		select {
		case slot.ch <- f:
		default:
			// Drop under burst rather than blocking the carrier read loop.
		}
	}
}

func (c *muxCarrier) chaffLoop() {
	defer c.wg.Done()
	for {
		delay := time.Duration(randIntRange(4000, 11000)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if c.retired.Load() || c.ActiveCount() == 0 {
			continue
		}
		size := randIntRange(32, 160)
		_ = c.codec.WriteFrame(wireFrame{
			Type: FrameChaff,
			Data: make([]byte, size),
		})
	}
}

type muxStream struct {
	carrier *muxCarrier
	id      uint32

	openOnce  sync.Once
	openReady chan struct{}
	openErr   error

	creditMu   sync.Mutex
	creditCond *sync.Cond
	sendCredit int
	sendClosed bool

	recvMu       sync.Mutex
	recvCond     *sync.Cond
	recvChunks   [][]byte
	recvBuffered int
	recvUnacked  int
	recvClosed   bool
	recvErr      error
}

func newMuxStream(carrier *muxCarrier, id uint32) *muxStream {
	s := &muxStream{
		carrier:    carrier,
		id:         id,
		openReady:  make(chan struct{}),
		sendCredit: InitialStreamWindow,
	}
	s.creditCond = sync.NewCond(&s.creditMu)
	s.recvCond = sync.NewCond(&s.recvMu)
	return s
}

func (s *muxStream) completeOpen(err error) {
	s.openOnce.Do(func() {
		s.openErr = err
		close(s.openReady)
	})
}

func (s *muxStream) failOpen(err error) {
	s.completeOpen(err)
}

func (s *muxStream) addSendCredit(delta int) {
	if delta <= 0 {
		return
	}
	s.creditMu.Lock()
	s.sendCredit += delta
	s.creditCond.Broadcast()
	s.creditMu.Unlock()
}

func (s *muxStream) pushRecv(data []byte) {
	s.recvMu.Lock()
	if s.recvClosed {
		s.recvMu.Unlock()
		return
	}
	if s.recvBuffered+len(data) > InitialStreamWindow*2 {
		s.recvClosed = true
		s.recvErr = errors.New("переполнение буфера потока mirage")
		s.recvCond.Broadcast()
		s.recvMu.Unlock()
		return
	}
	s.recvChunks = append(s.recvChunks, data)
	s.recvBuffered += len(data)
	s.recvCond.Signal()
	s.recvMu.Unlock()
}

func (s *muxStream) pushEOF() {
	s.recvMu.Lock()
	if !s.recvClosed {
		s.recvClosed = true
		s.recvErr = io.EOF
	}
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
}

func (s *muxStream) CloseWrite() error {
	s.creditMu.Lock()
	already := s.sendClosed
	s.sendClosed = true
	s.creditCond.Broadcast()
	s.creditMu.Unlock()
	if already {
		return nil
	}
	return s.carrier.codec.WriteFrame(wireFrame{
		Type:     FrameFIN,
		StreamID: s.id,
	})
}

func (s *muxStream) closeLocal(reason error) {
	s.creditMu.Lock()
	s.sendClosed = true
	s.creditCond.Broadcast()
	s.creditMu.Unlock()

	s.recvMu.Lock()
	if !s.recvClosed {
		s.recvClosed = true
		if reason == nil {
			reason = io.EOF
		}
		s.recvErr = reason
	}
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
}

func (s *muxStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.recvMu.Lock()
	for len(s.recvChunks) == 0 && !s.recvClosed {
		s.recvCond.Wait()
	}
	if len(s.recvChunks) == 0 {
		err := s.recvErr
		if err == nil {
			err = io.EOF
		}
		s.recvMu.Unlock()
		return 0, err
	}
	head := s.recvChunks[0]
	n := copy(p, head)
	if n == len(head) {
		s.recvChunks[0] = nil
		s.recvChunks = s.recvChunks[1:]
	} else {
		s.recvChunks[0] = head[n:]
	}
	s.recvBuffered -= n
	s.recvUnacked += n
	var creditToSend uint32
	if !s.recvClosed && s.recvUnacked >= StreamCreditThreshold {
		creditToSend = uint32(s.recvUnacked)
		s.recvUnacked = 0
	}
	s.recvMu.Unlock()

	if creditToSend > 0 {
		_ = s.carrier.codec.WriteFrame(wireFrame{
			Type:     FrameCredit,
			StreamID: s.id,
			Delta:    creditToSend,
		})
	}
	return n, nil
}

func (s *muxStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.creditMu.Lock()
		for s.sendCredit <= 0 && !s.sendClosed {
			s.creditCond.Wait()
		}
		if s.sendClosed {
			s.creditMu.Unlock()
			return written, io.ErrClosedPipe
		}
		chunk := len(p)
		if chunk > StreamChunkSize {
			chunk = StreamChunkSize
		}
		if chunk > s.sendCredit {
			chunk = s.sendCredit
		}
		s.sendCredit -= chunk
		s.creditMu.Unlock()

		if err := s.carrier.codec.WriteFrame(wireFrame{
			Type:     FrameData,
			StreamID: s.id,
			Data:     p[:chunk],
		}); err != nil {
			return written, err
		}
		written += chunk
		p = p[chunk:]
	}
	return written, nil
}

func (s *muxStream) Close() error {
	_ = s.carrier.codec.WriteFrame(wireFrame{
		Type:     FrameClose,
		StreamID: s.id,
		ErrMsg:   "eof",
	})
	s.carrier.removeStream(s.id, io.EOF)
	return nil
}
