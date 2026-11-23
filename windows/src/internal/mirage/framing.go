package mirage

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
)

type wireFrame struct {
	Type     byte
	StreamID uint32
	AddrType byte
	Host     string
	Port     uint16
	Data     []byte
	Delta    uint32
	ErrMsg   string
}

type wireCodec struct {
	rw io.ReadWriteCloser

	sendHdr  cipher.AEAD
	sendBody cipher.AEAD
	recvHdr  cipher.AEAD
	recvBody cipher.AEAD

	writeMu    sync.Mutex
	sendSeq    uint64
	framesSent uint64
	sendBuf    []byte

	readMu  sync.Mutex
	recvSeq uint64
	hdrBuf  [18]byte

	bytesMoved atomic.Int64
	jitterPad  bool
}

func newWireCodec(rw io.ReadWriteCloser, isClient bool, keys sessionKeys, jitterPad bool) (*wireCodec, error) {
	var sh, sb, rh, rb cipher.AEAD
	var err error
	if isClient {
		sh, sb, err = makeAEADs(keys.C2SHeader, keys.C2SBody)
		if err != nil {
			return nil, err
		}
		rh, rb, err = makeAEADs(keys.S2CHeader, keys.S2CBody)
		if err != nil {
			return nil, err
		}
	} else {
		sh, sb, err = makeAEADs(keys.S2CHeader, keys.S2CBody)
		if err != nil {
			return nil, err
		}
		rh, rb, err = makeAEADs(keys.C2SHeader, keys.C2SBody)
		if err != nil {
			return nil, err
		}
	}
	return &wireCodec{
		rw:        rw,
		sendHdr:   sh,
		sendBody:  sb,
		recvHdr:   rh,
		recvBody:  rb,
		jitterPad: jitterPad,
	}, nil
}

func buildNonce(seq uint64) [12]byte {
	var n [12]byte
	copy(n[0:4], "SRKN")
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n
}

func (w *wireCodec) BytesMoved() int64 {
	return w.bytesMoved.Load()
}

func (w *wireCodec) Close() error {
	return w.rw.Close()
}

func (w *wireCodec) WriteFrame(f wireFrame) error {
	payload, err := encodeWireFrame(f)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameBody {
		return fmt.Errorf("кадр mirage слишком велик (%d > %d)", len(payload), MaxFrameBody)
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	targetLen := len(payload)
	if w.framesSent < 4 && targetLen < 700 {
		// Polymorphic padding on first 4 frames defeats handshake length classifiers.
		targetLen = randIntRange(700, 1380)
	} else if w.jitterPad && len(payload) < 256 && f.Type != FrameData {
		targetLen = len(payload) + randIntRange(8, 64)
	}
	if targetLen > MaxFrameBody {
		targetLen = MaxFrameBody
	}
	if targetLen < len(payload) {
		targetLen = len(payload)
	}

	nonce := buildNonce(w.sendSeq)
	w.sendSeq++
	w.framesSent++

	var plainHdr [2]byte
	binary.BigEndian.PutUint16(plainHdr[:], uint16(targetLen))

	totalWire := (2 + 16) + (targetLen + 16)
	if cap(w.sendBuf) < totalWire {
		w.sendBuf = make([]byte, totalWire)
	}
	wire := w.sendBuf[:totalWire]

	w.sendHdr.Seal(wire[:0], nonce[:], plainHdr[:], nil)

	plainBodyStart := 18
	// Reuse the scratch slice suffix safely after building plaintext.
	plainBody := make([]byte, targetLen)
	copy(plainBody, payload)
	w.sendBody.Seal(wire[plainBodyStart:plainBodyStart], nonce[:], plainBody, plainHdr[:])

	n, err := w.rw.Write(wire)
	if n > 0 {
		w.bytesMoved.Add(int64(n))
	}
	return err
}

func (w *wireCodec) ReadFrame() (wireFrame, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	var zero wireFrame
	if _, err := io.ReadFull(w.rw, w.hdrBuf[:]); err != nil {
		return zero, err
	}
	nonce := buildNonce(w.recvSeq)
	w.recvSeq++

	var plainHdrBuf [2]byte
	plainHdr, err := w.recvHdr.Open(plainHdrBuf[:0], nonce[:], w.hdrBuf[:], nil)
	if err != nil {
		return zero, errors.New("ошибка аутентификации заголовка кадра mirage")
	}
	bodyLen := int(binary.BigEndian.Uint16(plainHdr))
	if bodyLen == 0 || bodyLen > MaxFrameBody {
		return zero, fmt.Errorf("некорректная длина кадра mirage: %d", bodyLen)
	}

	cipherBody := make([]byte, bodyLen+w.recvBody.Overhead())
	if _, err := io.ReadFull(w.rw, cipherBody); err != nil {
		return zero, err
	}
	w.bytesMoved.Add(int64(len(w.hdrBuf) + len(cipherBody)))

	plainBody, err := w.recvBody.Open(cipherBody[:0], nonce[:], cipherBody, plainHdr)
	if err != nil {
		return zero, errors.New("ошибка аутентификации тела кадра mirage")
	}
	return decodeWireFrame(plainBody)
}

func encodeWireFrame(f wireFrame) ([]byte, error) {
	switch f.Type {
	case FrameOpenTCP:
		addrBytes, err := encodeTargetAddr(f.AddrType, f.Host, f.Port)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 1+4+len(addrBytes))
		out[0] = FrameOpenTCP
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		copy(out[5:], addrBytes)
		return out, nil

	case FrameOpenOK:
		out := make([]byte, 5)
		out[0] = FrameOpenOK
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		return out, nil

	case FrameData:
		if len(f.Data) > MaxFrameBody-7 {
			return nil, errors.New("фрагмент данных mirage превышает предел")
		}
		out := make([]byte, 7+len(f.Data))
		out[0] = FrameData
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		binary.BigEndian.PutUint16(out[5:7], uint16(len(f.Data)))
		copy(out[7:], f.Data)
		return out, nil

	case FrameClose:
		msg := f.ErrMsg
		if len(msg) > 240 {
			msg = msg[:240]
		}
		out := make([]byte, 6+len(msg))
		out[0] = FrameClose
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		out[5] = byte(len(msg))
		copy(out[6:], msg)
		return out, nil

	case FrameUDP:
		addrBytes, err := encodeTargetAddr(f.AddrType, f.Host, f.Port)
		if err != nil {
			return nil, err
		}
		if 1+4+len(addrBytes)+2+len(f.Data) > MaxFrameBody {
			return nil, errors.New("UDP-датаграмма mirage превышает предел кадра")
		}
		out := make([]byte, 1+4+len(addrBytes)+2+len(f.Data))
		out[0] = FrameUDP
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		copy(out[5:], addrBytes)
		pos := 5 + len(addrBytes)
		binary.BigEndian.PutUint16(out[pos:pos+2], uint16(len(f.Data)))
		copy(out[pos+2:], f.Data)
		return out, nil

	case FrameChaff:
		n := len(f.Data)
		if n > MaxFrameBody-3 {
			n = MaxFrameBody - 3
		}
		out := make([]byte, 3+n)
		out[0] = FrameChaff
		binary.BigEndian.PutUint16(out[1:3], uint16(n))
		copy(out[3:], f.Data[:n])
		return out, nil

	case FrameRetire:
		return []byte{FrameRetire}, nil

	case FrameCredit:
		out := make([]byte, 9)
		out[0] = FrameCredit
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		binary.BigEndian.PutUint32(out[5:9], f.Delta)
		return out, nil

	case FrameFIN:
		out := make([]byte, 5)
		out[0] = FrameFIN
		binary.BigEndian.PutUint32(out[1:5], f.StreamID)
		return out, nil

	default:
		return nil, fmt.Errorf("неизвестный тип кадра %d", f.Type)
	}
}

func decodeWireFrame(b []byte) (wireFrame, error) {
	var f wireFrame
	if len(b) < 1 {
		return f, errors.New("пустой кадр mirage")
	}
	f.Type = b[0]
	switch f.Type {
	case FrameOpenTCP:
		if len(b) < 8 {
			return f, errors.New("усечённый кадр OpenTCP")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		atyp, host, port, _, err := decodeTargetAddr(b[5:])
		if err != nil {
			return f, err
		}
		f.AddrType, f.Host, f.Port = atyp, host, port
		return f, nil

	case FrameOpenOK:
		if len(b) < 5 {
			return f, errors.New("усечённый кадр OpenOK")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		return f, nil

	case FrameData:
		if len(b) < 7 {
			return f, errors.New("усечённый кадр Data")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		n := int(binary.BigEndian.Uint16(b[5:7]))
		if len(b) < 7+n {
			return f, errors.New("некорректная длина Data")
		}
		f.Data = make([]byte, n)
		copy(f.Data, b[7:7+n])
		return f, nil

	case FrameClose:
		if len(b) < 6 {
			return f, errors.New("усечённый кадр Close")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		n := int(b[5])
		if len(b) < 6+n {
			return f, errors.New("некорректная длина Close")
		}
		f.ErrMsg = string(b[6 : 6+n])
		return f, nil

	case FrameUDP:
		if len(b) < 10 {
			return f, errors.New("усечённый кадр UDP")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		atyp, host, port, used, err := decodeTargetAddr(b[5:])
		if err != nil {
			return f, err
		}
		pos := 5 + used
		if len(b) < pos+2 {
			return f, errors.New("усечённая длина UDP")
		}
		n := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		if len(b) < pos+2+n {
			return f, errors.New("некорректная длина UDP payload")
		}
		f.AddrType, f.Host, f.Port = atyp, host, port
		f.Data = make([]byte, n)
		copy(f.Data, b[pos+2:pos+2+n])
		return f, nil

	case FrameChaff:
		if len(b) < 3 {
			return f, errors.New("усечённый кадр Chaff")
		}
		n := int(binary.BigEndian.Uint16(b[1:3]))
		if len(b) < 3+n {
			return f, errors.New("некорректная длина Chaff")
		}
		return f, nil

	case FrameRetire:
		return f, nil

	case FrameCredit:
		if len(b) < 9 {
			return f, errors.New("усечённый кадр Credit")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		f.Delta = binary.BigEndian.Uint32(b[5:9])
		return f, nil

	case FrameFIN:
		if len(b) < 5 {
			return f, errors.New("усечённый кадр FIN")
		}
		f.StreamID = binary.BigEndian.Uint32(b[1:5])
		return f, nil

	default:
		return f, fmt.Errorf("неподдерживаемый тип кадра %d", f.Type)
	}
}

func encodeTargetAddr(atyp byte, host string, port uint16) ([]byte, error) {
	if atyp == 0 {
		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				atyp = AddrIPv4
			} else {
				atyp = AddrIPv6
			}
		} else {
			atyp = AddrDomain
		}
	}
	switch atyp {
	case AddrIPv4:
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return nil, fmt.Errorf("некорректный IPv4 %q", host)
		}
		out := make([]byte, 1+4+2)
		out[0] = AddrIPv4
		copy(out[1:5], ip)
		binary.BigEndian.PutUint16(out[5:7], port)
		return out, nil

	case AddrIPv6:
		ip := net.ParseIP(host).To16()
		if ip == nil {
			return nil, fmt.Errorf("некорректный IPv6 %q", host)
		}
		out := make([]byte, 1+16+2)
		out[0] = AddrIPv6
		copy(out[1:17], ip)
		binary.BigEndian.PutUint16(out[17:19], port)
		return out, nil

	case AddrDomain:
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("некорректная длина домена %q", host)
		}
		out := make([]byte, 1+1+len(host)+2)
		out[0] = AddrDomain
		out[1] = byte(len(host))
		copy(out[2:], host)
		binary.BigEndian.PutUint16(out[2+len(host):], port)
		return out, nil

	default:
		return nil, fmt.Errorf("неподдерживаемый тип адреса %d", atyp)
	}
}

func decodeTargetAddr(b []byte) (atyp byte, host string, port uint16, used int, err error) {
	if len(b) < 1 {
		return 0, "", 0, 0, errors.New("пустой адрес")
	}
	atyp = b[0]
	switch atyp {
	case AddrIPv4:
		if len(b) < 7 {
			return 0, "", 0, 0, errors.New("усечённый адрес IPv4")
		}
		ip := net.IP(b[1:5]).String()
		port = binary.BigEndian.Uint16(b[5:7])
		return atyp, ip, port, 7, nil

	case AddrIPv6:
		if len(b) < 19 {
			return 0, "", 0, 0, errors.New("усечённый адрес IPv6")
		}
		ip := net.IP(b[1:17]).String()
		port = binary.BigEndian.Uint16(b[17:19])
		return atyp, ip, port, 19, nil

	case AddrDomain:
		if len(b) < 2 {
			return 0, "", 0, 0, errors.New("усечённая длина домена")
		}
		n := int(b[1])
		if n == 0 || len(b) < 2+n+2 {
			return 0, "", 0, 0, errors.New("усечённый домен")
		}
		host = string(b[2 : 2+n])
		port = binary.BigEndian.Uint16(b[2+n : 2+n+2])
		return atyp, host, port, 2 + n + 2, nil

	default:
		return 0, "", 0, 0, fmt.Errorf("неизвестный тип адреса %d", atyp)
	}
}

func randIntRange(minVal, maxVal int) int {
	if maxVal <= minVal {
		return minVal
	}
	diff := big.NewInt(int64(maxVal - minVal + 1))
	v, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return minVal
	}
	return minVal + int(v.Int64())
}
