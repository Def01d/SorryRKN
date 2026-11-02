package selfhost

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SOCKSForward makes the VPS loopback-only SOCKS service accessible on this
// device. Only its random local port and authenticated URL are returned to UI.
type SOCKSForward struct {
	URL      string
	listener net.Listener
	client   *ssh.Client
	stop     context.CancelFunc
	once     sync.Once
}

func (f *SOCKSForward) Close() error {
	f.once.Do(func() {
		f.stop()
		f.listener.Close()
		f.client.Close()
	})
	return nil
}

func OpenSOCKS(ctx context.Context, s Server, remoteURL string) (*SOCKSForward, error) {
	u, err := url.Parse(remoteURL)
	if err != nil || u.Scheme != "socks5" || u.Host != "127.0.0.1:11080" || u.User == nil || u.User.Username() != "sorryrkn" {
		return nil, errors.New("неверный адрес серверного SOCKS5")
	}
	if pw, ok := u.User.Password(); !ok || !passwordToken.MatchString(pw) {
		return nil, errors.New("неверные учётные данные SOCKS5")
	}
	life, stop := context.WithCancel(ctx)
	client, err := verifiedSSH(life, s)
	if err != nil {
		stop()
		return nil, err
	}
	// Probe an actual SSH direct-tcpip channel before advertising the proxy.
	probe, err := client.DialContext(life, "tcp", "127.0.0.1:11080")
	if err != nil {
		stop()
		client.Close()
		return nil, errors.New("SSH forwarding недоступен. Проверьте SOCKS5 и AllowTcpForwarding на VPS")
	}
	probe.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		stop()
		client.Close()
		return nil, err
	}
	u.Host = listener.Addr().String()
	f := &SOCKSForward{URL: u.String(), listener: listener, client: client, stop: stop}
	context.AfterFunc(life, func() { f.Close() })
	go func() { client.Wait(); f.Close() }()
	go func() {
		limit := make(chan struct{}, 64)
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case limit <- struct{}{}:
				go func() {
					defer func() { <-limit }()
					defer local.Close()
					remote, err := client.DialContext(life, "tcp", "127.0.0.1:11080")
					if err != nil {
						return
					}
					defer remote.Close()
					go func() {
						io.Copy(remote, local)
						if cw, ok := remote.(interface{ CloseWrite() error }); ok {
							cw.CloseWrite()
						}
					}()
					io.Copy(local, remote)
				}()
			default:
				local.Close()
			}
		}
	}()
	return f, nil
}
