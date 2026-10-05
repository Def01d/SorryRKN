//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sorryrkn/internal/platform"
	"strings"
	"time"
)

func nativeTests(report map[string]any) {
	runner := platform.Runner{}
	script := `from proxy._aes import Cipher,algorithms,modes; k=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'); iv=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'); p=bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'); e=Cipher(algorithms.AES(k),modes.CTR(iv)).encryptor(); assert (e.update(p[:7])+e.update(p[7:])).hex()=='874d6191b620e3261bef6864990db6ce';print('CRYPTO_PASS')`
	child, e := runner.Start(filepath.Join(root, "python", "python.exe"), []string{"-c", script}, root, nil, filepath.Join(data, "crypto-test.log"))
	if e != nil {
		report["crypto_error"] = e.Error()
	} else {
		deadline := time.Now().Add(20 * time.Second)
		for child.Alive() && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		child.Stop()
		b, _ := os.ReadFile(filepath.Join(data, "crypto-test.log"))
		report["crypto"] = strings.Contains(string(b), "CRYPTO_PASS")
		if !strings.Contains(string(b), "CRYPTO_PASS") {
			report["crypto_error"] = string(b)
		}
	}
	input, _ := json.Marshal(map[string]any{"secret": secret, "test_mode": true})
	input = append(input, '\n')
	child, e = runner.Start(filepath.Join(root, "python", "python.exe"), []string{"-u", filepath.Join(root, "app", "tg_runner.py")}, root, input, filepath.Join(data, "tg-test.log"))
	if e != nil {
		report["telegram_error"] = e.Error()
	} else {
		deadline := time.Now().Add(15 * time.Second)
		opened := false
		for time.Now().Before(deadline) && child.Alive() {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:1443", 150*time.Millisecond)
			if err == nil {
				conn.Close()
				opened = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		child.Stop()
		_, err := net.DialTimeout("tcp", "127.0.0.1:1443", 150*time.Millisecond)
		report["telegram_listener"] = opened
		report["job_cleanup"] = err != nil
		if !opened {
			b, _ := os.ReadFile(filepath.Join(data, "tg-test.log"))
			report["telegram_error"] = string(b)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	dns := &platform.DNS{}
	stop, e := dns.Start(ctx, filepath.Join(root, "zapret", "bin"))
	if e != nil {
		report["windivert_error"] = e.Error()
		cancel()
		return
	}
	report["windivert_open"] = true
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'c', 'h', 'a', 't', 'g', 'p', 't', 3, 'c', 'o', 'm', 0, 0, 28, 0, 1}
	conn, e := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if e == nil {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write(query)
		b := make([]byte, 4096)
		n, err := conn.Read(b)
		report["selective_dns"] = err == nil && n >= 12 && binary.BigEndian.Uint16(b[:2]) == 0x1234 && b[2]&128 != 0 && binary.BigEndian.Uint16(b[6:8]) == 0
		conn.Close()
		if err != nil {
			report["dns_error"] = err.Error()
		}
	} else {
		report["dns_error"] = e.Error()
	}
	cancel()
	stop()
	report["dns_stopped"] = !dns.Alive()
	child, e = runner.Start(filepath.Join(root, "zapret", "bin", "winws.exe"), []string{"--wf-tcp=18888", "--wf-udp=18889", "--filter-tcp=18888"}, filepath.Join(root, "zapret", "bin"), nil, filepath.Join(data, "winws-test.log"))
	if e == nil {
		time.Sleep(time.Second)
		report["winws_started"] = child.Alive()
		if !child.Alive() {
			b, _ := os.ReadFile(filepath.Join(data, "winws-test.log"))
			report["winws_error"] = string(b)
		}
		child.Stop()
		report["winws_stopped"] = !child.Alive()
	} else {
		report["winws_error"] = fmt.Sprint(e)
	}
}
