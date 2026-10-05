package core

import (
	"os"
	"sync"
)

type Log struct {
	mu   sync.Mutex
	file *os.File
	size int64
}

func OpenLog(path string) (*Log, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		return nil, e
	}
	return &Log{file: f}, nil
}
func (l *Log) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size+int64(len(b)) > 2*1024*1024 {
		if e := l.file.Truncate(0); e != nil {
			return 0, e
		}
		l.file.Seek(0, 0)
		l.size = 0
	}
	n, e := l.file.Write(b)
	l.size += int64(n)
	return n, e
}
func (l *Log) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
