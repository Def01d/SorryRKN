package tunnel

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

const maxLibrary = 32 << 20

func Load(path string) (Library, error) {
	var lib Library
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return lib, nil
	}
	if err != nil {
		return lib, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxLibrary+4097))
	if err != nil {
		return lib, err
	}
	if len(b) == 0 || len(b) > maxLibrary+4096 {
		return lib, errors.New("неверный размер хранилища VPN")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return lib, errors.New("хранилище VPN не открывается для текущего пользователя")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	raw := unsafe.Slice(out.Data, out.Size)
	defer clear(raw)
	if err := json.Unmarshal(raw, &lib); err != nil {
		return Library{}, errors.New("повреждено хранилище VPN")
	}
	return lib, nil
}
func Save(path string, lib Library) error {
	raw, err := json.Marshal(lib)
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) > maxLibrary {
		return errors.New("хранилище VPN превышает 32 МиБ")
	}
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	var out windows.DataBlob
	if err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".vpn-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(unsafe.Slice(out.Data, out.Size))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
