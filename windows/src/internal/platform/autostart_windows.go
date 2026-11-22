//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const runRegistryKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "SorryRKN"

func autoStartCommand(exePath string) (string, error) {
	if strings.TrimSpace(exePath) == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	abs, err := filepath.Abs(exePath)
	if err == nil {
		exePath = abs
	}
	return `"` + exePath + `" --minimized`, nil
}

func IsAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runRegistryKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue(runValueName)
	return err == nil && strings.TrimSpace(val) != ""
}

func SetAutoStart(enabled bool, exePath string) error {
	if !enabled {
		k, err := registry.OpenKey(registry.CURRENT_USER, runRegistryKey, registry.SET_VALUE)
		if err != nil {
			if err == registry.ErrNotExist {
				return nil
			}
			return err
		}
		defer k.Close()
		err = k.DeleteValue(runValueName)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	cmd, err := autoStartCommand(exePath)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runRegistryKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(runValueName, cmd)
}
