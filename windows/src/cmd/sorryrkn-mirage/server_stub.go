//go:build clientonly

package main

import "errors"

func runServerCmd(_ []string) error {
	return errors.New("server mode disabled in clientonly build")
}

func runKeygenCmd(_ []string) error {
	return errors.New("keygen disabled in clientonly build")
}
