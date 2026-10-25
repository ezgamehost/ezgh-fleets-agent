package creds

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// File reads a bot key from a root-only file, on every call, so replacing the file rotates
// the key without a restart.
type File struct{ Path string }

func (f *File) Key(context.Context) (string, error) {
	fi, err := os.Stat(f.Path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is mode %04o: the key file must be 0600 (readable by root only)", f.Path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(b))
	if k == "" || strings.ContainsAny(k, " \n\t") {
		return "", errors.New(f.Path + " must hold one API key")
	}
	return k, nil
}

func (f *File) Invalidate(string) {}
