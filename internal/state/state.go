// Package state keeps the agent's files in its root-only state directory.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type Dir struct{ Path string }

// LockFile is held (flock) by the running agent.
const LockFile = "agent.lock"

// ErrLocked: another agent is running with this state directory.
var ErrLocked = errors.New("another ezgh-fleets-agent is already running with this state directory")

// Lock takes the directory's exclusive lock for this process's life, or fails with ErrLocked.
func (d *Dir) Lock() (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(d.Path, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Open creates the directory if needed and makes it 0700.
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return nil, err
	}
	return &Dir{Path: path}, nil
}

// Read decodes the named JSON file into v. A missing file is an os.ErrNotExist error.
func (d *Dir) Read(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Write replaces the named file with v as JSON, atomically, mode 0600.
func (d *Dir) Write(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(d.Path, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // a no-op after the rename
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(d.Path, name)); err != nil {
		return err
	}
	if dir, err := os.Open(d.Path); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// Remove deletes the named file; a missing one isn't an error.
func (d *Dir) Remove(name string) error {
	if err := os.Remove(filepath.Join(d.Path, name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
