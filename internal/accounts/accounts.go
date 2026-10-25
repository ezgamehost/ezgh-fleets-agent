// Package accounts readies the OS account a session or command runs as: named accounts must
// exist, and ezgh-user is created on first use. Changes go through the host's own commands
// (useradd, visudo), never edits of the account files.
package accounts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const EzghUser = "ezgh-user"

var (
	// ErrNotFound means the account doesn't exist and isn't one the agent creates.
	ErrNotFound   = errors.New("osUser_not_found")
	OSUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

type Manager struct {
	Passwd     string // default /etc/passwd
	SudoersDir string // default /etc/sudoers.d
	// Exec runs a host command; default os/exec, with its output in the error.
	Exec func(ctx context.Context, name string, args ...string) error
	Log  *slog.Logger

	mu sync.Mutex // around every account change
}

// Acquire readies the instruction's account and returns its name.
func (m *Manager) Acquire(ctx context.Context, in protocol.Instruction) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case in.OSUser == nil:
		return "", ErrNotFound
	case *in.OSUser == EzghUser:
		// Only an openSession sets sudo (PD10): a command run as ezgh-user leaves it as it is.
		if err := m.ensureEzghUser(ctx, in.Type == protocol.TypeOpenSession, in.EzghUserSudo); err != nil {
			return "", err
		}
		return EzghUser, nil
	case !OSUserPattern.MatchString(*in.OSUser):
		return "", ErrNotFound
	}
	if _, ok, err := m.lookup(func(e entry) bool { return e.name == *in.OSUser }); err != nil || !ok {
		return "", errors.Join(ErrNotFound, err)
	}
	return *in.OSUser, nil
}

func (m *Manager) ensureEzghUser(ctx context.Context, setSudo, sudo bool) error {
	_, ok, err := m.lookup(func(e entry) bool { return e.name == EzghUser })
	if err != nil {
		return err
	}
	if !ok {
		if err := m.exec(ctx, "useradd", "--create-home", "--shell", defaultShell(), "--comment", "EZGH Fleets", EzghUser); err != nil {
			return err
		}
	}
	if !setSudo {
		return nil
	}
	dir := m.SudoersDir
	if dir == "" {
		dir = "/etc/sudoers.d"
	}
	path := filepath.Join(dir, EzghUser)
	if !sudo {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		m.Log.Warn("ezghUserSudo is on but sudo isn't installed (no " + dir + "): opening the session without it")
		return nil
	}
	tmp, err := os.CreateTemp(dir, "."+EzghUser+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(EzghUser + " ALL=(ALL) NOPASSWD:ALL\n")
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o440)
	}
	if err == nil {
		err = m.exec(ctx, "visudo", "-cf", tmp.Name())
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// defaultShell is the shell new accounts get.
func defaultShell() string {
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

type entry struct{ name string }

func (m *Manager) lookup(match func(entry) bool) (entry, bool, error) {
	entries, err := m.entries()
	if err != nil {
		return entry{}, false, err
	}
	for _, e := range entries {
		if match(e) {
			return e, true, nil
		}
	}
	return entry{}, false, nil
}

func (m *Manager) entries() ([]entry, error) {
	path := m.Passwd
	if path == "" {
		path = "/etc/passwd"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Split(sc.Text(), ":"); len(fields) == 7 {
			out = append(out, entry{name: fields[0]})
		}
	}
	return out, sc.Err()
}

func (m *Manager) exec(ctx context.Context, name string, args ...string) error {
	if m.Exec != nil {
		return m.Exec(ctx, name, args...)
	}
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
