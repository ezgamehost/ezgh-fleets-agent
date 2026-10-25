// Package accounts readies the OS account a session or command runs as: named accounts must
// exist, ezgh-user is created on first use, and per-person accounts are created expired and
// usable only while their owner has a session open. Changes go through the host's own
// commands (useradd, chage, loginctl, pkill), never file edits.
package accounts

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const (
	EzghUser = "ezgh-user"
	// markerPref starts a per-person account's GECOS: ezgh/<principal type>/<principal ID>.
	// Not colons: they separate /etc/passwd's fields.
	markerPref = "ezgh/"
	// CreatedFile, in the state directory, names the per-person accounts the agent created
	// (name → marker). A marker counts only on those: chfn can set anyone's GECOS.
	CreatedFile = "accounts.json"
)

var (
	// ErrNotFound means the account doesn't exist and isn't one the agent creates.
	ErrNotFound   = errors.New("osUser_not_found")
	OSUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

type Manager struct {
	Passwd     string // default /etc/passwd
	SudoersDir string // default /etc/sudoers.d
	// Exec runs a host command; default os/exec, with its output in the error.
	Exec func(ctx context.Context, name string, args ...string) error
	Log  *slog.Logger
	// State keeps CreatedFile.
	State *state.Dir

	mu      sync.Mutex // around every account change
	open    map[string]int
	created map[string]string
}

// Acquire readies the instruction's account and returns its name. release must be called
// when the session or command ends.
func (m *Manager) Acquire(ctx context.Context, in protocol.Instruction) (name string, release func(), err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	noop := func() {}
	switch {
	case in.OSUser != nil && *in.OSUser == EzghUser:
		// Only an openSession sets sudo (PD10): a command run as ezgh-user leaves it as it is.
		if err := m.ensureEzghUser(ctx, in.Type == protocol.TypeOpenSession, in.EzghUserSudo); err != nil {
			return "", nil, err
		}
		return EzghUser, noop, nil
	case in.OSUser != nil:
		if !OSUserPattern.MatchString(*in.OSUser) {
			return "", nil, ErrNotFound
		}
		if _, ok, err := m.lookup(func(e entry) bool { return e.name == *in.OSUser }); err != nil || !ok {
			return "", nil, errors.Join(ErrNotFound, err)
		}
		return *in.OSUser, noop, nil
	case in.Person != nil:
		name, err := m.person(ctx, *in.Person)
		if err != nil {
			return "", nil, err
		}
		if m.open == nil {
			m.open = map[string]int{}
		}
		if m.open[name] == 0 {
			if err := m.exec(ctx, "chage", "-E", "-1", name); err != nil {
				return "", nil, err
			}
		}
		m.open[name]++
		var once sync.Once
		return name, func() { once.Do(func() { m.releasePerson(name) }) }, nil
	}
	return "", nil, ErrNotFound
}

// ExpirePersons expires every per-person account and ends its processes. Run at start, when
// no session is open, so a crash mid-session leaves nothing usable.
func (m *Manager) ExpirePersons(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	created, err := m.loadCreated()
	if err != nil {
		return err
	}
	entries, err := m.entries()
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if _, ours := created[e.name]; ours && m.open[e.name] == 0 {
			errs = append(errs, m.lock(ctx, e.name))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) releasePerson(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.open[name]--; m.open[name] > 0 {
		return
	}
	delete(m.open, name)
	if err := m.lock(context.Background(), name); err != nil {
		m.Log.Error("couldn't expire a per-person account", "account", name, "err", err)
	}
}

// lock expires the account and ends everything running as it.
func (m *Manager) lock(ctx context.Context, name string) error {
	err := m.exec(ctx, "chage", "-E", "0", name)
	// Best effort: these fail when there's nothing to end.
	_ = m.exec(ctx, "loginctl", "terminate-user", name)
	_ = m.exec(ctx, "pkill", "-KILL", "-u", name)
	_ = m.exec(ctx, "loginctl", "disable-linger", name)
	return err
}

// person finds the account by its marker, or creates it (expired) under the base name.
func (m *Manager) person(ctx context.Context, p protocol.Person) (string, error) {
	if !idPattern.MatchString(p.Type) || !idPattern.MatchString(p.ID) {
		return "", fmt.Errorf("person %q:%q: not a usable principal", p.Type, p.ID)
	}
	marker := markerPref + p.Type + "/" + p.ID
	created, err := m.loadCreated()
	if err != nil {
		return "", err
	}
	if e, ok, err := m.lookup(func(e entry) bool { return e.gecos == marker && created[e.name] == marker }); err != nil || ok {
		return e.name, err
	}
	if len(p.BaseName) > 24 || !OSUserPattern.MatchString(p.BaseName) {
		return "", fmt.Errorf("person base name %q isn't a valid account name", p.BaseName)
	}
	name := p.BaseName
	for _, candidate := range []string{p.BaseName, p.BaseName + "-" + suffix(p.ID)} {
		_, taken, err := m.lookup(func(e entry) bool { return e.name == candidate })
		if err != nil {
			return "", err
		}
		if !taken {
			name = candidate
			break
		}
		if candidate != p.BaseName {
			return "", fmt.Errorf("account names %q and %q are both taken", p.BaseName, candidate)
		}
	}
	// Recorded first: an account created but not recorded would never be expired at start.
	created[name] = marker
	if err := m.State.Write(CreatedFile, created); err != nil {
		delete(created, name)
		return "", fmt.Errorf("recording the account: %w", err)
	}
	if err := m.exec(ctx, "useradd", "--create-home", "--shell", defaultShell(), "--comment", marker, name); err != nil {
		return "", err
	}
	return name, m.exec(ctx, "chage", "-E", "0", name)
}

func (m *Manager) loadCreated() (map[string]string, error) {
	if m.created != nil {
		return m.created, nil
	}
	if m.State == nil {
		return nil, errors.New("accounts: no state directory")
	}
	created := map[string]string{}
	if err := m.State.Read(CreatedFile, &created); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", CreatedFile, err)
	}
	m.created = created
	return created, nil
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

func suffix(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])[:4]
}

// defaultShell is the shell new accounts get.
func defaultShell() string {
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

type entry struct{ name, gecos string }

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
			out = append(out, entry{name: fields[0], gecos: fields[4]})
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
