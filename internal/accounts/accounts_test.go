package accounts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

// fakeHost keeps a passwd file and records commands; useradd appends to the file.
type fakeHost struct {
	t      *testing.T
	passwd string
	cmds   []string
}

func newFake(t *testing.T, lines ...string) (*Manager, *fakeHost) {
	dir := t.TempDir()
	h := &fakeHost{t: t, passwd: filepath.Join(dir, "passwd")}
	_ = os.WriteFile(h.passwd, []byte(strings.Join(append([]string{"root:x:0:0:root:/root:/bin/bash"}, lines...), "\n")+"\n"), 0o644)
	st, err := state.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Passwd: h.passwd, SudoersDir: dir, State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Exec: h.exec}
	return m, h
}

func (h *fakeHost) exec(_ context.Context, name string, args ...string) error {
	h.cmds = append(h.cmds, name+" "+strings.Join(args, " "))
	switch name {
	case "useradd":
		comment := args[slices.Index(args, "--comment")+1]
		f, _ := os.OpenFile(h.passwd, os.O_APPEND|os.O_WRONLY, 0)
		defer f.Close()
		_, _ = f.WriteString(args[len(args)-1] + ":x:1500:1500:" + comment + ":/home/x:/bin/sh\n")
	case "visudo":
		b, _ := os.ReadFile(args[1])
		if string(b) != "ezgh-user ALL=(ALL) NOPASSWD:ALL\n" {
			return errors.New("bad sudoers")
		}
	}
	return nil
}

func (h *fakeHost) ran(cmd string) bool { return slices.Contains(h.cmds, cmd) }

func person(id, base string) protocol.Instruction {
	return protocol.Instruction{Person: &protocol.Person{Type: "user", ID: id, BaseName: base}}
}

func TestPersonNames(t *testing.T) {
	m, h := newFake(t, "bob:x:1001:1001::/home/bob:/bin/sh")
	ctx := context.Background()

	name, release, err := m.Acquire(ctx, person("u1", "alice"))
	if err != nil || name != "alice" {
		t.Fatalf("Acquire = %q, %v", name, err)
	}
	if !h.ran("chage -E 0 alice") || !h.ran("chage -E -1 alice") {
		t.Fatalf("not created expired then opened: %v", h.cmds)
	}
	release()

	// Found by its marker even when the base name changed.
	if name, _, _ := m.Acquire(ctx, person("u1", "alice2")); name != "alice" {
		t.Fatalf("renamed person got %q", name)
	}

	// A name held by an unmarked account gets a suffix of the principal's hash.
	name, _, err = m.Acquire(ctx, person("u2", "bob"))
	if err != nil || name != "bob-"+suffix("u2") {
		t.Fatalf("collision: %q, %v", name, err)
	}

	for _, bad := range []protocol.Instruction{person("u/3", "x"), person("u3", "Bad"), person("u3", strings.Repeat("a", 25)), {}} {
		if _, _, err := m.Acquire(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad.Person)
		}
	}
}

func TestPersonReleaseCounts(t *testing.T) {
	m, h := newFake(t)
	ctx := context.Background()
	_, r1, _ := m.Acquire(ctx, person("u1", "alice"))
	_, r2, _ := m.Acquire(ctx, person("u1", "alice"))
	h.cmds = nil
	r1()
	r1() // twice is once
	if len(h.cmds) != 0 {
		t.Fatalf("locked with a session still open: %v", h.cmds)
	}
	r2()
	for _, c := range []string{"chage -E 0 alice", "loginctl terminate-user alice", "pkill -KILL -u alice", "loginctl disable-linger alice"} {
		if !h.ran(c) {
			t.Errorf("%q not run: %v", c, h.cmds)
		}
	}
}

func TestExpirePersonsAtStart(t *testing.T) {
	m, h := newFake(t, "alice:x:1500:1500:ezgh/user/u1:/home/alice:/bin/sh", "deploy:x:1501:1501::/home/deploy:/bin/sh")
	_ = m.State.Write(CreatedFile, map[string]string{"alice": "ezgh/user/u1"})
	if err := m.ExpirePersons(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.ran("chage -E 0 alice") || h.ran("chage -E 0 deploy") || h.ran("chage -E 0 root") {
		t.Fatalf("cmds %v", h.cmds)
	}
}

func TestEzghUserAndNamed(t *testing.T) {
	m, h := newFake(t, "deploy:x:1501:1501::/home/deploy:/bin/sh")
	ctx := context.Background()
	u := EzghUser
	in := protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u, EzghUserSudo: true}
	if name, _, err := m.Acquire(ctx, in); err != nil || name != EzghUser {
		t.Fatalf("ezgh-user: %q, %v", name, err)
	}
	if !strings.HasPrefix(h.cmds[0], "useradd") {
		t.Fatalf("ezgh-user not created: %v", h.cmds)
	}
	sudoers := filepath.Join(m.SudoersDir, EzghUser)
	if fi, err := os.Stat(sudoers); err != nil || fi.Mode().Perm() != 0o440 {
		t.Fatalf("sudoers file: %v %v", fi, err)
	}
	in.EzghUserSudo = false
	if _, _, err := m.Acquire(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sudoers); !os.IsNotExist(err) {
		t.Fatal("sudoers file not removed")
	}
	if n := strings.Count(strings.Join(h.cmds, "\n"), "useradd"); n != 1 {
		t.Fatalf("ezgh-user created %d times", n)
	}

	d := "deploy"
	if name, _, err := m.Acquire(ctx, protocol.Instruction{OSUser: &d}); err != nil || name != "deploy" {
		t.Fatalf("deploy: %q, %v", name, err)
	}
	for _, missing := range []string{"nobody-here", "Root", "a/b"} {
		if _, _, err := m.Acquire(ctx, protocol.Instruction{OSUser: &missing}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v", missing, err)
		}
	}
}

// Only an openSession sets ezgh-user's sudo (PD10): a command run as ezgh-user leaves it be.
func TestInvocationLeavesSudoers(t *testing.T) {
	m, _ := newFake(t)
	ctx := context.Background()
	u := EzghUser
	if _, _, err := m.Acquire(ctx, protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u, EzghUserSudo: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Acquire(ctx, protocol.Instruction{Type: protocol.TypeRunInvocation, OSUser: &u}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.SudoersDir, EzghUser)); err != nil {
		t.Fatalf("a run as ezgh-user removed its sudoers file: %v", err)
	}
}

// Anyone allowed to chfn could put a marker in their GECOS: it counts only on an account the
// agent created.
func TestMarkerTrustedOnlyForCreated(t *testing.T) {
	m, h := newFake(t, "mallory:x:1600:1600:ezgh/user/u1:/home/mallory:/bin/sh")
	ctx := context.Background()
	name, release, err := m.Acquire(ctx, person("u1", "alice"))
	if err != nil || name != "alice" {
		t.Fatalf("got %q, %v; want a new account, not mallory", name, err)
	}
	release()
	h.cmds = nil
	if err := m.ExpirePersons(ctx); err != nil {
		t.Fatal(err)
	}
	if h.ran("chage -E 0 mallory") || !h.ran("chage -E 0 alice") {
		t.Fatalf("cmds %v", h.cmds)
	}
	// A restarted agent still knows alice.
	next := &Manager{Passwd: m.Passwd, SudoersDir: m.SudoersDir, State: m.State, Log: m.Log, Exec: h.exec}
	if name, release, err := next.Acquire(ctx, person("u1", "alice2")); err != nil || name != "alice" {
		t.Fatalf("after a restart: %q, %v", name, err)
	} else {
		release()
	}
}
