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
	m := &Manager{Passwd: h.passwd, SudoersDir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Exec: h.exec}
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

func TestEzghUserAndNamed(t *testing.T) {
	m, h := newFake(t, "deploy:x:1501:1501::/home/deploy:/bin/sh")
	ctx := context.Background()
	u := EzghUser
	in := protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u, EzghUserSudo: true}
	if name, err := m.Acquire(ctx, in); err != nil || name != EzghUser {
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
	if _, err := m.Acquire(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sudoers); !os.IsNotExist(err) {
		t.Fatal("sudoers file not removed")
	}
	if n := strings.Count(strings.Join(h.cmds, "\n"), "useradd"); n != 1 {
		t.Fatalf("ezgh-user created %d times", n)
	}

	d := "deploy"
	if name, err := m.Acquire(ctx, protocol.Instruction{OSUser: &d}); err != nil || name != "deploy" {
		t.Fatalf("deploy: %q, %v", name, err)
	}
	for _, missing := range []string{"nobody-here", "Root", "a/b"} {
		if _, err := m.Acquire(ctx, protocol.Instruction{OSUser: &missing}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v", missing, err)
		}
	}
}

// Only an openSession sets ezgh-user's sudo (PD10): a command run as ezgh-user leaves it be.
func TestInvocationLeavesSudoers(t *testing.T) {
	m, _ := newFake(t)
	ctx := context.Background()
	u := EzghUser
	if _, err := m.Acquire(ctx, protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u, EzghUserSudo: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Acquire(ctx, protocol.Instruction{Type: protocol.TypeRunInvocation, OSUser: &u}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.SudoersDir, EzghUser)); err != nil {
		t.Fatalf("a run as ezgh-user removed its sudoers file: %v", err)
	}
}

// Without sudo installed there's no /etc/sudoers.d: ezghUserSudo is skipped, not fatal.
func TestEzghUserSudoWithoutSudoers(t *testing.T) {
	m, _ := newFake(t)
	m.SudoersDir = filepath.Join(t.TempDir(), "missing")
	u := EzghUser
	if _, err := m.Acquire(context.Background(), protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u, EzghUserSudo: true}); err != nil {
		t.Fatalf("no sudoers.d: %v", err)
	}
}
