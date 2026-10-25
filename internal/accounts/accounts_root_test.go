//go:build linux

package accounts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

// These change real accounts: they run as root in CI's Linux job only.
func rootManager(t *testing.T, cleanup ...string) *Manager {
	t.Helper()
	if os.Getenv("EZGH_AGENT_ROOT_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set EZGH_AGENT_ROOT_TESTS=1 and run as root")
	}
	t.Cleanup(func() {
		for _, name := range cleanup {
			_ = exec.Command("pkill", "-KILL", "-u", name).Run()
			_ = exec.Command("userdel", "--remove", name).Run()
		}
		_ = os.Remove("/etc/sudoers.d/" + EzghUser)
	})
	return &Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return string(out)
}

func TestEzghUserCreated(t *testing.T) {
	m := rootManager(t, EzghUser)
	u := EzghUser
	if _, err := m.Acquire(context.Background(), protocol.Instruction{OSUser: &u}); err != nil {
		t.Fatal(err)
	}
	acct, err := user.Lookup(EzghUser)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(acct.HomeDir); err != nil || !fi.IsDir() {
		t.Fatalf("no home: %v", err)
	}
	if status := strings.Fields(sh(t, "passwd", "-S", EzghUser)); len(status) < 2 || (status[1] != "L" && status[1] != "NP" && status[1] != "LK") {
		t.Fatalf("ezgh-user has a usable password: %v", status)
	}
	if _, err := os.Stat("/etc/sudoers.d/" + EzghUser); !os.IsNotExist(err) {
		t.Fatal("ezgh-user has sudo by default")
	}
}

func TestEzghUserSudo(t *testing.T) {
	m := rootManager(t, EzghUser)
	u := EzghUser
	if _, err := m.Acquire(context.Background(), protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u, EzghUserSudo: true}); err != nil {
		t.Fatal(err)
	}
	sh(t, "visudo", "-cf", "/etc/sudoers.d/"+EzghUser)
	if _, err := m.Acquire(context.Background(), protocol.Instruction{Type: protocol.TypeOpenSession, OSUser: &u}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/etc/sudoers.d/" + EzghUser); !os.IsNotExist(err) {
		t.Fatal("sudoers file kept after ezghUserSudo turned off")
	}
}

func TestNamedAccountMissing(t *testing.T) {
	m := &Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d := "ezghtdeploy-missing"
	if _, err := m.Acquire(context.Background(), protocol.Instruction{OSUser: &d}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want osUser_not_found", err)
	}
}
