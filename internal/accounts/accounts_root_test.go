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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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

func expired(t *testing.T, name string) bool {
	t.Helper()
	for _, line := range strings.Split(sh(t, "chage", "-l", name), "\n") {
		if strings.HasPrefix(line, "Account expires") {
			return !strings.HasSuffix(strings.TrimSpace(line), "never")
		}
	}
	t.Fatalf("no expiry in chage -l %s", name)
	return false
}

func gecos(t *testing.T, name string) string {
	t.Helper()
	return strings.Split(strings.TrimSpace(sh(t, "getent", "passwd", name)), ":")[4]
}

func TestEzghUserCreated(t *testing.T) {
	m := rootManager(t, EzghUser)
	u := EzghUser
	if _, _, err := m.Acquire(context.Background(), protocol.Instruction{OSUser: &u}); err != nil {
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
	if _, _, err := m.Acquire(context.Background(), protocol.Instruction{OSUser: &u, EzghUserSudo: true}); err != nil {
		t.Fatal(err)
	}
	sh(t, "visudo", "-cf", "/etc/sudoers.d/"+EzghUser)
	if _, _, err := m.Acquire(context.Background(), protocol.Instruction{OSUser: &u}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/etc/sudoers.d/" + EzghUser); !os.IsNotExist(err) {
		t.Fatal("sudoers file kept after ezghUserSudo turned off")
	}
}

func TestPersonAccount(t *testing.T) {
	collided := "ezghtbob-" + suffix("u-bob")
	m := rootManager(t, "ezghtalice", "ezghtbob", collided)
	ctx := context.Background()
	name, release, err := m.Acquire(ctx, person("u-alice", "ezghtalice"))
	if err != nil || name != "ezghtalice" {
		t.Fatalf("%q, %v", name, err)
	}
	if gecos(t, name) != "ezgh/user/u-alice" || expired(t, name) {
		t.Fatalf("gecos %q, expired %v", gecos(t, name), expired(t, name))
	}
	release()
	if !expired(t, name) {
		t.Fatal("not expired after its session")
	}

	sh(t, "useradd", "--create-home", "ezghtbob")
	if name, release, err := m.Acquire(ctx, person("u-bob", "ezghtbob")); err != nil || name != collided {
		t.Fatalf("collision: %q, %v", name, err)
	} else {
		release()
	}
}

func TestPersonFoundByMarker(t *testing.T) {
	m := rootManager(t, "ezghtcarol")
	ctx := context.Background()
	_, release, err := m.Acquire(ctx, person("u-carol", "ezghtcarol"))
	if err != nil {
		t.Fatal(err)
	}
	release()
	name, release, err := m.Acquire(ctx, person("u-carol", "ezghtcarol2"))
	if err != nil || name != "ezghtcarol" {
		t.Fatalf("after a rename: %q, %v", name, err)
	}
	release()
}

func TestPersonAccountExpiredAfterLastSession(t *testing.T) {
	m := rootManager(t, "ezghtdave")
	ctx := context.Background()
	name, r1, err := m.Acquire(ctx, person("u-dave", "ezghtdave"))
	if err != nil {
		t.Fatal(err)
	}
	_, r2, err := m.Acquire(ctx, person("u-dave", "ezghtdave"))
	if err != nil {
		t.Fatal(err)
	}
	acct, _ := user.Lookup(name)
	uid, _ := strconv.Atoi(acct.Uid)
	gid, _ := strconv.Atoi(acct.Gid)
	proc := exec.Command("sleep", "1000")
	proc.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, Setsid: true}
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan struct{})
	go func() { _ = proc.Wait(); close(waited) }()
	sh(t, "loginctl", "enable-linger", name)

	r1()
	if expired(t, name) {
		t.Fatal("expired while a session is still open")
	}
	select {
	case <-waited:
		t.Fatal("processes ended while a session is still open")
	default:
	}

	r2()
	if !expired(t, name) {
		t.Fatal("not expired after the last session")
	}
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("the account's process survived its last session")
	}
	if _, err := os.Stat("/var/lib/systemd/linger/" + name); !os.IsNotExist(err) {
		t.Fatal("lingering still on")
	}
	if err := exec.Command("pgrep", "-u", name).Run(); err == nil {
		t.Fatal("processes left running as the account")
	}
	// logind drops the user once its manager stops.
	deadline := time.Now().Add(15 * time.Second)
	for exec.Command("loginctl", "show-user", name).Run() == nil {
		if time.Now().After(deadline) {
			t.Fatal("loginctl still has the user")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestStartupExpiresPersonAccounts(t *testing.T) {
	m := rootManager(t, "ezghterin")
	ctx := context.Background()
	name, _, err := m.Acquire(ctx, person("u-erin", "ezghterin"))
	if err != nil {
		t.Fatal(err)
	}
	// The agent crashed with the session open: the next agent expires the account at start.
	next := &Manager{Log: m.Log}
	if err := next.ExpirePersons(ctx); err != nil {
		t.Fatal(err)
	}
	if !expired(t, name) {
		t.Fatal("not expired at start")
	}
}

func TestNamedAccountMissing(t *testing.T) {
	m := &Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d := "ezghtdeploy-missing"
	if _, _, err := m.Acquire(context.Background(), protocol.Instruction{OSUser: &d}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want osUser_not_found", err)
	}
}
