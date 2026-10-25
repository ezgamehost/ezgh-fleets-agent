//go:build linux

package session

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
)

// The shell's terminal belongs to its account and the tty group, mode 0620, as with sshd.
// Root only, in CI's Linux job.
func TestTTYOwnedByAccountRoot(t *testing.T) {
	if os.Getenv("EZGH_AGENT_ROOT_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set EZGH_AGENT_ROOT_TESTS=1 and run as root")
	}
	const name = "ezghttty"
	if out, err := exec.Command("useradd", "--create-home", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("userdel", "--remove", name).Run() })
	u, _ := user.Lookup(name)
	tty, err := user.LookupGroup("tty")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := accounts.Command(name, "/bin/sh", "-c", `stat -c '%u %g %a' "$(tty)"`)
	if err != nil {
		t.Fatal(err)
	}
	f, err := startPTY(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	_ = cmd.Wait()
	if got, want := strings.TrimSpace(line), u.Uid+" "+tty.Gid+" 620"; got != want {
		t.Fatalf("tty owner, group, mode = %q, want %q", got, want)
	}
}
