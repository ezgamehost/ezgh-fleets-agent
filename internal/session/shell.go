package session

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
)

// AccountShell builds a login shell as the named, existing account.
func AccountShell(name string) (*exec.Cmd, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, accounts.ErrNotFound
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	var groups []uint32
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	shell := loginShell(u.Username)
	cmd := &exec.Cmd{Path: shell, Args: []string{"-" + filepath.Base(shell)}, Dir: u.HomeDir}
	cmd.Env = []string{
		"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "SHELL=" + shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm-256color",
	}
	if uint32(uid) != uint32(os.Getuid()) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}}
	}
	return cmd, nil
}

// loginShell is the account's shell from /etc/passwd, or /bin/sh.
func loginShell(name string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) == 7 && fields[0] == name && filepath.IsAbs(fields[6]) {
			if _, err := os.Stat(fields[6]); err == nil {
				return fields[6]
			}
		}
	}
	return "/bin/sh"
}
