package accounts

import (
	"bufio"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Command builds path with args, run as the named account: its IDs and groups, its home as the
// working directory, and a clean login environment (HOME, USER, LOGNAME, SHELL, PATH).
func Command(name, path string, args ...string) (*exec.Cmd, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, ErrNotFound
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
	cmd := &exec.Cmd{Path: path, Args: append([]string{path}, args...), Dir: u.HomeDir}
	cmd.Env = []string{
		"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "SHELL=" + LoginShell(u.Username),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if uint32(uid) != uint32(os.Getuid()) {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}
	}
	return cmd, nil
}

// LoginShell is the account's shell from /etc/passwd, or /bin/sh.
func LoginShell(name string) string {
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
