package session

import (
	"os/exec"
	"path/filepath"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
)

// AccountShell builds a login shell as the named, existing account.
func AccountShell(name string) (*exec.Cmd, error) {
	shell := accounts.LoginShell(name)
	cmd, err := accounts.Command(name, shell)
	if err != nil {
		return nil, err
	}
	cmd.Args[0] = "-" + filepath.Base(shell)
	cmd.Env = append(cmd.Env, "TERM=xterm-256color")
	return cmd, nil
}
