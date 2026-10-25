package session

import (
	"errors"
	"os/user"
	"testing"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
)

func TestAccountShell(t *testing.T) {
	if _, err := AccountShell("ezgh-no-such-user"); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("missing account: %v", err)
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	cmd, err := AccountShell(me.Username)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Dir != me.HomeDir || cmd.Args[0][0] != '-' || cmd.SysProcAttr != nil {
		t.Fatalf("cmd %+v", cmd)
	}
}
