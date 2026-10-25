package session

import (
	"errors"
	"os/user"
	"testing"

	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

func TestNamedAccountShell(t *testing.T) {
	if _, err := NamedAccountShell(protocol.Instruction{}); !errors.Is(err, ErrOSUserNotFound) {
		t.Fatalf("no account: %v", err)
	}
	missing := "ezgh-no-such-user"
	if _, err := NamedAccountShell(protocol.Instruction{OSUser: &missing}); !errors.Is(err, ErrOSUserNotFound) {
		t.Fatalf("missing account: %v", err)
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	cmd, err := NamedAccountShell(protocol.Instruction{OSUser: &me.Username})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Dir != me.HomeDir || cmd.Args[0][0] != '-' || cmd.SysProcAttr != nil {
		t.Fatalf("cmd %+v", cmd)
	}
}
