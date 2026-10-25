package instr

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ezgamehost/ezgh-systems-agent/internal/state"
	"github.com/ezgamehost/ezgh-systems-agent/protocol"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func TestCheck(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	st, err := state.Open(filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("node-1", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Roots = map[string]ed25519.PublicKey{"r": rootPub}
	in := protocol.Instruction{Type: protocol.TypeOpenSession, NodeID: "node-1", ID: "s1", IssuedAt: t0, ExpiresAt: t0.Add(time.Minute)}
	s, _ := protocol.SignInstruction(priv, "k", in)

	if _, err := c.Check(s, t0); !errors.Is(err, protocol.ErrUnknownKey) {
		t.Fatalf("before a key list: %v", err)
	}
	l, _ := protocol.SignKeyList(rootPriv, "r", []protocol.PublicKey{{Kid: "k", PublicKey: pub, NotAfter: t0.Add(time.Hour)}})
	if err := c.SetKeyList(l, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(s, t0); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Check(s, t0); !errors.Is(err, ErrReplayed) || got.ID != "s1" || Reason(err) != "replayed" {
		t.Fatalf("replay: %v %+v", err, got)
	}

	// A restarted agent still remembers it.
	c2, err := New("node-1", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2.Roots = c.Roots
	_ = c2.SetKeyList(l, t0)
	if _, err := c2.Check(s, t0.Add(time.Second)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay after restart: %v", err)
	}

	// A resume of the same session, signed afresh, is a new instruction.
	in.Type, in.IssuedAt = protocol.TypeResumeSession, t0.Add(time.Second)
	r, _ := protocol.SignInstruction(priv, "k", in)
	if _, err := c.Check(r, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	other := in
	other.NodeID = "node-2"
	o, _ := protocol.SignInstruction(priv, "k", other)
	if _, err := c.Check(o, t0); Reason(err) != "wrong_node" || UnverifiedID(o) != "s1" {
		t.Fatalf("wrong node: %v", err)
	}
	if Reason(errors.New("x")) != "bad_signature" {
		t.Fatal("default reason")
	}
}
