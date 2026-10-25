package instr

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
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

func TestKeyListRollbackRefused(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	st, _ := state.Open(filepath.Join(t.TempDir(), "s"))
	keys := []protocol.PublicKey{{Kid: "k", PublicKey: pub, NotAfter: t0.Add(time.Hour)}}
	older, _ := protocol.SignKeyList(rootPriv, "r", keys)
	at, _ := issuedAt(older)
	newer := older
	for { // signed with the wall clock: re-sign until the timestamps differ
		newer, _ = protocol.SignKeyList(rootPriv, "r", keys)
		if n, _ := issuedAt(newer); n.After(at) {
			break
		}
	}
	c, _ := New("node-1", st, nil)
	c.Roots = map[string]ed25519.PublicKey{"r": rootPub}
	if err := c.SetKeyList(newer, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.SetKeyList(older, t0); !errors.Is(err, ErrKeyListRollback) {
		t.Fatalf("an older key list: %v", err)
	}
	if err := c.SetKeyList(newer, t0); err != nil {
		t.Fatalf("the same list again: %v", err)
	}
	// Remembered across restarts.
	c2, _ := New("node-1", st, nil)
	c2.Roots = c.Roots
	if err := c2.SetKeyList(older, t0); !errors.Is(err, ErrKeyListRollback) {
		t.Fatalf("an older key list after a restart: %v", err)
	}
}

func newChecker(t *testing.T, keys ...protocol.PublicKey) *Checker {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	st, _ := state.Open(filepath.Join(t.TempDir(), "s"))
	c, err := New("node-1", st, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Roots = map[string]ed25519.PublicKey{"r": rootPub}
	l, _ := protocol.SignKeyList(rootPriv, "r", keys)
	if err := c.SetKeyList(l, t0); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestReencodedReplayRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := newChecker(t, protocol.PublicKey{Kid: "k", PublicKey: pub, NotAfter: t0.Add(time.Hour)})
	s, _ := protocol.SignInstruction(priv, "k", protocol.Instruction{Type: protocol.TypeOpenSession, NodeID: "node-1", ID: "s1", IssuedAt: t0, ExpiresAt: t0.Add(time.Minute)})
	if _, err := c.Check(s, t0); err != nil {
		t.Fatal(err)
	}
	for _, v := range []protocol.SignedInstruction{
		{V: 1, Kid: "k", Payload: s.Payload[:8] + "\n" + s.Payload[8:], Sig: s.Sig},
		{V: 1, Kid: "k", Payload: s.Payload, Sig: s.Sig[:8] + "\r\n" + s.Sig[8:]},
	} {
		if _, err := c.Check(v, t0); err == nil {
			t.Fatalf("a re-encoded copy was accepted: %+v", v)
		}
	}
}

func TestExpiredKeyRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := newChecker(t, protocol.PublicKey{Kid: "k", PublicKey: pub, NotAfter: t0.Add(time.Hour)})
	at := t0.Add(2 * time.Hour) // the key list was set at t0 and never refreshed
	s, _ := protocol.SignInstruction(priv, "k", protocol.Instruction{Type: protocol.TypeOpenSession, NodeID: "node-1", ID: "s1", IssuedAt: at, ExpiresAt: at.Add(time.Minute)})
	if _, err := c.Check(s, at); !errors.Is(err, protocol.ErrUnknownKey) {
		t.Fatalf("signed by a key past its notAfter: %v", err)
	}
}
