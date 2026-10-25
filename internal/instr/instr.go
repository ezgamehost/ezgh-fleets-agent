// Package instr checks the signed instructions the gateway relays: the key list against the
// built-in roots, each instruction's signature, node and validity window, and replays.
package instr

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

// SeenFile keeps the instructions already accepted, until they expire. KeyListFile keeps
// the newest key list's issuedAt, so an older list served later is refused.
const (
	SeenFile    = "seen.json"
	KeyListFile = "keylist.json"
)

// Skew is the clock difference tolerated on an instruction's validity window.
const Skew = 300 * time.Second

var (
	ErrReplayed        = errors.New("replayed")
	ErrKeyListRollback = errors.New("key list older than one already accepted")
)

// Checker is safe for concurrent use.
type Checker struct {
	NodeID string
	State  *state.Dir
	Roots  map[string]ed25519.PublicKey // protocol.Roots unless set
	Log    *slog.Logger

	mu     sync.Mutex
	keys   []protocol.PublicKey // each trusted until its notAfter
	seen   map[string]time.Time // signed bytes' hash → when it can be forgotten
	newest keyListState
}

type keyListState struct {
	IssuedAt time.Time `json:"issuedAt"`
}

// New loads the seen instructions from the state directory.
func New(nodeID string, st *state.Dir, log *slog.Logger) (*Checker, error) {
	c := &Checker{NodeID: nodeID, State: st, Log: log, seen: map[string]time.Time{}}
	if err := st.Read(SeenFile, &c.seen); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", SeenFile, err)
	}
	if err := st.Read(KeyListFile, &c.newest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", KeyListFile, err)
	}
	return c, nil
}

// SetKeyList replaces the instruction keys with those in l, once it verifies and isn't older
// than the newest list accepted before (a gateway can't serve back a list with a retired key).
func (c *Checker) SetKeyList(l protocol.SignedKeyList, now time.Time) error {
	roots := c.Roots
	if roots == nil {
		roots = protocol.Roots
	}
	keys, err := protocol.VerifyKeyListKeys(roots, l, now)
	if err != nil {
		return err
	}
	at, err := issuedAt(l) // the payload verified above
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if at.Before(c.newest.IssuedAt) {
		return fmt.Errorf("%w: issued %s, have %s", ErrKeyListRollback, at.Format(time.RFC3339), c.newest.IssuedAt.Format(time.RFC3339))
	}
	if at.After(c.newest.IssuedAt) {
		if err := c.State.Write(KeyListFile, keyListState{IssuedAt: at}); err != nil {
			return fmt.Errorf("persisting the key list's issuedAt: %w", err)
		}
		c.newest.IssuedAt = at
	}
	c.keys = keys
	return nil
}

func issuedAt(l protocol.SignedKeyList) (time.Time, error) {
	b, err := base64.RawURLEncoding.DecodeString(l.Payload)
	if err != nil {
		return time.Time{}, err
	}
	var p struct {
		IssuedAt time.Time `json:"issuedAt"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return time.Time{}, err
	}
	return p.IssuedAt, nil
}

// Check verifies s and records it. A replay is ErrReplayed, returned with the instruction.
//
// Replays are keyed by the signed (decoded) bytes, not the ID: every resumeSession for a session carries
// the session's ID. Acting on an ID once (a session opened, a run started) is the caller's job.
func (c *Checker) Check(s protocol.SignedInstruction, now time.Time) (protocol.Instruction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	valid := map[string]ed25519.PublicKey{}
	for _, k := range c.keys {
		if now.Before(k.NotAfter) {
			valid[k.Kid] = k.PublicKey
		}
	}
	in, err := protocol.VerifyInstruction(valid, s, c.NodeID, now, Skew)
	if err != nil {
		return in, err
	}
	signed, err := base64.RawURLEncoding.DecodeString(s.Payload) // canonical: verified above
	if err != nil {
		return in, protocol.ErrBadSignature
	}
	sum := sha256.Sum256(signed)
	h := hex.EncodeToString(sum[:])
	if _, ok := c.seen[h]; ok {
		return in, ErrReplayed
	}
	for k, until := range c.seen {
		if now.After(until) {
			delete(c.seen, k)
		}
	}
	c.seen[h] = in.ExpiresAt.Add(Skew)
	// shortcut: a failed write keeps the record in memory only, so a replay after a restart
	// inside the window would pass; upgrade if disk errors become a real failure mode.
	if err := c.State.Write(SeenFile, c.seen); err != nil && c.Log != nil {
		c.Log.Error("couldn't persist seen instructions", "err", err)
	}
	return in, nil
}

// Reason is the refused reason for a Check error.
func Reason(err error) string {
	for _, e := range []error{protocol.ErrExpired, protocol.ErrWrongNode, ErrReplayed, protocol.ErrUnknownKey} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return protocol.ErrBadSignature.Error()
}

// UnverifiedID reads the instruction ID from s without trusting it, to name it in a report.
func UnverifiedID(s protocol.SignedInstruction) string {
	b, err := base64.RawURLEncoding.DecodeString(s.Payload)
	if err != nil {
		return ""
	}
	var in struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &in)
	return in.ID
}
