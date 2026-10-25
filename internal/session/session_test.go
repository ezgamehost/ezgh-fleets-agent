package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const (
	nodeID    = "0b6c3d1e-0000-4000-8000-000000000002"
	sessionID = "5d2e8f10-0000-4000-8000-000000000004"
)

type key struct{}

func (key) Key(context.Context) (string, error) { return "ezgh_key", nil }
func (key) Invalidate(string)                   {}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

type fixture struct {
	t        *testing.T
	m        *Manager
	clock    *clockwork.FakeClock
	conns    chan *websocket.Conn
	mu       sync.Mutex
	refuse   bool
	ended    chan protocol.SessionEnded
	nodePub  ed25519.PublicKey
	released atomic.Int32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, clock: clockwork.NewFakeClock(), conns: make(chan *websocket.Conn, 4), ended: make(chan protocol.SessionEnded, 4), nodePub: pub}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		refuse := f.refuse
		f.mu.Unlock()
		if refuse || r.URL.Path != "/agent/v1/sessions/"+sessionID || r.Header.Get("Authorization") != "Bearer ezgh_key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.AgentSubprotocol}})
		if err != nil {
			return
		}
		ws.SetReadLimit(protocol.MaxFrame)
		nonce := base64.RawURLEncoding.EncodeToString([]byte("nonce-nonce-nonce-nonce-nonce-32"))
		ctx := context.Background()
		_ = wsjson.Write(ctx, ws, protocol.Challenge{T: protocol.TypeChallenge, Nonce: nonce})
		var h protocol.Hello
		if err := wsjson.Read(ctx, ws, &h); err != nil {
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(h.Signature)
		if !ed25519.Verify(f.nodePub, protocol.DataMessage(nodeID, sessionID, nonce), sig) {
			t.Error("data connection not signed over the data context")
			ws.CloseNow()
			return
		}
		f.conns <- ws
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	f.m = &Manager{
		GatewayURL: "ws" + strings.TrimPrefix(srv.URL, "http"), NodeID: nodeID, NodeSlug: "nod_abc", PrivateKey: priv,
		Creds: key{}, Clock: f.clock, Log: slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Spawn: func(protocol.Instruction) (*exec.Cmd, func(), error) {
			cmd := exec.Command("/bin/sh")
			cmd.Env = []string{"PS1=$ ", "TERM=dumb", "PATH=/usr/bin:/bin"}
			return cmd, func() { f.released.Add(1) }, nil
		},
		Report: func(v any) { f.ended <- v.(protocol.SessionEnded) },
	}
	t.Cleanup(f.m.Shutdown)
	return f
}

func (f *fixture) open() {
	root := "root"
	f.m.Open(protocol.Instruction{Type: protocol.TypeOpenSession, NodeID: nodeID, ID: sessionID, OSUser: &root})
}

func (f *fixture) setRefuse(v bool) { f.mu.Lock(); f.refuse = v; f.mu.Unlock() }

// client plays the console: it keeps what it received by offset and its own input outbox.
type client struct {
	t      *testing.T
	ws     *websocket.Conn
	recv   uint64
	output bytes.Buffer
	in     protocol.Outbox
	exit   *int
}

func (f *fixture) accept(c *client) {
	f.t.Helper()
	select {
	case ws := <-f.conns:
		c.t, c.ws = f.t, ws
	case <-time.After(10 * time.Second):
		f.t.Fatal("the agent didn't open a data connection")
	}
	// Both sides send resume first; the client then resends input from the agent's offset.
	var r protocol.Resume
	if err := wsjson.Read(context.Background(), c.ws, &r); err != nil || r.T != protocol.TypeResume {
		f.t.Fatalf("first message: %+v, %v", r, err)
	}
	if err := wsjson.Write(context.Background(), c.ws, protocol.Resume{T: protocol.TypeResume, Offset: c.recv}); err != nil {
		f.t.Fatal(err)
	}
	if pending, err := c.in.From(r.Offset); err == nil && len(pending) > 0 {
		c.sendFrame(r.Offset, pending)
	}
}

func (c *client) sendFrame(off uint64, p []byte) {
	if err := c.ws.Write(context.Background(), websocket.MessageBinary, protocol.EncodeData(off, p)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) send(s string) {
	off := c.in.Write([]byte(s))
	c.sendFrame(off, []byte(s))
}

// queue writes input while disconnected; it goes out on the next resume.
func (c *client) queue(s string) { c.in.Write([]byte(s)) }

func (c *client) control(v any) {
	if err := wsjson.Write(context.Background(), c.ws, v); err != nil {
		c.t.Fatal(err)
	}
}

// readUntil reads until stop says so, acking every 16 KiB. It returns false when the
// connection ended first.
func (c *client) readUntil(stop func() bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lastAck := c.recv
	for !stop() {
		typ, b, err := c.ws.Read(ctx)
		if err != nil {
			return false
		}
		if typ == websocket.MessageText {
			var m struct {
				T    string `json:"t"`
				Code int    `json:"code"`
			}
			_ = json.Unmarshal(b, &m)
			if m.T == protocol.TypeExit {
				c.exit = &m.Code
			}
			continue
		}
		off, p, _ := protocol.DecodeData(b)
		if off > c.recv {
			c.t.Fatalf("output gap: frame at %d, have %d", off, c.recv)
		}
		if end := off + uint64(len(p)); end > c.recv {
			c.output.Write(p[c.recv-off:])
			c.recv = end
		}
		if c.recv-lastAck >= 16<<10 {
			c.control(protocol.Ack{T: protocol.TypeAck, Offset: c.recv})
			lastAck = c.recv
		}
	}
	return true
}

func (c *client) waitFor(s string) {
	c.t.Helper()
	if !c.readUntil(func() bool { return strings.Contains(c.output.String(), s) }) {
		c.t.Fatalf("connection ended before %q; output %q", s, tail(c.output.String()))
	}
}

func (f *fixture) waitEnded() protocol.SessionEnded {
	f.t.Helper()
	select {
	case e := <-f.ended:
		return e
	case <-time.After(10 * time.Second):
		f.t.Fatal("session never ended")
		return protocol.SessionEnded{}
	}
}

func tail(s string) string { return s[max(0, len(s)-300):] }

func TestSessionShell(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	c.send("echo hi$((1+1)); exit 3\n")
	c.waitFor("hi2")
	c.readUntil(func() bool { return c.exit != nil })
	if c.exit == nil || *c.exit != 3 {
		t.Fatalf("exit %v", c.exit)
	}
	if e := f.waitEnded(); e.Reason != ReasonExited || e.SessionID != sessionID {
		t.Fatalf("ended %+v", e)
	}
	if f.released.Load() != 1 {
		t.Fatalf("account released %d times", f.released.Load())
	}
}

func TestResize(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	c.control(protocol.Resize{T: protocol.TypeResize, Cols: 100, Rows: 40})
	c.send("stty size\n")
	c.waitFor("40 100")
}

func TestResumeNoLossNoDuplicate(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	const n = 20000
	c.send(fmt.Sprintf("i=0; while [ $i -lt %d ]; do echo line$i; i=$((i+1)); done\n", n))
	c.readUntil(func() bool { return c.recv > 30<<10 })

	// The connection drops mid-output; input typed meanwhile waits in the client's outbox.
	c.ws.CloseNow()
	c.queue("echo mark$((40+2))\n")
	f.accept(&c)
	c.waitFor("mark42\r\n")

	out := strings.ReplaceAll(c.output.String(), "\r\n", "\n")
	// Not anchored at the line start: the shell's first prompt can land before line0.
	got := regexp.MustCompile(`(?m)line(\d+)$`).FindAllStringSubmatch(out, -1)
	if len(got) != n {
		t.Fatalf("%d lines, want %d", len(got), n)
	}
	for i, m := range got {
		if m[1] != strconv.Itoa(i) {
			t.Fatalf("line %d is line%s: lost or duplicated output", i, m[1])
		}
	}
	if k := len(regexp.MustCompile(`(?m)mark42$`).FindAllString(out, -1)); k != 1 {
		t.Fatalf("input sent while disconnected ran %d times", k)
	}
}

func TestClientGone(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	c.send("sh -c 'echo pid=$$; exec sleep 1000'\n")
	re := regexp.MustCompile(`pid=(\d+)\r?\n`)
	c.readUntil(func() bool { return re.MatchString(c.output.String()) })
	m := re.FindStringSubmatch(c.output.String())
	pid, _ := strconv.Atoi(m[1])

	f.setRefuse(true)
	c.ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The ack ticker, the client-gone timer, and the redial backoff.
	if err := f.clock.BlockUntilContext(ctx, 3); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(ClientGoneAfter - time.Second)
	select {
	case e := <-f.ended:
		t.Fatalf("ended early: %+v", e)
	default:
	}
	f.clock.Advance(time.Second)
	if e := f.waitEnded(); e.Reason != ReasonClientGone {
		t.Fatalf("ended %+v", e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("process %d still running after the session ended", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("kill -0: %v", err)
	}
}

func TestGapEndsSession(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	c.send("echo $((6*7))\n")
	c.waitFor("42")
	c.control(protocol.Ack{T: protocol.TypeAck, Offset: c.recv}) // the agent frees all it sent
	c.ws.CloseNow()

	// The peer comes back claiming it has nothing: those bytes are gone.
	c.recv = 0
	c.output.Reset()
	f.accept(&c)
	c.readUntil(func() bool { return c.exit != nil })
	if c.exit == nil || *c.exit != 255 {
		t.Fatalf("exit %v, want 255", c.exit)
	}
	if e := f.waitEnded(); e.Reason != ReasonResumeGap {
		t.Fatalf("ended %+v", e)
	}
}

// An ended session stays ended: a fresh openSession for its ID (re-signed, so the replay
// check passes it) doesn't open it again before the instruction expires.
func TestEndedSessionNotReopened(t *testing.T) {
	f := newFixture(t)
	root := "root"
	in := protocol.Instruction{Type: protocol.TypeOpenSession, NodeID: nodeID, ID: sessionID, OSUser: &root,
		IssuedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(time.Minute)}
	f.m.Open(in)
	var c client
	f.accept(&c)
	f.m.Close(sessionID, "closed")
	open := func() bool {
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		return f.m.sessions[sessionID] != nil
	}
	f.m.Open(in)
	if open() {
		t.Fatal("an ended session was opened again")
	}
	f.clock.Advance(time.Minute + instr.Skew + time.Second)
	f.m.Open(in) // only an expired instruction could get here, and it'd be refused before
	if !open() {
		t.Fatal("the ended ID was never forgotten")
	}
}
