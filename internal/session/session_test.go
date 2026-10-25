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
	t           *testing.T
	m           *Manager
	clock       *clockwork.FakeClock
	conns       chan *websocket.Conn
	mu          sync.Mutex
	refuse      bool
	retry       string // Retry-After on a refusal
	controlDown bool   // Report fails, as with the control connection down
	ended       chan protocol.SessionEnded
	nodePub     ed25519.PublicKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, clock: clockwork.NewFakeClock(), conns: make(chan *websocket.Conn, 4), ended: make(chan protocol.SessionEnded, 4), nodePub: pub}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		refuse, retry := f.refuse, f.retry
		f.mu.Unlock()
		if refuse || r.URL.Path != "/agent/v1/sessions/"+sessionID || r.Header.Get("Authorization") != "Bearer ezgh_key" {
			if retry != "" {
				w.Header().Set("Retry-After", retry)
			}
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
		Spawn: func(protocol.Instruction) (*exec.Cmd, error) {
			cmd := exec.Command("/bin/sh")
			cmd.Env = []string{"PS1=$ ", "TERM=dumb", "PATH=/usr/bin:/bin"}
			return cmd, nil
		},
		Report: func(v any) error {
			f.mu.Lock()
			down := f.controlDown
			f.mu.Unlock()
			if down {
				return errors.New("not connected")
			}
			f.ended <- v.(protocol.SessionEnded)
			return nil
		},
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
	// No echo: input typed during the output would otherwise land mid-line in it.
	c.send("stty -echo\n")
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

func (f *fixture) noDial(within time.Duration) {
	f.t.Helper()
	select {
	case <-f.conns:
		f.t.Fatal("redialed without waiting")
	case <-time.After(within):
	}
}

func (f *fixture) waiters(n int) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.clock.BlockUntilContext(ctx, n); err != nil {
		f.t.Fatal(err)
	}
}

// PD8: a resumeSession replaces the data connection, even one that still looks alive (a
// half-open old home), rather than only waking a redial loop that isn't waiting.
func TestResumeReplacesConnection(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c1 client
	f.accept(&c1)
	f.m.Resume(protocol.Instruction{Type: protocol.TypeResumeSession, NodeID: nodeID, ID: sessionID})
	var c2 client
	f.accept(&c2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, _, err := c1.ws.Read(ctx); err != nil {
			if ctx.Err() != nil {
				t.Fatal("the old data connection was kept open")
			}
			break
		}
	}
	c2.send("echo ok$((1+1))\n")
	c2.waitFor("ok2")
}

// A data connection that ends before the resume handshake counts as a failed dial: the agent
// backs off rather than redialing at once.
func TestUnattachedConnectionBacksOff(t *testing.T) {
	f := newFixture(t)
	f.open()
	ws := <-f.conns
	ws.CloseNow() // no resume
	f.noDial(200 * time.Millisecond)
	f.waiters(3) // the ack ticker, the client-gone timer and the backoff
	f.clock.Advance(time.Second)
	var c client
	f.accept(&c)
}

// A refused dial waits at least the gateway's Retry-After.
func TestRefusedDialHonoursRetryAfter(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	f.mu.Lock()
	f.refuse, f.retry = true, "5"
	f.mu.Unlock()
	c.ws.CloseNow() // redialed at once, and refused
	f.waiters(3)
	f.mu.Lock()
	f.refuse, f.retry = false, ""
	f.mu.Unlock()
	f.clock.Advance(5*time.Second - time.Millisecond)
	f.noDial(200 * time.Millisecond)
	f.clock.Advance(time.Millisecond)
	f.accept(&c)
}

// When the control connection comes back, a session waiting out a backoff redials at once:
// it may still be inside its resume window.
func TestReconnectedRedialsAtOnce(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	f.mu.Lock()
	f.refuse, f.retry = true, "30"
	f.mu.Unlock()
	c.ws.CloseNow() // redialed at once, refused: now waiting 30 s
	f.waiters(3)
	f.setRefuse(false)
	f.m.Reconnected()
	f.accept(&c)
}

// A sessionEnded that couldn't be sent is sent when the control connection is back.
func TestSessionEndedQueuedWhileDisconnected(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	f.mu.Lock()
	f.controlDown = true
	f.mu.Unlock()
	c.send("exit 3\n")
	c.readUntil(func() bool { return c.exit != nil })
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.m.mu.Lock()
		n := len(f.m.unsent)
		f.m.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sessionEnded not queued")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	f.controlDown = false
	f.mu.Unlock()
	f.m.Reconnected()
	if e := f.waitEnded(); e.SessionID != sessionID || e.Reason != ReasonExited {
		t.Fatalf("ended %+v", e)
	}
	f.m.Reconnected()
	select {
	case e := <-f.ended:
		t.Fatalf("sent twice: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

// Input and acks the gateway forwards before the client's resume (sent while only the
// agent's side was down) are skipped, not fatal: the client resends input after the resume.
func TestInputBeforeResumeSkipped(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	select {
	case ws := <-f.conns:
		c.t, c.ws = t, ws
	case <-time.After(10 * time.Second):
		t.Fatal("the agent didn't open a data connection")
	}
	var r protocol.Resume
	if err := wsjson.Read(context.Background(), c.ws, &r); err != nil || r.T != protocol.TypeResume {
		t.Fatalf("first message: %+v, %v", r, err)
	}
	c.sendFrame(0, []byte("echo early\n")) // dropped: resent below after the resume
	c.control(protocol.Ack{T: protocol.TypeAck, Offset: 0})
	c.control(protocol.Resume{T: protocol.TypeResume, Offset: 0})
	c.sendFrame(0, []byte("echo ok$((1+1))\n"))
	c.waitFor("ok2")
	if strings.Contains(c.output.String(), "early") {
		t.Fatalf("input sent before the resume ran: %q", c.output.String())
	}
}

// A connection that fails while the buffered output is resent doesn't stay the session's:
// the client-gone timer runs again, so a session nobody comes back to ends.
func TestResendFailureDetaches(t *testing.T) {
	f := newFixture(t)
	f.open()
	var c client
	f.accept(&c)
	c.send("echo buffered\n")
	c.waitFor("buffered") // read, never acked: still in the outbox
	f.setRefuse(true)     // no redial gets in

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err == nil {
			<-r.Context().Done()
			ws.CloseNow()
		}
	}))
	t.Cleanup(srv.Close)
	dead, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	dead.CloseNow() // every write on it fails

	f.m.mu.Lock()
	s := f.m.sessions[sessionID]
	f.m.mu.Unlock()
	if s.attach(dead, 0) {
		t.Fatal("attach over a dead connection succeeded")
	}
	s.mu.Lock()
	attached := s.ws != nil
	s.mu.Unlock()
	if attached {
		t.Fatal("the dead connection stayed attached")
	}
	f.waiters(3)
	f.clock.Advance(ClientGoneAfter)
	if e := f.waitEnded(); e.Reason != ReasonClientGone {
		t.Fatalf("ended %+v", e)
	}
}
