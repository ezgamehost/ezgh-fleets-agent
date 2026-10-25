package conn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const nodeID = "0b6c3d1e-0000-4000-8000-000000000002"

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type keys struct {
	mu  sync.Mutex
	key string
}

func (k *keys) Key(context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.key, nil
}
func (k *keys) Invalidate(string) {}
func (k *keys) set(v string)      { k.mu.Lock(); k.key = v; k.mu.Unlock() }

type handler struct{ got chan protocol.Instruction }

func (h *handler) Instruction(_ context.Context, in protocol.Instruction) { h.got <- in }
func (h *handler) Cancel(string)                                          {}
func (h *handler) SessionClosed(string, string)                           {}

// gwConn is one agent connection as the fake gateway sees it.
type gwConn struct {
	r    *http.Request
	ws   *websocket.Conn
	msgs chan []byte
	done chan struct{}
}

func (g *gwConn) send(t *testing.T, v any) {
	t.Helper()
	if err := wsjson.Write(context.Background(), g.ws, v); err != nil {
		t.Fatal(err)
	}
}

func (g *gwConn) next(t *testing.T, v any) string {
	t.Helper()
	select {
	case b := <-g.msgs:
		if v != nil {
			if err := json.Unmarshal(b, v); err != nil {
				t.Fatal(err)
			}
		}
		var m struct{ T string }
		_ = json.Unmarshal(b, &m)
		return m.T
	case <-time.After(5 * time.Second):
		t.Fatal("no message from the agent")
		return ""
	}
}

type fixture struct {
	t        *testing.T
	clock    *clockwork.FakeClock
	conns    chan *gwConn
	refuse   chan int // an HTTP status to answer the next upgrade with
	root     ed25519.PrivateKey
	instrKey ed25519.PrivateKey
	nodePub  ed25519.PublicKey
	creds    *keys
	h        *handler
	statuses chan Status
	c        *Conn
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	_, instrKey, _ := ed25519.GenerateKey(rand.Reader)
	nodePub, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, clock: clockwork.NewFakeClockAt(t0), conns: make(chan *gwConn, 4), refuse: make(chan int, 4),
		root: root, instrKey: instrKey, nodePub: nodePub, creds: &keys{key: "ezgh_key"},
		h: &handler{got: make(chan protocol.Instruction, 4)}, statuses: make(chan Status, 16)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case code := <-f.refuse:
			w.WriteHeader(code)
			return
		default:
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.AgentSubprotocol}})
		if err != nil {
			return
		}
		g := &gwConn{r: r, ws: ws, msgs: make(chan []byte, 16), done: make(chan struct{})}
		go func() {
			defer close(g.done)
			for {
				_, b, err := ws.Read(context.Background())
				if err != nil {
					return
				}
				g.msgs <- b
			}
		}()
		f.conns <- g
		<-g.done
	}))
	t.Cleanup(srv.Close)
	st, _ := state.Open(filepath.Join(t.TempDir(), "s"))
	chk, err := instr.New(nodeID, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	chk.Roots = map[string]ed25519.PublicKey{"root-test": rootPub}
	f.c = &Conn{
		GatewayURL: "ws" + strings.TrimPrefix(srv.URL, "http"), NodeID: nodeID, NodeSlug: "nod_abc", PrivateKey: nodePriv,
		Version: "0.1.0", Creds: f.creds, Checker: chk, Handler: f.h, Clock: f.clock,
		Log: slog.New(slog.NewTextHandler(testWriter{t}, nil)), Rand: func() float64 { return 0.5 },
		OnStatus: func(s Status) {
			select {
			case f.statuses <- s:
			default:
			}
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return f
}

func (f *fixture) accept() *gwConn {
	f.t.Helper()
	select {
	case g := <-f.conns:
		return g
	case <-time.After(5 * time.Second):
		f.t.Fatal("the agent didn't connect")
		return nil
	}
}

// handshake runs the challenge and welcome, and returns the nonce signed.
func (f *fixture) handshake(g *gwConn, serverTime time.Time) {
	f.t.Helper()
	nonce := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	g.send(f.t, protocol.Challenge{T: protocol.TypeChallenge, Nonce: nonce})
	var hello protocol.Hello
	if typ := g.next(f.t, &hello); typ != protocol.TypeHello {
		f.t.Fatalf("got %q, want hello", typ)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(hello.Signature)
	if !ed25519.Verify(f.nodePub, protocol.ConnectMessage(nodeID, nonce), sig) {
		f.t.Fatal("hello not signed with the node key over the connect context")
	}
	if hello.AgentVersion != "0.1.0" {
		f.t.Fatalf("agentVersion %q", hello.AgentVersion)
	}
	pub := f.instrKey.Public().(ed25519.PublicKey)
	l, _ := protocol.SignKeyList(f.root, "root-test", []protocol.PublicKey{{Kid: "k1", PublicKey: pub, NotAfter: t0.Add(24 * time.Hour)}})
	g.send(f.t, protocol.Welcome{T: protocol.TypeWelcome, KeyList: l, ServerTime: serverTime})
}

func (f *fixture) connected() Status {
	f.t.Helper()
	for {
		select {
		case s := <-f.statuses:
			if s.Connected {
				return s
			}
		case <-time.After(5 * time.Second):
			f.t.Fatal("never connected")
		}
	}
}

func (f *fixture) disconnected() {
	f.t.Helper()
	select {
	case s := <-f.statuses:
		if s.Connected {
			f.t.Fatal("still connected")
		}
	case <-time.After(5 * time.Second):
		f.t.Fatal("never disconnected")
	}
}

func (f *fixture) instruction(node, id string) protocol.SignedInstruction {
	root := "root"
	s, err := protocol.SignInstruction(f.instrKey, "k1", protocol.Instruction{Type: protocol.TypeOpenSession, NodeID: node, ID: id, OSUser: &root, IssuedAt: t0, ExpiresAt: t0.Add(time.Minute)})
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func TestConnectSignsChallenge(t *testing.T) {
	f := newFixture(t)
	g := f.accept()
	if g.r.Header.Get("Authorization") != "Bearer ezgh_key" || g.r.Header.Get("EZGH-Node") != "nod_abc" {
		t.Fatalf("headers %v", g.r.Header)
	}
	if g.ws.Subprotocol() != protocol.AgentSubprotocol {
		t.Fatalf("subprotocol %q", g.ws.Subprotocol())
	}
	f.handshake(g, t0)
	if s := f.connected(); s.Warning != "" {
		t.Fatalf("warning with synced clocks: %q", s.Warning)
	}
	g.send(t, protocol.Deliver{T: protocol.TypeInstruction, Instruction: f.instruction(nodeID, "s1")})
	select {
	case in := <-f.h.got:
		if in.ID != "s1" || *in.OSUser != "root" {
			t.Fatalf("instruction %+v", in)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("instruction not delivered")
	}
}

func TestReplayRefused(t *testing.T) {
	f := newFixture(t)
	g := f.accept()
	f.handshake(g, t0)
	f.connected()
	s := f.instruction(nodeID, "s1")
	g.send(t, protocol.Deliver{T: protocol.TypeInstruction, Instruction: s})
	<-f.h.got
	g.send(t, protocol.Deliver{T: protocol.TypeInstruction, Instruction: s})
	var r protocol.Refused
	if typ := g.next(t, &r); typ != protocol.TypeRefused || r.Reason != "replayed" || r.ID != "s1" {
		t.Fatalf("got %q %+v, want refused replayed", typ, r)
	}
	select {
	case in := <-f.h.got:
		t.Fatalf("a replay was acted on: %+v", in)
	default:
	}
}

func TestWrongNodeRefused(t *testing.T) {
	f := newFixture(t)
	g := f.accept()
	f.handshake(g, t0)
	f.connected()
	g.send(t, protocol.Deliver{T: protocol.TypeInstruction, Instruction: f.instruction("another-node", "s2")})
	var r protocol.Refused
	if typ := g.next(t, &r); typ != protocol.TypeRefused || r.Reason != "wrong_node" || r.ID != "s2" {
		t.Fatalf("got %q %+v", typ, r)
	}
}

func TestClockSkewReported(t *testing.T) {
	f := newFixture(t)
	g := f.accept()
	f.handshake(g, t0.Add(-301*time.Second))
	s := f.connected()
	if !strings.Contains(s.Warning, "clock") || s.ClockSkew != 301*time.Second {
		t.Fatalf("status %+v", s)
	}
}

func TestRekeyBeforeExpiry(t *testing.T) {
	f := newFixture(t)
	g := f.accept()
	f.handshake(g, t0)
	f.connected()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.clock.BlockUntilContext(ctx, 2); err != nil { // the rekey and ping tickers
		t.Fatal(err)
	}
	f.clock.Advance(RekeyEvery)
	var rk protocol.Rekey
	for typ := g.next(t, &rk); typ != protocol.TypeRekey; typ = g.next(t, &rk) {
	}
	if rk.APIKey != "ezgh_key" {
		t.Fatalf("rekey with %q", rk.APIKey)
	}

	// A refreshed key goes out at the next check, not 10 minutes later.
	f.creds.set("ezgh_new")
	f.clock.Advance(keyCheckEvery)
	for typ := g.next(t, &rk); typ != protocol.TypeRekey; typ = g.next(t, &rk) {
	}
	if rk.APIKey != "ezgh_new" {
		t.Fatalf("rekey with %q, want the refreshed key", rk.APIKey)
	}
}

func TestReconnectBackoff(t *testing.T) {
	for n := 0; n < 12; n++ {
		d := min(BackoffBase<<min(n, 10), BackoffMax)
		if lo, hi := Backoff(n, 0), Backoff(n, 0.999); lo != d/2 || hi > d || hi < lo {
			t.Fatalf("attempt %d: [%s, %s], want within [%s, %s]", n, lo, hi, d/2, d)
		}
	}
	if Backoff(100, 0.999) > BackoffMax {
		t.Fatal("backoff not capped")
	}

	f := newFixture(t)
	g := f.accept()
	f.handshake(g, t0)
	f.connected()

	// 4012 reconnects at once: no wait on the clock.
	_ = g.ws.Close(CloseReconnect, "draining")
	g = f.accept()
	f.handshake(g, t0)
	f.connected()

	// Anything else waits, growing: 1 s then 2 s (jitter 0.5 → 0.75 of each).
	f.refuse <- http.StatusServiceUnavailable
	f.refuse <- http.StatusServiceUnavailable
	g.ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, want := range []time.Duration{750 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second} {
		f.disconnected() // the connection's tickers are gone: the one waiter left is the backoff
		if err := f.clock.BlockUntilContext(ctx, 1); err != nil {
			t.Fatal(err)
		}
		f.clock.Advance(want - time.Millisecond)
		select {
		case <-f.conns:
			t.Fatalf("reconnected before %s", want)
		case <-time.After(50 * time.Millisecond):
		}
		f.clock.Advance(time.Millisecond)
		if want == 3*time.Second {
			f.accept()
		}
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// A reset node is refused before the upgrade (403 awaiting_registration): Run stops so the
// agent can register again, rather than retrying a binding that's gone.
func TestAwaitingRegistrationStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"awaiting_registration","message":"This node was reset: the agent must register again"}}`))
	}))
	t.Cleanup(srv.Close)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := &Conn{GatewayURL: "ws" + strings.TrimPrefix(srv.URL, "http"), NodeID: nodeID, NodeSlug: "nod_abc", PrivateKey: priv,
		Creds: &keys{key: "ezgh_key"}, Clock: clockwork.NewFakeClockAt(t0), Log: slog.New(slog.NewTextHandler(testWriter{t}, nil))}
	done := make(chan error, 1)
	go func() { done <- c.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrAwaitingRegistration) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept retrying a reset node")
	}
}

// A deregistered node is a 404: the agent says so and re-checks hourly, not every minute.
func TestNodeGoneRechecksHourly(t *testing.T) {
	f := newFixture(t)
	g := f.accept()
	f.handshake(g, t0)
	f.connected()
	f.refuse <- http.StatusNotFound
	g.ws.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.disconnected() // the drop: then the usual 750 ms
	if err := f.clock.BlockUntilContext(ctx, 1); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(750 * time.Millisecond)
	f.disconnected() // the 404
	if err := f.clock.BlockUntilContext(ctx, 1); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(NodeGoneRetry - time.Millisecond)
	select {
	case <-f.conns:
		t.Fatal("re-checked before an hour")
	case <-time.After(100 * time.Millisecond):
	}
	f.clock.Advance(time.Millisecond)
	f.accept()
}
