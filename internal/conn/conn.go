// Package conn keeps the agent's control connection to the Fleets gateway: it
// authenticates (bot key plus a challenge signed with the node binding), checks the
// instructions it relays, rekeys, and reconnects with jittered backoff.
package conn

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/creds"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const (
	CloseReconnect = 4012

	RekeyEvery    = 10 * time.Minute
	keyCheckEvery = time.Minute // a refreshed key is sent at the next check
	PingEvery     = 30 * time.Second
	PongWait      = 75 * time.Second
	BackoffBase   = time.Second
	BackoffMax    = 60 * time.Second
	MaxSkew       = instr.Skew
	handshakeWait = 30 * time.Second
	// NodeGoneRetry is the wait after the gateway doesn't know the node (404: deregistered).
	// It keeps re-checking, so a node deregistered by mistake comes back.
	NodeGoneRetry = time.Hour
)

var (
	ErrNotConnected = errors.New("not connected to the gateway")
	// ErrAwaitingRegistration ends Run: the node was reset in EZGH and must register again.
	ErrAwaitingRegistration = errors.New("the node was reset: awaiting registration")
)

// Handler receives what arrives on the control connection, instructions already verified.
type Handler interface {
	Instruction(ctx context.Context, in protocol.Instruction)
	Cancel(runID string)
	SessionClosed(sessionID, reason string)
}

// Status is the connection's state, for `ezgh-fleets-agent status`.
type Status struct {
	Connected bool          `json:"connected"`
	Since     time.Time     `json:"since"`
	ClockSkew time.Duration `json:"clockSkew"`
	Warning   string        `json:"warning,omitempty"`
	LastError string        `json:"lastError,omitempty"`
}

type Conn struct {
	GatewayURL string // wss://…
	NodeID     string // UUID, in signed messages
	NodeSlug   string // nod_…, in the EZGH-Node header
	PrivateKey ed25519.PrivateKey
	Version    string
	Creds      creds.Source
	Checker    *instr.Checker
	Handler    Handler
	Clock      clockwork.Clock
	HTTP       *http.Client
	Log        *slog.Logger
	OnStatus   func(Status)
	// OnConnected runs after each welcome, in its own goroutine: the time to resend reports
	// that couldn't be sent while disconnected.
	OnConnected func()
	Rand        func() float64 // [0,1), for jitter

	mu     sync.Mutex
	ws     *websocket.Conn
	status Status
}

// Backoff is the wait before reconnect attempt n (from 0): exponential from 1 s, capped at
// 60 s, jittered to between half and all of it.
func Backoff(n int, r float64) time.Duration {
	d := BackoffMax
	if n < 6 {
		d = min(BackoffBase<<n, BackoffMax)
	}
	return d/2 + time.Duration(r*float64(d/2))
}

// Run stays connected until ctx ends.
func (c *Conn) Run(ctx context.Context) error {
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	attempt := 0
	for {
		welcomed, retryAfter, err := c.connect(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrAwaitingRegistration) {
			c.setStatus(func(s *Status) { s.Connected, s.Since, s.LastError = false, c.Clock.Now(), errString(err) })
			return err
		}
		if welcomed {
			attempt = 0
		}
		c.setStatus(func(s *Status) { s.Connected, s.Since, s.LastError = false, c.Clock.Now(), errString(err) })
		if websocket.CloseStatus(err) == CloseReconnect || errors.Is(err, errReconnect) {
			c.Log.Info("gateway asked to reconnect")
			continue
		}
		wait := max(Backoff(attempt, c.Rand()), retryAfter)
		attempt++
		c.Log.Warn("gateway connection lost", "err", err, "retryIn", wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-c.Clock.After(wait):
		}
	}
}

var errReconnect = errors.New("reconnect")

// Send writes v on the control connection.
func (c *Conn) Send(ctx context.Context, v any) error {
	c.mu.Lock()
	ws := c.ws
	c.mu.Unlock()
	if ws == nil {
		return ErrNotConnected
	}
	return wsjson.Write(ctx, ws, v)
}

func (c *Conn) connect(ctx context.Context) (welcomed bool, retryAfter time.Duration, err error) {
	key, err := c.Creds.Key(ctx)
	if err != nil {
		return false, 0, err
	}
	ws, resp, err := Dial(ctx, c.HTTP, strings.TrimRight(c.GatewayURL, "/")+"/agent/v1/connect", key, c.NodeSlug, c.Version, c.Clock.Now(), c.PrivateKey,
		func(nonce string) []byte { return protocol.ConnectMessage(c.NodeID, nonce) })
	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusUnauthorized {
				c.Creds.Invalidate(key)
			}
			if resp.StatusCode == http.StatusForbidden && RefusalCode(resp) == "awaiting_registration" {
				return false, 0, ErrAwaitingRegistration
			}
			if resp.StatusCode == http.StatusNotFound {
				c.Log.Error("EZGH doesn't know this node: it was deregistered. Uninstall the agent, or delete node.json in its state directory and restart it to register again; re-checking hourly", "node", c.NodeSlug)
				retryAfter = NodeGoneRetry
			}
			if n, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && n > 0 {
				retryAfter = time.Duration(n) * time.Second
			}
		}
		return false, retryAfter, err
	}
	defer ws.CloseNow()

	hctx, cancel := context.WithTimeout(ctx, handshakeWait)
	var w protocol.Welcome
	err = wsjson.Read(hctx, ws, &w)
	cancel()
	if err != nil {
		return false, 0, fmt.Errorf("waiting for welcome: %w", err)
	}
	if w.T != protocol.TypeWelcome {
		return false, 0, fmt.Errorf("expected welcome, got %q", w.T)
	}
	now := c.Clock.Now()
	// First: a clock far off is the likeliest reason for what follows to fail.
	skew := now.Sub(w.ServerTime)
	warning := ""
	if skew > MaxSkew || skew < -MaxSkew {
		warning = fmt.Sprintf("this machine's clock is %s off EZGH's; instructions will be refused until it's fixed (check NTP)", skew.Round(time.Second))
		c.Log.Warn(warning)
	}
	if err := c.Checker.SetKeyList(w.KeyList, now); err != nil {
		c.setStatus(func(s *Status) { s.Warning = warning })
		_ = ws.Close(websocket.StatusPolicyViolation, "bad key list")
		return false, 0, fmt.Errorf("the gateway's key list doesn't verify: %w", err)
	}

	c.mu.Lock()
	c.ws = ws
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.ws = nil
		c.mu.Unlock()
	}()
	c.setStatus(func(s *Status) { *s = Status{Connected: true, Since: now, ClockSkew: skew, Warning: warning} })
	c.Log.Info("connected to the gateway", "node", c.NodeSlug)
	if c.OnConnected != nil {
		go c.OnConnected()
	}

	lctx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait() // the loops' tickers are gone before the caller waits on the clock
	defer stop()
	wg.Go(func() { c.rekeyLoop(lctx, ws, key, now) })
	wg.Go(func() { c.pingLoop(lctx, ws) })
	return true, 0, c.readLoop(ctx, ws)
}

func (c *Conn) readLoop(ctx context.Context, ws *websocket.Conn) error {
	for {
		_, b, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var m struct {
			T string `json:"t"`
		}
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		switch m.T {
		case protocol.TypeInstruction:
			var d protocol.Deliver
			if json.Unmarshal(b, &d) != nil {
				continue
			}
			in, err := c.Checker.Check(d.Instruction, c.Clock.Now())
			if err != nil {
				reason := instr.Reason(err)
				c.Log.Warn("instruction refused", "id", instr.UnverifiedID(d.Instruction), "reason", reason)
				_ = wsjson.Write(ctx, ws, protocol.Refused{T: protocol.TypeRefused, ID: instr.UnverifiedID(d.Instruction), Reason: reason})
				continue
			}
			c.Handler.Instruction(ctx, in)
		case protocol.TypeCancel:
			var x protocol.Cancel
			if json.Unmarshal(b, &x) == nil {
				c.Handler.Cancel(x.RunID)
			}
		case protocol.TypeSessionClosed:
			var x protocol.SessionClosed
			if json.Unmarshal(b, &x) == nil {
				c.Handler.SessionClosed(x.SessionID, x.Reason)
			}
		case protocol.TypeReconnect:
			_ = ws.Close(websocket.StatusNormalClosure, "reconnecting")
			return errReconnect
		}
	}
}

// rekeyLoop sends the current key every RekeyEvery, and as soon as it changes.
func (c *Conn) rekeyLoop(ctx context.Context, ws *websocket.Conn, sent string, at time.Time) {
	t := c.Clock.NewTicker(keyCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.Chan():
		}
		key, err := c.Creds.Key(ctx)
		if err != nil {
			c.Log.Warn("no key to rekey with", "err", err)
			continue
		}
		now := c.Clock.Now()
		if key == sent && now.Sub(at) < RekeyEvery {
			continue
		}
		if err := wsjson.Write(ctx, ws, protocol.Rekey{T: protocol.TypeRekey, APIKey: key}); err != nil {
			return
		}
		sent, at = key, now
	}
}

func (c *Conn) pingLoop(ctx context.Context, ws *websocket.Conn) {
	t := c.Clock.NewTicker(PingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.Chan():
		}
		pctx, cancel := context.WithTimeout(ctx, PongWait)
		err := ws.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				c.Log.Warn("no pong from the gateway", "err", err)
				ws.CloseNow()
			}
			return
		}
	}
}

func (c *Conn) setStatus(f func(*Status)) {
	c.mu.Lock()
	f(&c.status)
	s := c.status
	c.mu.Unlock()
	if c.OnStatus != nil {
		c.OnStatus(s)
	}
}

// Dial opens an agent WebSocket at u with the bot key and node header, and answers the
// gateway's challenge with a Hello signing msg(nonce). The response is returned when the
// upgrade was refused.
func Dial(ctx context.Context, hc *http.Client, u, key, nodeSlug, version string, now time.Time, priv ed25519.PrivateKey, msg func(nonce string) []byte) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+key)
	h.Set(protocol.HeaderNode, nodeSlug)
	ws, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: h, Subprotocols: []string{protocol.AgentSubprotocol}})
	if err != nil {
		return nil, resp, err
	}
	ws.SetReadLimit(protocol.MaxFrame)
	hctx, cancel := context.WithTimeout(ctx, handshakeWait)
	defer cancel()
	var ch protocol.Challenge
	if err := wsjson.Read(hctx, ws, &ch); err != nil || ch.T != protocol.TypeChallenge || ch.Nonce == "" {
		ws.CloseNow()
		return nil, nil, fmt.Errorf("waiting for the challenge: %v", err)
	}
	sig := ed25519.Sign(priv, msg(ch.Nonce))
	hello := protocol.Hello{T: protocol.TypeHello, Signature: base64.RawURLEncoding.EncodeToString(sig), AgentVersion: version, Time: now}
	if err := wsjson.Write(hctx, ws, hello); err != nil {
		ws.CloseNow()
		return nil, nil, err
	}
	return ws, nil, nil
}

// RefusalCode is the error code in a refused upgrade's JSON body ({"error":{"code":…}}).
func RefusalCode(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
	return e.Error.Code
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
