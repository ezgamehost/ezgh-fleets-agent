// Package session runs shell sessions on PTYs and carries them over data connections to the
// gateway, framed by byte offset so either side can resume after a dropped connection.
package session

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/creack/pty"
	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/conn"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/creds"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const (
	ClientGoneAfter = 60 * time.Second // the PTY is kept this long without a data connection
	AckEvery        = time.Second
	AckBytes        = 64 << 10
	redialMax       = 10 * time.Second
	readChunk       = 32 << 10
	inputQueue      = 256 // frames received but not yet written to the PTY
	gapExitCode     = 255
	resumeWait      = 30 * time.Second // for the peer's resume on a new data connection
)

// End reasons reported in SessionEnded.
const (
	ReasonExited         = "exited"
	ReasonClientGone     = "client_gone"
	ReasonOSUserNotFound = "osUser_not_found"
	ReasonResumeGap      = "resume_gap"
)

// ReasonStartFailed: the account or shell couldn't be readied for another reason.
const ReasonStartFailed = "start_failed"

// Spawn readies the session's account and builds its shell command (not started).
type Spawn func(in protocol.Instruction) (*exec.Cmd, error)

type Manager struct {
	GatewayURL string
	NodeID     string
	NodeSlug   string
	PrivateKey ed25519.PrivateKey
	Version    string
	Creds      creds.Source
	Spawn      Spawn
	Report     func(v any) error // sends on the control connection
	Clock      clockwork.Clock
	HTTP       *http.Client
	Log        *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session
	ended    map[string]time.Time    // ended session IDs → until their openSession expires
	unsent   []protocol.SessionEnded // couldn't be reported: resent by Reconnected
	wg       sync.WaitGroup
}

// Open starts the session an openSession instruction names. A session already open is left alone.
func (m *Manager) Open(in protocol.Instruction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Clock == nil {
		m.Clock = clockwork.NewRealClock()
	}
	if m.sessions == nil {
		m.sessions = map[string]*session{}
	}
	if _, ok := m.sessions[in.ID]; ok {
		return
	}
	now := m.Clock.Now()
	for id, until := range m.ended {
		if now.After(until) {
			delete(m.ended, id)
		}
	}
	if _, ok := m.ended[in.ID]; ok {
		m.Log.Warn("openSession for a session that already ended; not reopening it", "session", in.ID)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{m: m, in: in, ctx: ctx, cancel: cancel, kick: make(chan struct{}, 1), input: make(chan []byte, inputQueue)}
	s.cond = sync.NewCond(&s.mu)
	m.sessions[in.ID] = s
	s.gone = m.Clock.AfterFunc(ClientGoneAfter, func() { s.end(ReasonClientGone, true) })
	m.wg.Go(s.dialLoop)
	m.wg.Go(s.writeInput)
	m.wg.Go(s.ackLoop)
}

// Shutdown ends every session, unreported, and waits for their goroutines.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	var all []*session
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	for _, s := range all {
		s.end("agent_stopped", false)
	}
	m.wg.Wait()
}

// Reconnected runs when the control connection is back: unreported sessionEnded messages are
// sent, and sessions without a data connection redial now rather than after their backoff,
// as they may still be inside their resume window.
func (m *Manager) Reconnected() {
	m.mu.Lock()
	unsent := m.unsent
	m.unsent = nil
	var waiting []*session
	for _, s := range m.sessions {
		waiting = append(waiting, s)
	}
	m.mu.Unlock()
	for i, e := range unsent {
		if err := m.Report(e); err != nil {
			m.mu.Lock()
			m.unsent = append(unsent[i:], m.unsent...)
			m.mu.Unlock()
			break
		}
	}
	for _, s := range waiting {
		s.mu.Lock()
		attached := s.ws != nil
		s.mu.Unlock()
		if !attached {
			select {
			case s.kick <- struct{}{}:
			default:
			}
		}
	}
}

// Resume dials a fresh data connection for the session a resumeSession instruction names.
func (m *Manager) Resume(in protocol.Instruction) {
	m.mu.Lock()
	s := m.sessions[in.ID]
	m.mu.Unlock()
	if s != nil {
		s.resume()
	}
}

// Close ends a session the gateway closed.
func (m *Manager) Close(id, reason string) {
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	if s != nil {
		m.Log.Info("session closed by the gateway", "session", id, "reason", reason)
		s.end(reason, false)
	}
}

type session struct {
	m      *Manager
	in     protocol.Instruction
	ctx    context.Context
	cancel context.CancelFunc
	kick   chan struct{}
	input  chan []byte
	gone   clockwork.Timer

	wmu sync.Mutex // serializes writes on the data connection, in offset order

	mu       sync.Mutex
	cond     *sync.Cond
	ws       *websocket.Conn
	pty      *os.File
	cmd      *exec.Cmd
	out      protocol.Outbox
	written  uint64          // output bytes put in out
	acked    uint64          // output bytes the peer has
	inRecv   uint64          // input bytes received
	inDone   uint64          // input bytes written to the PTY
	inAcked  uint64          // input offset last acked to the peer
	live     *websocket.Conn // the dial loop's connection, attached or not
	exited   bool
	drained  bool // the PTY has no more output
	exitCode int
	ended    bool
}

// resume replaces the data connection (PD8): the current one, attached or still in its
// handshake, is closed, even if it looks alive, and a new one is dialed at once.
func (s *session) resume() {
	s.mu.Lock()
	live := s.live
	s.mu.Unlock()
	if live != nil {
		live.CloseNow()
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// dialLoop keeps a data connection while the session lives: at once after a drop or a
// resumeSession, backing off after a refused dial or a connection that never attached.
func (s *session) dialLoop() {
	wait := time.Duration(0)
	backoff := func(retryAfter time.Duration) {
		wait = max(min(max(2*wait, time.Second), redialMax), retryAfter)
	}
	for {
		if wait > 0 {
			select {
			case <-s.ctx.Done():
				return
			case <-s.kick:
			case <-s.m.Clock.After(wait):
			}
		}
		if s.ctx.Err() != nil {
			return
		}
		ws, retryAfter, err := s.dial()
		if err != nil {
			s.m.Log.Warn("session data connection failed", "session", s.in.ID, "err", err)
			backoff(retryAfter)
			continue
		}
		s.mu.Lock()
		s.live = ws
		s.mu.Unlock()
		attached := s.serve(ws)
		s.mu.Lock()
		if s.live == ws {
			s.live = nil
		}
		s.mu.Unlock()
		if s.ctx.Err() != nil {
			return
		}
		if !attached {
			s.m.Log.Warn("session data connection ended before it attached", "session", s.in.ID)
			backoff(0)
			continue
		}
		// Dropped after working: try again at once, then wait for a kick or the backoff.
		wait = 0
		select {
		case <-s.kick:
		default:
		}
	}
}

func (s *session) dial() (*websocket.Conn, time.Duration, error) {
	key, err := s.m.Creds.Key(s.ctx)
	if err != nil {
		return nil, 0, err
	}
	u := strings.TrimRight(s.m.GatewayURL, "/") + "/agent/v1/sessions/" + s.in.ID
	ws, resp, err := conn.Dial(s.ctx, s.m.HTTP, u, key, s.m.NodeSlug, s.m.Version, s.m.Clock.Now(), s.m.PrivateKey,
		func(nonce string) []byte { return protocol.DataMessage(s.m.NodeID, s.in.ID, nonce) })
	var retryAfter time.Duration
	if resp != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			s.m.Creds.Invalidate(key)
		}
		if n, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && n > 0 {
			retryAfter = time.Duration(n) * time.Second
		}
	}
	return ws, retryAfter, err
}

// serve runs one data connection until it drops. It says whether the connection attached.
func (s *session) serve(ws *websocket.Conn) bool {
	defer ws.CloseNow()
	s.mu.Lock()
	recv := s.inRecv
	s.mu.Unlock()
	if s.write(ws, protocol.Resume{T: protocol.TypeResume, Offset: recv}) != nil {
		return false
	}
	r, err := s.awaitResume(ws)
	if err != nil {
		return false
	}
	if !s.attach(ws, r.Offset) {
		return true // ended, not a dial to retry
	}
	for {
		typ, b, err := ws.Read(s.ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageBinary {
			if !s.receive(b) {
				return true
			}
			continue
		}
		s.control(b)
	}
	s.detach(ws)
	return true
}

// detach drops ws, if it's still the session's connection, and starts the client-gone timer.
func (s *session) detach(ws *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ws == ws {
		s.ws = nil
		if !s.ended {
			s.gone.Reset(ClientGoneAfter)
		}
	}
}

// awaitResume reads until the peer's resume, within resumeWait. Input and acks before it
// (forwarded by the gateway from a client that never lost its side) are dropped: the client
// resends unacknowledged input after the resume exchange.
func (s *session) awaitResume(ws *websocket.Conn) (protocol.Resume, error) {
	ctx, cancel := context.WithTimeout(s.ctx, resumeWait)
	defer cancel()
	for {
		typ, b, err := ws.Read(ctx)
		if err != nil {
			return protocol.Resume{}, err
		}
		var r protocol.Resume
		if typ == websocket.MessageText && json.Unmarshal(b, &r) == nil && r.T == protocol.TypeResume {
			return r, nil
		}
	}
}

// attach makes ws the session's connection and resends output from the peer's offset.
func (s *session) attach(ws *websocket.Conn, from uint64) bool {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return false
	}
	pending, err := s.out.From(from)
	if err != nil {
		s.mu.Unlock()
		s.m.Log.Warn("session can't resume: the peer's offset was dropped", "session", s.in.ID, "offset", from)
		_ = wsjson.Write(s.ctx, ws, protocol.Exit{T: protocol.TypeExit, Code: gapExitCode})
		s.end(ReasonResumeGap, true)
		return false
	}
	s.ackLocked(from)
	old := s.ws
	s.ws = ws
	s.gone.Stop()
	start := s.pty == nil
	s.mu.Unlock()
	if old != nil {
		old.CloseNow()
	}
	if start {
		if err := s.start(); err != nil {
			s.m.Log.Warn("session not started", "session", s.in.ID, "err", err)
			reason := ReasonStartFailed
			if errors.Is(err, accounts.ErrNotFound) {
				reason = ReasonOSUserNotFound
			}
			_ = ws.Close(websocket.StatusNormalClosure, reason)
			s.end(reason, true)
			return false
		}
	}
	for len(pending) > 0 {
		n := min(len(pending), readChunk)
		if ws.Write(s.ctx, websocket.MessageBinary, protocol.EncodeData(from, pending[:n])) != nil {
			s.detach(ws)
			return false
		}
		from += uint64(n)
		pending = pending[n:]
	}
	s.finishLocked(ws)
	return true
}

func (s *session) start() error {
	cmd, err := s.m.Spawn(s.in)
	if err != nil {
		return err
	}
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.ended { // ended while the shell started: end() saw no process to kill
		s.mu.Unlock()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = f.Close()
		_ = cmd.Wait()
		return errors.New("session ended while starting")
	}
	s.pty, s.cmd = f, cmd
	s.mu.Unlock()
	s.m.wg.Go(s.pump)
	s.m.wg.Go(s.wait)
	return nil
}

// pump moves PTY output to the outbox and the connection. It stops reading while the
// peer hasn't acknowledged ResumeBuffer bytes, so nothing is ever dropped from the outbox.
func (s *session) pump() {
	buf := make([]byte, readChunk)
	for {
		s.mu.Lock()
		for s.written-s.acked >= protocol.ResumeBuffer && !s.ended {
			s.cond.Wait()
		}
		ended := s.ended
		s.mu.Unlock()
		if ended {
			return
		}
		n, err := s.pty.Read(buf[:min(readChunk, protocol.ResumeBuffer-int(s.unacked()))])
		if n > 0 {
			s.wmu.Lock()
			s.mu.Lock()
			off := s.out.Write(buf[:n])
			s.written += uint64(n)
			ws := s.ws
			s.mu.Unlock()
			if ws != nil && ws.Write(s.ctx, websocket.MessageBinary, protocol.EncodeData(off, buf[:n])) != nil {
				ws.CloseNow()
			}
			s.wmu.Unlock()
		}
		if err != nil {
			s.wmu.Lock()
			s.mu.Lock()
			s.drained = true
			s.cond.Broadcast()
			ws := s.ws
			s.mu.Unlock()
			s.finishLocked(ws)
			s.wmu.Unlock()
			return
		}
	}
}

func (s *session) unacked() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written - s.acked
}

// wait records the shell's exit status.
func (s *session) wait() {
	err := s.cmd.Wait()
	code := 0
	if err != nil {
		code = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			} else {
				code = ee.ExitCode()
			}
		}
	}
	s.wmu.Lock()
	s.mu.Lock()
	s.exited, s.exitCode = true, code
	ws := s.ws
	s.mu.Unlock()
	s.finishLocked(ws)
	s.wmu.Unlock()
}

// finishLocked sends exit once the shell has exited and all its output is out. Holds wmu.
func (s *session) finishLocked(ws *websocket.Conn) {
	s.mu.Lock()
	done := s.exited && s.drained && !s.ended && ws != nil && s.ws == ws
	code := s.exitCode
	s.mu.Unlock()
	if !done {
		return
	}
	if wsjson.Write(s.ctx, ws, protocol.Exit{T: protocol.TypeExit, Code: code}) == nil {
		// A clean close waits for the peer's answer: don't hold up the report for it.
		s.mu.Lock()
		s.ws = nil
		s.mu.Unlock()
		s.m.wg.Go(func() { _ = ws.Close(websocket.StatusNormalClosure, ReasonExited) })
	}
	s.end(ReasonExited, true)
}

// receive takes one input frame, dropping what was already received. false ends the session.
func (s *session) receive(b []byte) bool {
	off, p, err := protocol.DecodeData(b)
	if err != nil {
		return true
	}
	s.mu.Lock()
	if off > s.inRecv {
		s.mu.Unlock()
		s.m.Log.Warn("session input has a gap", "session", s.in.ID, "offset", off, "have", s.inRecv)
		s.wmu.Lock()
		if ws := s.current(); ws != nil {
			_ = wsjson.Write(s.ctx, ws, protocol.Exit{T: protocol.TypeExit, Code: gapExitCode})
		}
		s.wmu.Unlock()
		s.end(ReasonResumeGap, true)
		return false
	}
	if off+uint64(len(p)) <= s.inRecv {
		s.mu.Unlock()
		return true
	}
	p = append([]byte(nil), p[s.inRecv-off:]...)
	s.inRecv += uint64(len(p))
	s.mu.Unlock()
	select {
	case s.input <- p:
	case <-s.ctx.Done():
		return false
	}
	return true
}

// writeInput writes received input to the PTY, acknowledging every AckBytes.
func (s *session) writeInput() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case p := <-s.input:
			s.mu.Lock()
			f := s.pty
			s.mu.Unlock()
			if f == nil {
				continue
			}
			if _, err := f.Write(p); err != nil {
				continue
			}
			s.mu.Lock()
			s.inDone += uint64(len(p))
			due := s.inDone-s.inAcked >= AckBytes
			s.mu.Unlock()
			if due {
				s.sendAck()
			}
		}
	}
}

func (s *session) ackLoop() {
	t := s.m.Clock.NewTicker(AckEvery)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.Chan():
			s.sendAck()
		}
	}
}

func (s *session) sendAck() {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	ws, off := s.ws, s.inDone
	due := off > s.inAcked
	s.mu.Unlock()
	if ws == nil || !due {
		return
	}
	if wsjson.Write(s.ctx, ws, protocol.Ack{T: protocol.TypeAck, Offset: off}) == nil {
		s.mu.Lock()
		s.inAcked = max(s.inAcked, off)
		s.mu.Unlock()
	}
}

func (s *session) control(b []byte) {
	var m struct {
		T      string `json:"t"`
		Offset uint64 `json:"offset"`
		Cols   int    `json:"cols"`
		Rows   int    `json:"rows"`
	}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	switch m.T {
	case protocol.TypeAck:
		s.mu.Lock()
		s.ackLocked(m.Offset)
		s.mu.Unlock()
	case protocol.TypeResize:
		if m.Cols < 1 || m.Rows < 1 || m.Cols > 1000 || m.Rows > 1000 {
			return
		}
		s.mu.Lock()
		f := s.pty
		s.mu.Unlock()
		if f != nil {
			_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(m.Rows), Cols: uint16(m.Cols)})
		}
	}
}

// ackLocked frees output the peer has. Holds mu.
func (s *session) ackLocked(off uint64) {
	if off > s.acked && off <= s.written {
		s.acked = off
		s.out.Ack(off)
		s.cond.Broadcast()
	}
}

func (s *session) current() *websocket.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ws
}

// end stops the session once: the shell's process group is killed and the PTY closed.
func (s *session) end(reason string, report bool) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	if s.exited && reason == ReasonClientGone {
		reason = ReasonExited
	}
	s.cond.Broadcast()
	cmd, f, ws := s.cmd, s.pty, s.ws
	s.mu.Unlock()
	s.gone.Stop()
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if f != nil {
		_ = f.Close() // hangs up the terminal: its foreground jobs get SIGHUP
	}
	if ws != nil {
		ws.CloseNow()
	}
	s.cancel()
	s.m.mu.Lock()
	delete(s.m.sessions, s.in.ID)
	if s.m.ended == nil {
		s.m.ended = map[string]time.Time{}
	}
	s.m.ended[s.in.ID] = s.in.ExpiresAt.Add(instr.Skew)
	s.m.mu.Unlock()
	s.m.Log.Info("session ended", "session", s.in.ID, "reason", reason)
	if report && s.m.Report != nil {
		e := protocol.SessionEnded{T: protocol.TypeSessionEnded, SessionID: s.in.ID, Reason: reason}
		if err := s.m.Report(e); err != nil {
			s.m.Log.Warn("couldn't report the session ended; resent on reconnect", "session", s.in.ID, "err", err)
			s.m.mu.Lock()
			s.m.unsent = append(s.m.unsent, e)
			s.m.mu.Unlock()
		}
	}
}

// write sends a control message in order with the data frames.
func (s *session) write(ws *websocket.Conn, v any) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return wsjson.Write(s.ctx, ws, v)
}
