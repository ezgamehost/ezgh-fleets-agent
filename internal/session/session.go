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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/creack/pty"
	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-systems-agent/internal/conn"
	"github.com/ezgamehost/ezgh-systems-agent/internal/creds"
	"github.com/ezgamehost/ezgh-systems-agent/protocol"
)

const (
	ClientGoneAfter = 60 * time.Second // the PTY is kept this long without a data connection
	AckEvery        = time.Second
	AckBytes        = 64 << 10
	redialMax       = 10 * time.Second
	readChunk       = 32 << 10
	inputQueue      = 256 // frames received but not yet written to the PTY
	gapExitCode     = 255
)

// End reasons reported in SessionEnded.
const (
	ReasonExited         = "exited"
	ReasonClientGone     = "client_gone"
	ReasonOSUserNotFound = "osUser_not_found"
	ReasonResumeGap      = "resume_gap"
)

// ErrOSUserNotFound means the session's account doesn't exist on this machine.
var ErrOSUserNotFound = errors.New("osUser_not_found")

// Spawn builds the shell command for a session (not started).
type Spawn func(in protocol.Instruction) (*exec.Cmd, error)

type Manager struct {
	GatewayURL string
	NodeID     string
	NodeSlug   string
	PrivateKey ed25519.PrivateKey
	Version    string
	Creds      creds.Source
	Spawn      Spawn
	Report     func(v any) // sends on the control connection
	Clock      clockwork.Clock
	HTTP       *http.Client
	Log        *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session
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

// Resume dials a fresh data connection for the session a resumeSession instruction names.
func (m *Manager) Resume(in protocol.Instruction) {
	m.mu.Lock()
	s := m.sessions[in.ID]
	m.mu.Unlock()
	if s != nil {
		s.redialNow()
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
	written  uint64 // output bytes put in out
	acked    uint64 // output bytes the peer has
	inRecv   uint64 // input bytes received
	inDone   uint64 // input bytes written to the PTY
	inAcked  uint64 // input offset last acked to the peer
	exited   bool
	drained  bool // the PTY has no more output
	exitCode int
	ended    bool
}

func (s *session) redialNow() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// dialLoop keeps a data connection while the session lives: at once after a drop or a
// resumeSession, then backing off until the session ends.
func (s *session) dialLoop() {
	wait := time.Duration(0)
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
		ws, err := s.dial()
		if err != nil {
			s.m.Log.Warn("session data connection failed", "session", s.in.ID, "err", err)
			wait = min(max(2*wait, time.Second), redialMax)
			continue
		}
		wait = 0
		s.serve(ws)
		if s.ctx.Err() != nil {
			return
		}
		// Dropped: try again at once, then wait for a kick or the backoff.
		select {
		case <-s.kick:
		default:
		}
	}
}

func (s *session) dial() (*websocket.Conn, error) {
	key, err := s.m.Creds.Key(s.ctx)
	if err != nil {
		return nil, err
	}
	u := strings.TrimRight(s.m.GatewayURL, "/") + "/agent/v1/sessions/" + s.in.ID
	ws, resp, err := conn.Dial(s.ctx, s.m.HTTP, u, key, s.m.NodeSlug, s.m.Version, s.m.Clock.Now(), s.m.PrivateKey,
		func(nonce string) []byte { return protocol.DataMessage(s.m.NodeID, s.in.ID, nonce) })
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		s.m.Creds.Invalidate(key)
	}
	return ws, err
}

// serve runs one data connection until it drops.
func (s *session) serve(ws *websocket.Conn) {
	defer ws.CloseNow()
	s.mu.Lock()
	recv := s.inRecv
	s.mu.Unlock()
	if s.write(ws, protocol.Resume{T: protocol.TypeResume, Offset: recv}) != nil {
		return
	}
	var r protocol.Resume
	if err := wsjson.Read(s.ctx, ws, &r); err != nil || r.T != protocol.TypeResume {
		return
	}
	if !s.attach(ws, r.Offset) {
		return
	}
	for {
		typ, b, err := ws.Read(s.ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageBinary {
			if !s.receive(b) {
				return
			}
			continue
		}
		s.control(b)
	}
	s.mu.Lock()
	if s.ws == ws {
		s.ws = nil
		if !s.ended {
			s.gone.Reset(ClientGoneAfter)
		}
	}
	s.mu.Unlock()
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
			_ = ws.Close(websocket.StatusNormalClosure, ReasonOSUserNotFound)
			s.end(ReasonOSUserNotFound, true)
			return false
		}
	}
	for len(pending) > 0 {
		n := min(len(pending), readChunk)
		if ws.Write(s.ctx, websocket.MessageBinary, protocol.EncodeData(from, pending[:n])) != nil {
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
	s.m.mu.Unlock()
	s.m.Log.Info("session ended", "session", s.in.ID, "reason", reason)
	if report && s.m.Report != nil {
		s.m.Report(protocol.SessionEnded{T: protocol.TypeSessionEnded, SessionID: s.in.ID, Reason: reason})
	}
}

// write sends a control message in order with the data frames.
func (s *session) write(ws *websocket.Conn, v any) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return wsjson.Write(s.ctx, ws, v)
}
