// Package run runs command invocations, at most once: each invocation's ID is written to the
// state directory before it starts, and an invocation found started but unreported after a
// restart is reported failed (agent_restarted), never run again. Output is drained and
// discarded.
package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

const (
	KillAfter = 10 * time.Second // SIGTERM, then SIGKILL this much later

	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusTimedOut  = "timed_out"
	StatusCancelled = "cancelled"

	ReasonAgentRestarted = "agent_restarted"
	ReasonOSUserNotFound = "osUser_not_found"
	ReasonScriptHash     = "script_hash_mismatch"
	ReasonStartFailed    = "start_failed"
)

var paramName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

type Runner struct {
	Dir *state.Dir // one file per invocation
	// Acquire readies the account; accounts.Manager.Acquire.
	Acquire func(ctx context.Context, in protocol.Instruction) (string, func(), error)
	Report  func(v any) error // sends on the control connection
	Clock   clockwork.Clock
	Log     *slog.Logger

	mu      sync.Mutex
	running map[string]*proc
	wg      sync.WaitGroup
}

// Wait waits for running invocations and pending reports.
func (r *Runner) Wait() { r.wg.Wait() }

// record is the invocation's state file.
type record struct {
	ID          string                     `json:"id"`
	StartedAt   *time.Time                 `json:"startedAt,omitempty"`
	Result      *protocol.InvocationResult `json:"result,omitempty"`
	Reported    bool                       `json:"reported"`
	ForgetAfter time.Time                  `json:"forgetAfter"`
}

type proc struct {
	cmd    *exec.Cmd
	reason string // set when stopped: timed_out or cancelled
	timers []clockwork.Timer
}

func file(id string) string { return "inv-" + id + ".json" }

// Recover runs at start, before any instruction: invocations started but never finished are
// reported failed (agent_restarted), unreported results are resent, old records forgotten.
func (r *Runner) Recover() error {
	r.init()
	ents, err := os.ReadDir(r.Dir.Path)
	if err != nil {
		return err
	}
	now := r.Clock.Now()
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "inv-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		var rec record
		if err := r.Dir.Read(name, &rec); err != nil {
			r.Log.Error("unreadable invocation record", "file", name, "err", err)
			continue
		}
		switch {
		case rec.Result == nil:
			end := now
			rec.Result = &protocol.InvocationResult{T: protocol.TypeInvocationResult, RunID: rec.ID, Status: StatusFailed, Reason: ReasonAgentRestarted, StartedAt: rec.StartedAt, EndedAt: &end}
			r.Log.Warn("invocation interrupted by an agent restart; not run again", "run", rec.ID)
			r.save(&rec)
		case rec.Reported && now.After(rec.ForgetAfter):
			_ = r.Dir.Remove(name)
		}
	}
	r.Resend()
	return nil
}

// Resend sends every result not yet reported. Run after each (re)connect.
func (r *Runner) Resend() {
	ents, err := os.ReadDir(r.Dir.Path)
	if err != nil {
		return
	}
	for _, e := range ents {
		var rec record
		if !strings.HasPrefix(e.Name(), "inv-") || r.Dir.Read(e.Name(), &rec) != nil || rec.Result == nil || rec.Reported {
			continue
		}
		r.report(&rec)
	}
}

// Run starts the invocation once. A second delivery of the same ID (a reconnect, or the
// worker re-signing it) reports what the agent knows instead.
func (r *Runner) Run(in protocol.Instruction) {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	var rec record
	switch err := r.Dir.Read(file(in.ID), &rec); {
	case err == nil:
		if rec.Result != nil {
			rec.Reported = false
			r.wg.Go(func() { r.report(&rec) })
		} else if rec.StartedAt != nil {
			_ = r.Report(protocol.InvocationStarted{T: protocol.TypeInvocationStarted, RunID: in.ID, StartedAt: *rec.StartedAt})
		}
		return
	case !errors.Is(err, os.ErrNotExist):
		r.Log.Error("unreadable invocation record; not running it", "run", in.ID, "err", err)
		return
	}
	now := r.Clock.Now()
	rec = record{ID: in.ID, StartedAt: &now, ForgetAfter: in.ExpiresAt.Add(instr.Skew)}
	// Written before anything starts: the at-most-once guarantee.
	if err := r.Dir.Write(file(in.ID), &rec); err != nil {
		r.Log.Error("couldn't record the invocation; not running it", "run", in.ID, "err", err)
		return
	}
	p := &proc{}
	r.running[in.ID] = p
	r.wg.Go(func() { r.execute(in, &rec, p) })
}

// Cancel stops a running invocation: SIGTERM, then SIGKILL after 10 s.
func (r *Runner) Cancel(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.running[runID]; p != nil {
		r.stopLocked(p, StatusCancelled)
	}
}

func (r *Runner) stopLocked(p *proc, reason string) {
	if p.reason != "" || p.cmd == nil || p.cmd.Process == nil {
		if p.reason == "" {
			p.reason = reason // not started yet: it won't be
		}
		return
	}
	p.reason = reason
	pid := p.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	p.timers = append(p.timers, r.Clock.AfterFunc(KillAfter, func() { _ = syscall.Kill(-pid, syscall.SIGKILL) }))
}

func (r *Runner) execute(in protocol.Instruction, rec *record, p *proc) {
	res := r.start(in, rec, p)
	r.mu.Lock()
	delete(r.running, in.ID)
	for _, t := range p.timers {
		t.Stop()
	}
	r.mu.Unlock()
	end := r.Clock.Now()
	res.T, res.RunID, res.StartedAt, res.EndedAt = protocol.TypeInvocationResult, in.ID, rec.StartedAt, &end
	rec.Result = res
	r.save(rec)
	r.report(rec)
}

// start runs the invocation to its end and says how it ended.
func (r *Runner) start(in protocol.Instruction, rec *record, p *proc) *protocol.InvocationResult {
	failed := func(reason string) *protocol.InvocationResult {
		return &protocol.InvocationResult{Status: StatusFailed, Reason: reason}
	}
	if in.OSUser == nil {
		return failed(ReasonOSUserNotFound)
	}
	var path string
	var args []string
	env := []string{}
	switch {
	case in.Command != nil:
		path, args = "/bin/sh", []string{"-c", *in.Command}
	case in.Script != nil:
		sum := sha256.Sum256([]byte(in.Script.Body))
		if hex.EncodeToString(sum[:]) != strings.ToLower(in.Script.SHA256) {
			return failed(ReasonScriptHash)
		}
		switch in.Script.Shell {
		case "sh", "bash":
			path, args = "/bin/"+in.Script.Shell, []string{"-c", in.Script.Body}
		default:
			return failed(ReasonStartFailed)
		}
		for k, v := range in.Parameters {
			if !paramName.MatchString(k) {
				return failed(ReasonStartFailed)
			}
			env = append(env, "EZGH_PARAM_"+strings.ToUpper(k)+"="+v)
		}
	default:
		return failed(ReasonStartFailed)
	}

	ctx := context.Background()
	name, release, err := r.Acquire(ctx, in)
	if err != nil {
		r.Log.Warn("invocation account not ready", "run", in.ID, "err", err)
		if errors.Is(err, accounts.ErrNotFound) {
			return failed(ReasonOSUserNotFound)
		}
		return failed(ReasonStartFailed)
	}
	defer release()
	cmd, err := accounts.Command(name, path, args...)
	if err != nil {
		return failed(ReasonOSUserNotFound)
	}
	cmd.Env = append(cmd.Env, env...)
	cmd.SysProcAttr.Setpgid = true
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard // drained, never kept
	cmd.WaitDelay = time.Minute                     // a leftover child holding the pipes doesn't hang the result

	r.mu.Lock()
	if p.reason != "" { // cancelled before it started
		r.mu.Unlock()
		return &protocol.InvocationResult{Status: p.reason}
	}
	err = cmd.Start()
	p.cmd = cmd
	if err == nil && in.TimeoutSeconds > 0 {
		p.timers = append(p.timers, r.Clock.AfterFunc(time.Duration(in.TimeoutSeconds)*time.Second, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.stopLocked(p, StatusTimedOut)
		}))
	}
	r.mu.Unlock()
	if err != nil {
		r.Log.Warn("invocation didn't start", "run", in.ID, "err", err)
		return failed(ReasonStartFailed)
	}
	if err := r.Report(protocol.InvocationStarted{T: protocol.TypeInvocationStarted, RunID: in.ID, StartedAt: *rec.StartedAt}); err != nil {
		r.Log.Warn("couldn't report the invocation started", "run", in.ID, "err", err)
	}

	err = cmd.Wait()
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
	r.mu.Lock()
	stopped := p.reason
	r.mu.Unlock()
	res := &protocol.InvocationResult{Status: StatusSucceeded, ExitCode: &code}
	switch {
	case stopped != "":
		res.Status = stopped
	case code != 0:
		res.Status = StatusFailed
	}
	return res
}

func (r *Runner) report(rec *record) {
	if err := r.Report(*rec.Result); err != nil {
		r.Log.Warn("couldn't report the invocation result; resent on reconnect", "run", rec.ID, "err", err)
		return
	}
	rec.Reported = true
	r.save(rec)
}

func (r *Runner) save(rec *record) {
	if err := r.Dir.Write(file(rec.ID), rec); err != nil {
		r.Log.Error("couldn't write the invocation record", "run", rec.ID, "err", err)
	}
}

func (r *Runner) init() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Clock == nil {
		r.Clock = clockwork.NewRealClock()
	}
	if r.running == nil {
		r.running = map[string]*proc{}
	}
}
