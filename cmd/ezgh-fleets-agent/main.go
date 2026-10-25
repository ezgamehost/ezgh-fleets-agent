// Command ezgh-fleets-agent is the EZGH Fleets agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/accounts"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/config"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/conn"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/creds"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/register"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/run"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/session"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

// StatusFile holds the connection's last status, for `status`.
const statusFile = "status.json"

// version is set at build time.
var version = "dev"

const usage = `usage: ezgh-fleets-agent <command> [--config FILE]

commands:
  run       register this machine (once) and stay connected to EZGH Fleets
  status    show this machine's node
  version   print the version
`

var errUsage = errors.New("unknown command; see --help")

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cli(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ezgh-fleets-agent:", err)
		os.Exit(1)
	}
}

func cli(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, "ezgh-fleets-agent", version)
		return nil
	case "status":
		return status(*configPath, stdout)
	case "run":
		return agent(*configPath)
	}
	return errUsage
}

func load(path string) (*config.Config, *state.Dir, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	st, err := state.Open(cfg.StateDir)
	return cfg, st, err
}

func status(path string, stdout io.Writer) error {
	_, st, err := load(path)
	if err != nil {
		return err
	}
	var id register.Identity
	if err := st.Read(register.NodeFile, &id); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if id.Node == nil {
		fmt.Fprintln(stdout, "node: not registered yet")
		return nil
	}
	fmt.Fprintf(stdout, "node: %s (%s)\norganization: %s\nproject: %s\n", id.Node.Slug, id.Node.ID, id.Node.OrganizationID, id.Node.ProjectID)
	var cs conn.Status
	if err := st.Read(statusFile, &cs); err != nil {
		fmt.Fprintln(stdout, "gateway: no connection yet")
		return nil
	}
	link := "disconnected"
	if cs.Connected {
		link = "connected"
	}
	fmt.Fprintf(stdout, "gateway: %s since %s\n", link, cs.Since.Format("2006-01-02T15:04:05Z07:00"))
	if cs.LastError != "" && !cs.Connected {
		fmt.Fprintln(stdout, "last error:", cs.LastError)
	}
	if cs.Warning != "" {
		fmt.Fprintln(stdout, "warning:", cs.Warning)
	}
	return nil
}

func agent(path string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, st, err := load(path)
	if err != nil {
		return err
	}
	unlock, err := st.Lock()
	if err != nil {
		return fmt.Errorf("%s: %w", cfg.StateDir, err)
	}
	defer unlock()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Before anything else, registration included: a crash mid-session left accounts usable.
	accts := &accounts.Manager{State: st, Log: log}
	if err := accts.ExpirePersons(ctx); err != nil {
		log.Error("couldn't expire per-person accounts at start", "err", err)
	}
	src := creds.New(cfg)
	r := &register.Registrar{Config: cfg, State: st, Creds: src, Facts: register.LocalFacts(version), Log: log}
	invDir, err := state.Open(filepath.Join(cfg.StateDir, "invocations"))
	if err != nil {
		return err
	}
	var cur atomic.Pointer[conn.Conn]
	send := func(v any) error {
		c := cur.Load()
		if c == nil {
			return conn.ErrNotConnected
		}
		return c.Send(ctx, v)
	}
	runner := &run.Runner{Dir: invDir, Acquire: accts.Acquire, Log: log, Report: send}
	if err := runner.Recover(); err != nil {
		return err
	}
	for resets := 0; ; resets++ {
		err := serve(ctx, cfg, st, r, src, accts, runner, &cur, send, log)
		if !errors.Is(err, conn.ErrAwaitingRegistration) || ctx.Err() != nil {
			return err
		}
		if resets > 0 { // reset again straight after registering: back off, up to a minute
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(conn.Backoff(resets-1, rand.Float64())):
			}
		}
		log.Warn("this node was reset in EZGH: registering again with a new binding key")
		if err := r.Reset(); err != nil {
			return err
		}
	}
}

// serve registers (once) and stays connected as the node, until ctx ends or the node is reset.
func serve(ctx context.Context, cfg *config.Config, st *state.Dir, r *register.Registrar, src creds.Source,
	accts *accounts.Manager, runner *run.Runner, cur *atomic.Pointer[conn.Conn], send func(any) error, log *slog.Logger) error {
	id, err := r.Ensure(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	log.Info("node ready", "node", id.Node.Slug, "version", version)
	chk, err := instr.New(id.Node.ID, st, log)
	if err != nil {
		return err
	}
	spawn := func(in protocol.Instruction) (*exec.Cmd, func(), error) {
		name, release, err := accts.Acquire(ctx, in)
		if err != nil {
			return nil, nil, err
		}
		cmd, err := session.AccountShell(name)
		if err != nil {
			release()
			return nil, nil, err
		}
		return cmd, release, nil
	}
	sessions := &session.Manager{
		GatewayURL: cfg.GatewayURL, NodeID: id.Node.ID, NodeSlug: id.Node.Slug, PrivateKey: id.PrivateKey(),
		Version: version, Creds: src, Spawn: spawn, Log: log,
		Report: send,
	}
	defer sessions.Shutdown()
	c := &conn.Conn{
		GatewayURL: cfg.GatewayURL, NodeID: id.Node.ID, NodeSlug: id.Node.Slug, PrivateKey: id.PrivateKey(),
		Version: version, Creds: src, Checker: chk, Handler: &dispatch{log: log, sessions: sessions, runner: runner}, Log: log,
		OnConnected: func() { runner.Resend(); sessions.Reconnected() },
		OnStatus: func(s conn.Status) {
			if err := st.Write(statusFile, s); err != nil {
				log.Warn("couldn't write the status file", "err", err)
			}
		},
	}
	cur.Store(c)
	defer cur.Store(nil)
	return c.Run(ctx)
}

// dispatch routes verified instructions.
type dispatch struct {
	log      *slog.Logger
	sessions *session.Manager
	runner   *run.Runner
}

func (d *dispatch) Instruction(_ context.Context, in protocol.Instruction) {
	switch in.Type {
	case protocol.TypeOpenSession:
		d.sessions.Open(in)
	case protocol.TypeResumeSession:
		d.sessions.Resume(in)
	case protocol.TypeRunInvocation:
		d.runner.Run(in)
	}
}
func (d *dispatch) Cancel(runID string)             { d.runner.Cancel(runID) }
func (d *dispatch) SessionClosed(id, reason string) { d.sessions.Close(id, reason) }
