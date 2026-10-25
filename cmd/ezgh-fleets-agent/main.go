// Command ezgh-fleets-agent is the EZGH Fleets agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/config"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/conn"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/creds"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/register"
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
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ezgh-fleets-agent:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	src := creds.New(cfg)
	r := &register.Registrar{Config: cfg, State: st, Creds: src, Facts: register.LocalFacts(version), Log: log}
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
	var c *conn.Conn
	sessions := &session.Manager{
		GatewayURL: cfg.GatewayURL, NodeID: id.Node.ID, NodeSlug: id.Node.Slug, PrivateKey: id.PrivateKey(),
		Version: version, Creds: src, Spawn: session.NamedAccountShell, Log: log,
		Report: func(v any) {
			if err := c.Send(ctx, v); err != nil {
				log.Warn("couldn't report to the gateway", "err", err)
			}
		},
	}
	defer sessions.Shutdown()
	c = &conn.Conn{
		GatewayURL: cfg.GatewayURL, NodeID: id.Node.ID, NodeSlug: id.Node.Slug, PrivateKey: id.PrivateKey(),
		Version: version, Creds: src, Checker: chk, Handler: &dispatch{log: log, sessions: sessions}, Log: log,
		OnStatus: func(s conn.Status) {
			if err := st.Write(statusFile, s); err != nil {
				log.Warn("couldn't write the status file", "err", err)
			}
		},
	}
	return c.Run(ctx)
}

// dispatch routes verified instructions.
type dispatch struct {
	log      *slog.Logger
	sessions *session.Manager
}

func (d *dispatch) Instruction(_ context.Context, in protocol.Instruction) {
	switch in.Type {
	case protocol.TypeOpenSession:
		d.sessions.Open(in)
	case protocol.TypeResumeSession:
		d.sessions.Resume(in)
	default:
		d.log.Warn("instruction not supported by this agent yet", "type", in.Type, "id", in.ID)
	}
}
func (d *dispatch) Cancel(string)                   {}
func (d *dispatch) SessionClosed(id, reason string) { d.sessions.Close(id, reason) }
