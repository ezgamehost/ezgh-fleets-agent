// Command ezgh-systems-agent is the EZGH Systems Manager agent.
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

	"github.com/ezgamehost/ezgh-systems-agent/internal/config"
	"github.com/ezgamehost/ezgh-systems-agent/internal/creds"
	"github.com/ezgamehost/ezgh-systems-agent/internal/register"
	"github.com/ezgamehost/ezgh-systems-agent/internal/state"
)

// version is set at build time.
var version = "dev"

const usage = `usage: ezgh-systems-agent <command> [--config FILE]

commands:
  run       register this machine (once) and stay connected to EZGH Systems Manager
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
		fmt.Fprintln(os.Stderr, "ezgh-systems-agent:", err)
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
		fmt.Fprintln(stdout, "ezgh-systems-agent", version)
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
	<-ctx.Done()
	return nil
}
