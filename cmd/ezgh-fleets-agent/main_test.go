package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionAndStatus(t *testing.T) {
	var out bytes.Buffer
	if err := cli([]string{"version"}, &out); err != nil || !strings.HasPrefix(out.String(), "ezgh-fleets-agent ") {
		t.Fatalf("version: %q, %v", out.String(), err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("project: 7a1b2c3d-0000-4000-8000-000000000003\nstateDir: "+filepath.Join(dir, "state")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cli([]string{"status", "--config", cfg}, &out); err != nil || !strings.Contains(out.String(), "not registered") {
		t.Fatalf("status: %q, %v", out.String(), err)
	}
	if err := cli([]string{"bogus"}, &out); err == nil {
		t.Fatal("an unknown command ran")
	}
}
