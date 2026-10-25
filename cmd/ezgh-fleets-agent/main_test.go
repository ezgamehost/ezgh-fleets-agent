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
	if err := run([]string{"version"}, &out); err != nil || !strings.HasPrefix(out.String(), "ezgh-fleets-agent ") {
		t.Fatalf("version: %q, %v", out.String(), err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("project: prj_p\nstateDir: "+filepath.Join(dir, "state")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"status", "--config", cfg}, &out); err != nil || !strings.Contains(out.String(), "not registered") {
		t.Fatalf("status: %q, %v", out.String(), err)
	}
	if err := run([]string{"bogus"}, &out); err == nil {
		t.Fatal("an unknown command ran")
	}
}
