package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", fi.Mode().Perm())
	}
	var v map[string]int
	if err := d.Read("x.json", &v); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if err := d.Write("x.json", map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(p, "x.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", fi.Mode().Perm())
	}
	if err := d.Read("x.json", &v); err != nil || v["a"] != 1 {
		t.Fatalf("read back %v, %v", v, err)
	}
	if ents, _ := os.ReadDir(p); len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

func TestLockExclusive(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Lock(); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	again, err := d.Lock()
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
}
