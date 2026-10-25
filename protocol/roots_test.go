package protocol

import (
	"crypto/ed25519"
	"testing"
)

func TestProductionRoot(t *testing.T) {
	k, ok := Roots["root-2026-10"]
	if !ok || len(k) != ed25519.PublicKeySize {
		t.Fatalf("production root missing or malformed: %v", k)
	}
}
