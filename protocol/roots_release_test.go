//go:build !dev

package protocol

import "testing"

func TestReleaseTrustsOnlyProductionRoots(t *testing.T) {
	if len(Roots) != 1 {
		t.Fatalf("release build trusts %d roots, want only root-2026-10", len(Roots))
	}
}
