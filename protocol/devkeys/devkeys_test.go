//go:build dev

package devkeys

import (
	"encoding/base64"
	"testing"
)

func TestDevRootPublicKey(t *testing.T) {
	if got := base64.RawURLEncoding.EncodeToString(RootPublicKey); got != "_w6Pwybt7ab3Ek8fdmrCSjqsNudc4YteUdjFx22qPcQ" {
		t.Fatalf("dev root public key changed: %s", got)
	}
}
