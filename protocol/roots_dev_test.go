//go:build dev

package protocol

import (
	"testing"
	"time"

	"github.com/ezgamehost/ezgh-systems-agent/protocol/devkeys"
)

func TestDevRootTrusted(t *testing.T) {
	if !Roots[devkeys.RootKid].Equal(devkeys.RootPublicKey) || !devkeys.RootPublicKey.Equal(devkeys.RootPrivateKey.Public()) {
		t.Fatal("dev root not in Roots under the dev tag")
	}
	pub, _ := newKey(t)
	l, err := SignKeyList(devkeys.RootPrivateKey, devkeys.RootKid, []PublicKey{{Kid: "k", PublicKey: pub, NotAfter: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKeyList(Roots, l, t0); err != nil {
		t.Fatal(err)
	}
}
