//go:build dev

package protocol

import "github.com/ezgamehost/ezgh-systems-agent/protocol/devkeys"

// Development builds also trust the dev root, whose private key is public. Never ship them.
func init() {
	Roots[devkeys.RootKid] = devkeys.RootPublicKey
}
