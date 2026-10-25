package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
)

// Roots are the public keys that may sign instruction key lists, by kid. The private halves
// are kept offline; rotating an instruction key needs a new signed key list, not a release.
var Roots = map[string]ed25519.PublicKey{
	"root-2026-10": mustKey("qncrA3pXYqEKw3pjFnuM6LZ3n-lidII_CuhjOdA7ang"),
}

func mustKey(s string) ed25519.PublicKey {
	k, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		panic("protocol: bad root key " + s)
	}
	return k
}
