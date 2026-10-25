//go:build dev

// Package devkeys holds the development instruction root. DEV ONLY: its private key is
// published here on purpose, so anyone can sign key lists with it. Only builds with the
// `dev` tag trust it (protocol/roots_dev.go); release builds never do.
package devkeys

import (
	"crypto/ed25519"
	"encoding/base64"
)

const RootKid = "dev-root"

var (
	RootPrivateKey = ed25519.NewKeyFromSeed(mustDecode("nXHG8Cr5ifQeEhho4SscPdg3JZA3qxeFAm9uhl0vegU"))
	RootPublicKey  = RootPrivateKey.Public().(ed25519.PublicKey)
)

func mustDecode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
