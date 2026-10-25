// Package creds supplies the agent's bot key: from the instance metadata service, a root-only
// key file, or an OIDC token exchange.
package creds

import (
	"context"
	"encoding/json"

	"github.com/ezgamehost/ezgh-systems-agent/internal/config"
)

// Source hands out the current bot key.
type Source interface {
	Key(ctx context.Context) (string, error)
	// Invalidate drops refused if it's the key held, so the next Key gets a new one.
	Invalidate(refused string)
}

// New picks the source the config names. auto is the metadata service on an EZGH compute
// instance, else the key file.
func New(c *config.Config) Source {
	switch c.Credentials.Source {
	case config.SourceOIDC:
		return &OIDC{OrgsURL: c.OrgsURL, Organization: c.Organization, Bot: c.Credentials.OIDC.Bot, TokenFile: c.Credentials.OIDC.TokenFile}
	case config.SourceFile:
		return &File{Path: c.Credentials.File}
	}
	m := &Metadata{Endpoint: c.MetadataURL}
	if c.Credentials.Source == config.SourceAuto && !m.Available() {
		return &File{Path: c.Credentials.File}
	}
	return m
}

// errorCode is the platform error code in a JSON error body, or "".
func errorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}
