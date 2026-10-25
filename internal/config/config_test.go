package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadDefaults(t *testing.T) {
	c, err := load(t, "project: 7a1b2c3d-0000-4000-8000-000000000003\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Credentials.Source != SourceAuto || c.Credentials.File != DefaultCredentialsFile || c.StateDir != DefaultStateDir {
		t.Fatalf("defaults: %+v", c)
	}
	if c.APIURL != "https://fleets-api.ezghcloud.com" || c.GatewayURL != "wss://fleets-gateway.ezghcloud.com" {
		t.Fatalf("urls: %+v", c)
	}
}

func TestLoadRefuses(t *testing.T) {
	const p = "project: 7a1b2c3d-0000-4000-8000-000000000003\n"
	for body, want := range map[string]string{
		"organization: org_x\n":                                            "project",
		"project: prj_abc\n":                                               "project must be the project's ID (a UUID), not its prj_ name",
		p + "organization: org_x\n":                                        "organization must be the organization's ID (a UUID), not its org_ name",
		p + "projet: typo\n":                                               "projet",
		p + "credentials: {source: ssh}\n":                                 "source",
		p + "credentials: {source: oidc, oidc: {bot: b}}\n":                "tokenFile",
		p + "credentials: {source: oidc, oidc: {bot: b, tokenFile: /t}}\n": "organization",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to mention %q", body, err, want)
		}
	}
}
