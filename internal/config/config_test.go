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
	c, err := load(t, "project: prj_abc\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Credentials.Source != SourceAuto || c.Credentials.File != DefaultCredentialsFile || c.StateDir != DefaultStateDir {
		t.Fatalf("defaults: %+v", c)
	}
	if c.APIURL != "https://systems-api.ezghcloud.com" || c.GatewayURL != "wss://systems-gateway.ezghcloud.com" {
		t.Fatalf("urls: %+v", c)
	}
}

func TestLoadRefuses(t *testing.T) {
	for body, want := range map[string]string{
		"organization: org_x\n":                                                    "project",
		"project: p\nprojet: typo\n":                                               "projet",
		"project: p\ncredentials: {source: ssh}\n":                                 "source",
		"project: p\ncredentials: {source: oidc, oidc: {bot: b}}\n":                "tokenFile",
		"project: p\ncredentials: {source: oidc, oidc: {bot: b, tokenFile: /t}}\n": "organization",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to mention %q", body, err, want)
		}
	}
}
