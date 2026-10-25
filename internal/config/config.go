// Package config reads the agent's configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultPath            = "/etc/ezgh-fleets-agent/config.yaml"
	DefaultCredentialsFile = "/etc/ezgh-fleets-agent/credentials"
	DefaultStateDir        = "/var/lib/ezgh-fleets-agent"
)

// Credential sources.
const (
	SourceAuto     = "auto" // metadata on an EZGH compute instance, else the key file
	SourceMetadata = "metadata"
	SourceFile     = "file"
	SourceOIDC     = "oidc"
)

// fleets-api takes IDs in its paths, not prj_/org_ names.
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Config struct {
	// Organization (optional: the agent asks org-api which one its key belongs to) and Project
	// are IDs (UUIDs).
	Organization string      `yaml:"organization"`
	Project      string      `yaml:"project"`
	Credentials  Credentials `yaml:"credentials"`

	APIURL      string `yaml:"apiUrl"`
	GatewayURL  string `yaml:"gatewayUrl"`
	OrgsURL     string `yaml:"orgsUrl"`
	MetadataURL string `yaml:"metadataUrl"`
	StateDir    string `yaml:"stateDir"`
}

type Credentials struct {
	Source string `yaml:"source"`
	File   string `yaml:"file"`
	OIDC   OIDC   `yaml:"oidc"`
}

// OIDC exchanges a workload's ID token for a short-lived key of Bot.
type OIDC struct {
	Bot       string `yaml:"bot"`
	TokenFile string `yaml:"tokenFile"`
}

// Load reads and checks the file at path, filling in defaults.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) check() error {
	if c.Project == "" {
		return errors.New("project is required")
	}
	if !uuid.MatchString(c.Project) {
		return errors.New("project must be the project's ID (a UUID), not its prj_ name")
	}
	if c.Organization != "" && !uuid.MatchString(c.Organization) {
		return errors.New("organization must be the organization's ID (a UUID), not its org_ name")
	}
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&c.APIURL, "https://fleets-api.ezghcloud.com")
	def(&c.GatewayURL, "wss://fleets-gateway.ezghcloud.com")
	def(&c.OrgsURL, "https://orgs.ezghcloud.com")
	def(&c.MetadataURL, "http://169.254.169.254")
	def(&c.StateDir, DefaultStateDir)
	def(&c.Credentials.Source, SourceAuto)
	def(&c.Credentials.File, DefaultCredentialsFile)
	switch c.Credentials.Source {
	case SourceAuto, SourceMetadata, SourceFile:
	case SourceOIDC:
		if c.Credentials.OIDC.Bot == "" || c.Credentials.OIDC.TokenFile == "" {
			return errors.New("credentials.oidc needs bot and tokenFile")
		}
		if c.Organization == "" {
			return errors.New("organization is required with OIDC credentials")
		}
	default:
		return fmt.Errorf("credentials.source %q: use auto, metadata, file or oidc", c.Credentials.Source)
	}
	return nil
}
