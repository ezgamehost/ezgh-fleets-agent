// Package register registers this machine as a Systems Manager node, once, and keeps the node
// binding (an Ed25519 key pair the agent makes itself) in the state directory.
package register

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ezgamehost/ezgh-systems-agent/internal/config"
	"github.com/ezgamehost/ezgh-systems-agent/internal/creds"
	"github.com/ezgamehost/ezgh-systems-agent/internal/state"
)

// NodeFile holds the Identity.
const NodeFile = "node.json"

const (
	refusedRetry   = 5 * time.Minute // node_exists, or a refusal a person has to fix
	transientRetry = 30 * time.Second
)

type Node struct {
	ID             string `json:"id"`
	Slug           string `json:"slug"`
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId"`
}

// Identity is the node binding and, once registered, the node.
type Identity struct {
	Seed           string `json:"privateKeySeed"` // base64url Ed25519 seed
	IdempotencyKey string `json:"idempotencyKey"` // reused until the registration is answered
	Node           *Node  `json:"node,omitempty"`
}

func (i *Identity) PrivateKey() ed25519.PrivateKey {
	seed, _ := base64.RawURLEncoding.DecodeString(i.Seed)
	return ed25519.NewKeyFromSeed(seed)
}

type OS struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
}

// Facts describe the machine at registration.
type Facts struct {
	Hostname     string
	OS           OS
	Arch         string
	AgentVersion string
}

// LocalFacts reads this machine's facts.
func LocalFacts(agentVersion string) Facts {
	h, _ := os.Hostname()
	f := Facts{Hostname: h, Arch: runtime.GOARCH, AgentVersion: agentVersion}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(line, "=")
			v = strings.Trim(v, `"'`)
			switch k {
			case "ID":
				f.OS.ID = v
			case "VERSION_ID":
				f.OS.Version = v
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.OS.Kernel = strings.TrimSpace(string(b))
	}
	return f
}

type Registrar struct {
	Config *config.Config
	State  *state.Dir
	Creds  creds.Source
	Facts  Facts
	HTTP   *http.Client
	Sleep  func(ctx context.Context, d time.Duration) error // default: a timer
	Log    *slog.Logger
}

// Ensure returns the stored node, or registers until it has one (or ctx ends). It never
// deletes the node binding.
func (r *Registrar) Ensure(ctx context.Context) (*Identity, error) {
	var id Identity
	switch err := r.State.Read(NodeFile, &id); {
	case err == nil && id.Node != nil:
		return &id, nil
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		id = Identity{Seed: base64.RawURLEncoding.EncodeToString(seed), IdempotencyKey: newIdempotencyKey()}
		if err := r.State.Write(NodeFile, &id); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("reading %s: %w", NodeFile, err)
	}
	for {
		wait, err := r.attempt(ctx, &id)
		if err == nil {
			r.Log.Info("registered", "node", id.Node.Slug)
			return &id, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err := r.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// attempt registers once; on failure it says how long to wait.
func (r *Registrar) attempt(ctx context.Context, id *Identity) (time.Duration, error) {
	key, err := r.Creds.Key(ctx)
	if err != nil {
		wait := transientRetry
		if errors.Is(err, creds.ErrNoBot) {
			wait = creds.NoBotRetry
		}
		r.Log.Warn("no bot key yet", "err", err, "retryIn", wait)
		return wait, err
	}
	org := r.Config.Organization
	if org == "" {
		if org, err = r.organization(ctx, key); err != nil {
			r.Log.Warn("couldn't learn the organization; set organization in the config", "err", err)
			return transientRetry, err
		}
	}
	body, _ := json.Marshal(map[string]any{
		"publicKey":    base64.RawURLEncoding.EncodeToString(id.PrivateKey().Public().(ed25519.PublicKey)),
		"hostname":     r.Facts.Hostname,
		"os":           r.Facts.OS,
		"arch":         r.Facts.Arch,
		"agentVersion": r.Facts.AgentVersion,
	})
	u := strings.TrimRight(r.Config.APIURL, "/") + "/v1/organizations/" + url.PathEscape(org) + "/projects/" + url.PathEscape(r.Config.Project) + "/nodes/register"
	status, rb, retryAfter, err := r.do(ctx, http.MethodPost, u, key, id.IdempotencyKey, body)
	if err != nil {
		r.Log.Warn("registration failed", "err", err)
		return transientRetry, err
	}
	switch {
	case status == http.StatusOK || status == http.StatusCreated:
		var n Node
		if err := json.Unmarshal(rb, &n); err != nil || n.ID == "" || n.Slug == "" {
			return transientRetry, errors.New("systems-api sent an unreadable node")
		}
		if n.OrganizationID == "" {
			n.OrganizationID = org
		}
		if n.ProjectID == "" {
			n.ProjectID = r.Config.Project
		}
		id.Node = &n
		return 0, r.State.Write(NodeFile, id)
	case status == http.StatusUnauthorized:
		r.Creds.Invalidate(key)
		r.Log.Warn("the bot key was refused", "status", status)
		return transientRetry, errors.New("unauthorized")
	case status == http.StatusTooManyRequests || status >= 500:
		r.Log.Warn("registration failed", "status", status)
		return max(transientRetry, retryAfter), fmt.Errorf("status %d", status)
	}
	// A definite answer: the next attempt is a new request, not a replay of this one.
	id.IdempotencyKey = newIdempotencyKey()
	if err := r.State.Write(NodeFile, id); err != nil {
		return transientRetry, err
	}
	code, msg := apiError(rb)
	if status == http.StatusConflict && code == "node_exists" {
		r.Log.Error("this instance already has a node: reset the node in the console to register it again", "retryIn", refusedRetry)
	} else {
		r.Log.Error("registration refused", "status", status, "code", code, "message", msg, "retryIn", refusedRetry)
	}
	return refusedRetry, fmt.Errorf("status %d %s", status, code)
}

func (r *Registrar) organization(ctx context.Context, key string) (string, error) {
	status, b, _, err := r.do(ctx, http.MethodGet, strings.TrimRight(r.Config.OrgsURL, "/")+"/v1/organizations", key, "", nil)
	if err != nil {
		return "", err
	}
	if status == http.StatusUnauthorized {
		r.Creds.Invalidate(key)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("org-api answered %d", status)
	}
	var out struct {
		Organizations []struct {
			ID string `json:"id"`
		} `json:"organizations"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	if len(out.Organizations) != 1 {
		return "", fmt.Errorf("the key sees %d organizations", len(out.Organizations))
	}
	return out.Organizations[0].ID, nil
}

func (r *Registrar) do(ctx context.Context, method, u, key, idem string, body []byte) (int, []byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	c := r.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ra time.Duration
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
		ra = time.Duration(n) * time.Second
	}
	return resp.StatusCode, b, ra, nil
}

func (r *Registrar) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func apiError(b []byte) (code, message string) {
	var e struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Error.Code, e.Error.Message
}

func newIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
