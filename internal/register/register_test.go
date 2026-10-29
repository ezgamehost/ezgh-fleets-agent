package register

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/config"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/creds"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
)

type staticKey string

func (k staticKey) Key(context.Context) (string, error) { return string(k), nil }
func (staticKey) Invalidate(string)                     {}

type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	orgCalls int
	bodies   []map[string]any
	idemKeys []string
	status   []int // answers to successive registrations; the last repeats
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer ezgh_key" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/organizations":
		f.orgCalls++
		_, _ = io.WriteString(w, `{"organizations":[{"id":"6f0c1a2b-0000-4000-8000-000000000001","slug":"org_a"}]}`)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/organizations/6f0c1a2b-0000-4000-8000-000000000001/projects/prj_p/nodes/register":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.bodies = append(f.bodies, b)
		f.idemKeys = append(f.idemKeys, r.Header.Get("Idempotency-Key"))
		st := f.status[min(len(f.bodies), len(f.status))-1]
		w.WriteHeader(st)
		if st == http.StatusConflict {
			_, _ = io.WriteString(w, `{"error":{"code":"node_exists","message":"this instance already has a node"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"0b6c3d1e-0000-4000-8000-000000000002","slug":"nod_abc","organizationId":"6f0c1a2b-0000-4000-8000-000000000001","projectId":"7a1b2c3d-0000-4000-8000-000000000003"}`)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func newRegistrar(t *testing.T, srvURL string) (*Registrar, *[]time.Duration, *bytes.Buffer) {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	var sleeps []time.Duration
	logs := &bytes.Buffer{}
	return &Registrar{
		Config: &config.Config{Project: "prj_p", APIURL: srvURL, OrgsURL: srvURL},
		State:  st,
		Creds:  staticKey("ezgh_key"),
		Facts:  Facts{Hostname: "web-1", OS: OS{ID: "ubuntu", Version: "24.04", Kernel: "6.8.0"}, Arch: "amd64", AgentVersion: "0.1.0"},
		Sleep:  func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil },
		Log:    slog.New(slog.NewTextHandler(logs, nil)),
	}, &sleeps, logs
}

func TestRegisterOnce(t *testing.T) {
	api := &fakeAPI{t: t, status: []int{http.StatusCreated}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	r, _, _ := newRegistrar(t, srv.URL)

	id, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Node == nil || id.Node.ID != "0b6c3d1e-0000-4000-8000-000000000002" || id.Node.Slug != "nod_abc" {
		t.Fatalf("node %+v", id.Node)
	}
	if api.orgCalls != 1 || len(api.bodies) != 1 {
		t.Fatalf("%d org lookups, %d registrations", api.orgCalls, len(api.bodies))
	}
	b := api.bodies[0]
	pub, _ := base64.RawURLEncoding.DecodeString(b["publicKey"].(string))
	if len(pub) != 32 || !bytes.Equal(pub, id.PrivateKey().Public().(ed25519.PublicKey)) {
		t.Fatalf("publicKey %v isn't the stored key's", b["publicKey"])
	}
	if b["hostname"] != "web-1" || b["arch"] != "amd64" || b["agentVersion"] != "0.1.0" || b["os"].(map[string]any)["id"] != "ubuntu" {
		t.Fatalf("body %v", b)
	}
	if api.idemKeys[0] == "" {
		t.Fatal("no Idempotency-Key")
	}
	if fi, err := os.Stat(filepath.Join(r.State.Path, NodeFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("node.json: %v %v", fi, err)
	}

	// A second run reuses the stored node.
	again, err := r.Ensure(context.Background())
	if err != nil || again.Node.ID != id.Node.ID || again.Seed != id.Seed || len(api.bodies) != 1 {
		t.Fatalf("second run: %+v, %v, %d registrations", again, err, len(api.bodies))
	}
}

func TestRegisterConfiguredOrganization(t *testing.T) {
	api := &fakeAPI{t: t, status: []int{http.StatusCreated}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	r, _, _ := newRegistrar(t, srv.URL)
	r.Config.Organization = "6f0c1a2b-0000-4000-8000-000000000001"
	if _, err := r.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.orgCalls != 0 {
		t.Fatal("looked up the organization although the config names it")
	}
}

func TestRegisterNodeExists(t *testing.T) {
	api := &fakeAPI{t: t, status: []int{http.StatusConflict, http.StatusConflict, http.StatusCreated}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	r, sleeps, logs := newRegistrar(t, srv.URL)

	id, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(api.bodies) != 3 || id.Node == nil {
		t.Fatalf("%d registrations, node %+v", len(api.bodies), id.Node)
	}
	if len(*sleeps) != 2 || (*sleeps)[0] != 5*time.Minute || (*sleeps)[1] != 5*time.Minute {
		t.Fatalf("waits %v, want 5m twice", *sleeps)
	}
	if !strings.Contains(logs.String(), "reset the node in the console") {
		t.Fatalf("logs: %s", logs)
	}
	// The node binding never changed while waiting.
	if api.bodies[0]["publicKey"] != api.bodies[2]["publicKey"] {
		t.Fatal("the key pair was replaced")
	}
	// A definite refusal isn't replayed: each retry is a new request.
	if api.idemKeys[0] == api.idemKeys[1] {
		t.Fatal("retried a refused registration with the same Idempotency-Key")
	}
}

func TestRegisterRetriesTransient(t *testing.T) {
	var calls atomic.Int32
	inner := &fakeAPI{t: t, status: []int{http.StatusCreated}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/register") && calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	r, sleeps, _ := newRegistrar(t, srv.URL)
	if _, err := r.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sleeps) != 1 || (*sleeps)[0] >= 5*time.Minute {
		t.Fatalf("waits %v", *sleeps)
	}
}

// After a reset the agent forgets its node and binding key and registers with a new one.
func TestResetRegistersAgain(t *testing.T) {
	api := &fakeAPI{t: t, status: []int{http.StatusCreated}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	r, _, _ := newRegistrar(t, srv.URL)
	first, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(); err != nil {
		t.Fatal(err)
	}
	second, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.RegisteredAt.IsZero() || second.RegisteredAt.Before(first.RegisteredAt) {
		t.Fatalf("registeredAt %v then %v", first.RegisteredAt, second.RegisteredAt)
	}
	var stored Identity
	if err := r.State.Read(NodeFile, &stored); err != nil || !stored.RegisteredAt.Equal(second.RegisteredAt) {
		t.Fatalf("registeredAt not stored: %v, %v", stored.RegisteredAt, err)
	}
	if second.Seed == first.Seed || second.IdempotencyKey == first.IdempotencyKey {
		t.Fatal("registered again with the old binding key or idempotency key")
	}
	if len(api.bodies) != 2 || api.bodies[1]["publicKey"] == api.bodies[0]["publicKey"] {
		t.Fatalf("registrations %v, want a second one with a new key", api.bodies)
	}
}

// With no project in the config, the agent registers in the instance's project, from the metadata
// service; off an EZGH instance it refuses to start.
func TestRegisterUsesMetadataProject(t *testing.T) {
	var instanceReads atomic.Int32
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ezgh/v1/token":
			_, _ = io.WriteString(w, "tok")
		case "/ezgh/v1/credentials":
			_, _ = io.WriteString(w, `{"apiKey":"ezgh_key","expiresAt":"2999-01-01T00:00:00Z","bot":"bot_x"}`)
		case "/ezgh/v1/instance":
			instanceReads.Add(1)
			_, _ = io.WriteString(w, `{"id":"ins_a","name":"web-1","type":"g1.small","project":"prj_mtgr29er0q1k","region":"us-west-1","interfaces":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer md.Close()
	var path string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"0b6c3d1e-0000-4000-8000-000000000002","slug":"nod_abc"}`)
	}))
	defer api.Close()
	r, _, _ := newRegistrar(t, api.URL)
	r.Config.Project, r.Config.Organization = "", "6f0c1a2b-0000-4000-8000-000000000001"
	r.Creds = &creds.Metadata{Endpoint: md.URL}
	id, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, "/projects/prj_mtgr29er0q1k/") || id.Node.ProjectID != "prj_mtgr29er0q1k" {
		t.Fatalf("registered at %s, node %+v", path, id.Node)
	}
	if err := r.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ensure(context.Background()); err != nil || instanceReads.Load() != 1 {
		t.Fatalf("again: %v, %d instance reads (want 1: it can't change)", err, instanceReads.Load())
	}

	for name, src := range map[string]creds.Source{"not an instance": staticKey("ezgh_key"), "metadata unreachable": &creds.Metadata{Endpoint: "http://127.0.0.1:1"}} {
		r, _, _ := newRegistrar(t, api.URL)
		r.Config.Project, r.Creds = "", src
		if _, err := r.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "project is required (or run on an EZGH instance)") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
