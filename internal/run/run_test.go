package run

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/instr"
	"github.com/ezgamehost/ezgh-fleets-agent/internal/state"
	"github.com/ezgamehost/ezgh-fleets-agent/protocol"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type fixture struct {
	t       *testing.T
	r       *Runner
	clock   *clockwork.FakeClock
	reports chan any
	dir     string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Open(filepath.Join(dir, "invocations"))
	if err != nil {
		t.Fatal(err)
	}
	me, _ := user.Current()
	f := &fixture{t: t, clock: clockwork.NewFakeClockAt(t0), reports: make(chan any, 16), dir: dir}
	f.r = &Runner{
		Dir: st, Clock: f.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Acquire: func(context.Context, protocol.Instruction) (string, error) {
			return me.Username, nil
		},
		Report: func(v any) error { f.reports <- v; return nil },
	}
	t.Cleanup(f.r.Wait) // after TempDir's cleanup is registered, so it runs first: no write after removal
	return f
}

func (f *fixture) result() protocol.InvocationResult {
	f.t.Helper()
	for {
		select {
		case v := <-f.reports:
			if r, ok := v.(protocol.InvocationResult); ok {
				return r
			}
		case <-time.After(10 * time.Second):
			f.t.Fatal("no result")
		}
	}
}

func (f *fixture) started() {
	f.t.Helper()
	select {
	case v := <-f.reports:
		if _, ok := v.(protocol.InvocationStarted); !ok {
			f.t.Fatalf("got %#v, want invocationStarted", v)
		}
	case <-time.After(10 * time.Second):
		f.t.Fatal("never started")
	}
}

func command(id, c string, timeout int) protocol.Instruction {
	root := "root"
	return protocol.Instruction{Type: protocol.TypeRunInvocation, NodeID: "n", ID: id, OSUser: &root, Command: &c, TimeoutSeconds: timeout, IssuedAt: t0, ExpiresAt: t0.Add(time.Hour)}
}

func TestRunCommand(t *testing.T) {
	f := newFixture(t)
	who := filepath.Join(f.dir, "who")
	// Two megabytes of output: it would block on a full pipe if it weren't drained.
	f.r.Run(command("r1", "head -c 2000000 /dev/zero; id -un > "+who+"; exit 7", 0))
	f.started()
	res := f.result()
	if res.Status != StatusFailed || res.ExitCode == nil || *res.ExitCode != 7 || res.RunID != "r1" || res.StartedAt == nil || res.EndedAt == nil {
		t.Fatalf("result %+v", res)
	}
	me, _ := user.Current()
	if b, _ := os.ReadFile(who); strings.TrimSpace(string(b)) != me.Username {
		t.Fatalf("ran as %q", b)
	}
	f.r.Run(command("r2", "true", 0))
	f.started()
	if res := f.result(); res.Status != StatusSucceeded || *res.ExitCode != 0 {
		t.Fatalf("result %+v", res)
	}
}

func script(id, body, sum string, params map[string]string) protocol.Instruction {
	in := command(id, "", 0)
	in.Command = nil
	in.Script = &protocol.Script{Shell: "sh", Body: body, SHA256: sum}
	in.Parameters = params
	return in
}

func TestRunScriptParameters(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.dir, "ok")
	body := `[ "$EZGH_PARAM_SERVICE" = nginx ] && touch "$EZGH_PARAM_OUT"`
	sum := sha256.Sum256([]byte(body))
	f.r.Run(script("s1", body, hex.EncodeToString(sum[:]), map[string]string{"service": "nginx", "out": out}))
	f.started()
	if res := f.result(); res.Status != StatusSucceeded {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("parameters didn't reach the script")
	}

	_ = os.Remove(out)
	f.r.Run(script("s2", body, strings.Repeat("0", 64), map[string]string{"service": "nginx", "out": out}))
	if res := f.result(); res.Status != StatusFailed || res.Reason != ReasonScriptHash {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a script whose hash didn't match ran")
	}
}

func TestTimeoutKills(t *testing.T) {
	f := newFixture(t)
	// The shell and its child ignore SIGTERM, so only the SIGKILL 10 s later ends them.
	ready := filepath.Join(f.dir, "ready")
	f.r.Run(command("t1", "trap '' TERM; touch "+ready+"; sleep 1000", 5))
	f.started()
	waitFile(t, ready) // SIGTERM before the trap would end it
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.clock.BlockUntilContext(ctx, 1); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(5 * time.Second)
	if err := f.clock.BlockUntilContext(ctx, 1); err != nil { // the SIGKILL timer
		t.Fatal(err)
	}
	select {
	case v := <-f.reports:
		t.Fatalf("ended on SIGTERM: %#v", v)
	case <-time.After(100 * time.Millisecond):
	}
	f.clock.Advance(KillAfter)
	if res := f.result(); res.Status != StatusTimedOut {
		t.Fatalf("result %+v", res)
	}
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCancel(t *testing.T) {
	f := newFixture(t)
	f.r.Run(command("c1", "sleep 1000", 0))
	f.started()
	f.r.Cancel("c1")
	if res := f.result(); res.Status != StatusCancelled {
		t.Fatalf("result %+v", res)
	}
	f.r.Cancel("unknown") // no-op
}

func TestAgentRestartedNeverReruns(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(f.dir, "ran")
	in := command("a1", "touch "+marker, 0)
	// A record from before a crash: started, never finished.
	started := t0.Add(-time.Minute)
	if err := f.r.Dir.Write(file("a1"), record{ID: "a1", StartedAt: &started, ForgetAfter: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := f.r.Recover(); err != nil {
		t.Fatal(err)
	}
	if res := f.result(); res.Status != StatusFailed || res.Reason != ReasonAgentRestarted || !res.StartedAt.Equal(started) {
		t.Fatalf("result %+v", res)
	}
	f.r.Run(in) // the same invocation delivered again
	if res := f.result(); res.Reason != ReasonAgentRestarted {
		t.Fatalf("redelivery: %+v", res)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the interrupted invocation ran again")
	}
}

func TestDuplicateInstructionRunsOnce(t *testing.T) {
	f := newFixture(t)
	log := filepath.Join(f.dir, "log")
	in := command("d1", "echo x >> "+log, 0)

	// The worker re-signs on re-dispatch: different bytes, so the replay check lets both through.
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	st, _ := state.Open(filepath.Join(f.dir, "s"))
	chk, _ := instr.New("n", st, nil)
	chk.Roots = map[string]ed25519.PublicKey{"r": rootPub}
	l, _ := protocol.SignKeyList(rootPriv, "r", []protocol.PublicKey{{Kid: "k", PublicKey: pub, NotAfter: t0.Add(time.Hour)}})
	_ = chk.SetKeyList(l, t0)
	again := in
	again.IssuedAt = t0.Add(time.Second)
	var delivered []protocol.Instruction
	for _, x := range []protocol.Instruction{in, again} {
		s, _ := protocol.SignInstruction(priv, "k", x)
		got, err := chk.Check(s, t0.Add(2*time.Second))
		if err != nil {
			t.Fatalf("re-signed copy refused by the replay check: %v", err)
		}
		delivered = append(delivered, got)
	}

	f.r.Run(delivered[0])
	f.r.Run(delivered[1]) // while the first may still run
	f.result()
	f.r.Run(delivered[1]) // after it finished: the result is reported again
	if res := f.result(); res.Status != StatusSucceeded {
		t.Fatalf("result %+v", res)
	}
	if b, _ := os.ReadFile(log); string(b) != "x\n" {
		t.Fatalf("ran %d times", strings.Count(string(b), "x"))
	}

	// And once across restarts: a new runner on the same state directory.
	r2 := &Runner{Dir: f.r.Dir, Acquire: f.r.Acquire, Report: f.r.Report, Clock: f.clock, Log: f.r.Log}
	t.Cleanup(r2.Wait)
	if err := r2.Recover(); err != nil {
		t.Fatal(err)
	}
	r2.Run(delivered[0])
	f.result()
	if b, _ := os.ReadFile(log); string(b) != "x\n" {
		t.Fatal("ran again after a restart")
	}
}
