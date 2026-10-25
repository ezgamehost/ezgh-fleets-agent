package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func sampleInstruction() Instruction {
	root := "root"
	return Instruction{
		Type:      TypeOpenSession,
		NodeID:    "8d1f1a52-3c3e-4b8a-9e43-0c1f3b7a2d11",
		ID:        "0f0e6c0a-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		OSUser:    &root,
		IssuedAt:  t0,
		ExpiresAt: t0.Add(60 * time.Second),
	}
}

// withPayload swaps the payload for p while keeping the original signature.
func withPayload(s SignedInstruction, p []byte) SignedInstruction {
	s.Payload = base64.RawURLEncoding.EncodeToString(p)
	return s
}

func TestVerifyInstruction(t *testing.T) {
	pub, priv := newKey(t)
	_, otherPriv := newKey(t)
	keys := map[string]ed25519.PublicKey{"k1": pub}
	in := sampleInstruction()
	skew := 300 * time.Second

	good, err := SignInstruction(priv, "k1", in)
	if err != nil {
		t.Fatal(err)
	}
	byOther, err := SignInstruction(otherPriv, "k1", in)
	if err != nil {
		t.Fatal(err)
	}
	unknownKid, err := SignInstruction(priv, "k2", in)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(good.Payload)
	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)/2] ^= 0x01
	swapped := []byte(strings.Replace(string(raw), `"osUser":"root"`, `"osUser":"deploy"`, 1))
	if string(swapped) == string(raw) {
		t.Fatal("osUser not found in payload")
	}
	badVersion := good
	badVersion.V = 2

	cases := []struct {
		name   string
		s      SignedInstruction
		nodeID string
		now    time.Time
		want   error
	}{
		{"valid", good, in.NodeID, t0.Add(time.Second), nil},
		{"within skew after expiry", good, in.NodeID, in.ExpiresAt.Add(299 * time.Second), nil},
		{"within skew before issue", good, in.NodeID, t0.Add(-299 * time.Second), nil},
		{"expired beyond skew", good, in.NodeID, in.ExpiresAt.Add(301 * time.Second), ErrExpired},
		{"issued beyond skew in the future", good, in.NodeID, t0.Add(-301 * time.Second), ErrExpired},
		{"wrong node", good, "another-node", t0, ErrWrongNode},
		{"unknown kid", unknownKid, in.NodeID, t0, ErrUnknownKey},
		{"payload byte flipped", withPayload(good, flipped), in.NodeID, t0, ErrBadSignature},
		{"osUser swapped after signing", withPayload(good, swapped), in.NodeID, t0, ErrBadSignature},
		{"signed by a key not in the list", byOther, in.NodeID, t0, ErrBadSignature},
		{"unknown version", badVersion, in.NodeID, t0, ErrBadSignature},
		{"signature not base64", SignedInstruction{V: 1, Kid: "k1", Payload: good.Payload, Sig: "!!"}, in.NodeID, t0, ErrBadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := VerifyInstruction(keys, c.s, c.nodeID, c.now, skew)
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("err = %v, want %v", err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(in)
			if string(a) != string(b) {
				t.Fatalf("got %s, want %s", a, b)
			}
		})
	}
}

func TestSignInstructionRefusesUnsignable(t *testing.T) {
	_, priv := newKey(t)
	in := sampleInstruction()
	in.Type = "rm -rf"
	if _, err := SignInstruction(priv, "k1", in); err == nil {
		t.Fatal("signed an unknown instruction type")
	}
	in = sampleInstruction()
	in.NodeID = ""
	if _, err := SignInstruction(priv, "k1", in); err == nil {
		t.Fatal("signed an instruction without a node")
	}
}

func TestInstructionJSONNames(t *testing.T) {
	in := sampleInstruction()
	in.Person = &Person{Type: "user", ID: "u1", BaseName: "alice"}
	in.Script = &Script{Shell: "bash", Body: "echo", SHA256: "ab"}
	in.Parameters = map[string]string{"service": "nginx"}
	in.EzghUserSudo = true
	in.TimeoutSeconds = 5
	b, _ := json.Marshal(in)
	for _, f := range []string{`"type"`, `"nodeId"`, `"id"`, `"osUser"`, `"person"`, `"baseName"`, `"ezghUserSudo"`, `"script"`, `"sha256"`, `"parameters"`, `"timeoutSeconds"`, `"issuedAt"`, `"expiresAt"`} {
		if !strings.Contains(string(b), f) {
			t.Errorf("%s missing from %s", f, b)
		}
	}
}

func TestVerifyKeyList(t *testing.T) {
	rootPub, rootPriv := newKey(t)
	_, otherRoot := newKey(t)
	k1, _ := newKey(t)
	k2, _ := newKey(t)
	roots := map[string]ed25519.PublicKey{"root-test": rootPub}
	keys := []PublicKey{
		{Kid: "k1", PublicKey: k1, NotAfter: t0.Add(time.Hour)},
		{Kid: "k2", PublicKey: k2, NotAfter: t0.Add(-time.Second)},
	}

	l, err := SignKeyList(rootPriv, "root-test", keys)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid, a key past notAfter left out", func(t *testing.T) {
		got, err := VerifyKeyList(roots, l, t0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !got["k1"].Equal(k1) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("every key past notAfter", func(t *testing.T) {
		if _, err := VerifyKeyList(roots, l, t0.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown root", func(t *testing.T) {
		u := l
		u.RootKid = "root-other"
		if _, err := VerifyKeyList(roots, u, t0); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("signed by another root under a known kid", func(t *testing.T) {
		o, err := SignKeyList(otherRoot, "root-test", keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKeyList(roots, o, t0); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		raw, _ := base64.RawURLEncoding.DecodeString(l.Payload)
		raw[len(raw)/2] ^= 0x01
		u := l
		u.Payload = base64.RawURLEncoding.EncodeToString(raw)
		if _, err := VerifyKeyList(roots, u, t0); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("an instruction signature is not a key list signature", func(t *testing.T) {
		// Domain separation: bytes signed as an instruction never verify as a key list.
		s, err := SignInstruction(rootPriv, "root-test", sampleInstruction())
		if err != nil {
			t.Fatal(err)
		}
		u := SignedKeyList{V: 1, RootKid: "root-test", Payload: s.Payload, Sig: s.Sig}
		if _, err := VerifyKeyList(roots, u, t0); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("round trip through JSON", func(t *testing.T) {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"rootKid"`) {
			t.Fatalf("json names: %s", b)
		}
		var back SignedKeyList
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKeyList(roots, back, t0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad key length refused at signing", func(t *testing.T) {
		if _, err := SignKeyList(rootPriv, "root-test", []PublicKey{{Kid: "x", PublicKey: []byte{1}, NotAfter: t0}}); err == nil {
			t.Fatal("signed a short key")
		}
	})
}

func TestChallengeMessages(t *testing.T) {
	if got := string(ConnectMessage("n", "x")); got != "ezgh-fleets-connect-v1\nn\nx" {
		t.Fatal(got)
	}
	if got := string(DataMessage("n", "s", "x")); got != "ezgh-fleets-data-v1\nn\ns\nx" {
		t.Fatal(got)
	}
}
