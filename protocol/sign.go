package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrExpired      = errors.New("expired")
	ErrWrongNode    = errors.New("wrong_node")
	ErrUnknownKey   = errors.New("unknown_key")
	ErrBadSignature = errors.New("bad_signature")
)

// Signatures cover a context line plus the payload bytes, so bytes signed as one kind
// never verify as the other.
const (
	instructionContext = "ezgh-fleets-instruction-v1\n"
	keyListContext     = "ezgh-fleets-keylist-v1\n"
)

var b64 = base64.RawURLEncoding

type keyListPayload struct {
	Keys     []wireKey `json:"keys"`
	IssuedAt time.Time `json:"issuedAt"`
}

type wireKey struct {
	Kid       string    `json:"kid"`
	PublicKey string    `json:"publicKey"`
	NotAfter  time.Time `json:"notAfter"`
}

func validInstruction(in Instruction) error {
	switch in.Type {
	case TypeOpenSession, TypeResumeSession, TypeRunInvocation:
	default:
		return fmt.Errorf("unknown instruction type %q", in.Type)
	}
	if in.NodeID == "" || in.ID == "" || in.IssuedAt.IsZero() || in.ExpiresAt.IsZero() {
		return errors.New("instruction needs nodeId, id, issuedAt and expiresAt")
	}
	return nil
}

func SignInstruction(priv ed25519.PrivateKey, kid string, in Instruction) (SignedInstruction, error) {
	if err := validInstruction(in); err != nil {
		return SignedInstruction{}, err
	}
	p, err := json.Marshal(in)
	if err != nil {
		return SignedInstruction{}, err
	}
	sig := ed25519.Sign(priv, append([]byte(instructionContext), p...))
	return SignedInstruction{V: 1, Kid: kid, Payload: b64.EncodeToString(p), Sig: b64.EncodeToString(sig)}, nil
}

// VerifyInstruction checks the signature, the node and the validity window (±skew). Replays
// are the caller's to check: it must remember IDs it has seen until they expire.
func VerifyInstruction(keys map[string]ed25519.PublicKey, s SignedInstruction, nodeID string, now time.Time, skew time.Duration) (Instruction, error) {
	var in Instruction
	if s.V != 1 {
		return in, fmt.Errorf("%w: version %d", ErrBadSignature, s.V)
	}
	key, ok := keys[s.Kid]
	if !ok {
		return in, fmt.Errorf("%w: kid %q", ErrUnknownKey, s.Kid)
	}
	p, err := verify(key, instructionContext, s.Payload, s.Sig)
	if err != nil {
		return in, err
	}
	if err := json.Unmarshal(p, &in); err != nil {
		return Instruction{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if err := validInstruction(in); err != nil {
		return Instruction{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if in.NodeID != nodeID {
		return Instruction{}, ErrWrongNode
	}
	if now.After(in.ExpiresAt.Add(skew)) || now.Before(in.IssuedAt.Add(-skew)) {
		return Instruction{}, ErrExpired
	}
	return in, nil
}

func SignKeyList(root ed25519.PrivateKey, rootKid string, keys []PublicKey) (SignedKeyList, error) {
	wl := keyListPayload{Keys: make([]wireKey, 0, len(keys)), IssuedAt: time.Now().UTC()}
	for _, k := range keys {
		if k.Kid == "" || len(k.PublicKey) != ed25519.PublicKeySize || k.NotAfter.IsZero() {
			return SignedKeyList{}, fmt.Errorf("key %q: needs a kid, a 32-byte Ed25519 key and notAfter", k.Kid)
		}
		wl.Keys = append(wl.Keys, wireKey{Kid: k.Kid, PublicKey: b64.EncodeToString(k.PublicKey), NotAfter: k.NotAfter})
	}
	p, err := json.Marshal(wl)
	if err != nil {
		return SignedKeyList{}, err
	}
	sig := ed25519.Sign(root, append([]byte(keyListContext), p...))
	return SignedKeyList{V: 1, RootKid: rootKid, Payload: b64.EncodeToString(p), Sig: b64.EncodeToString(sig)}, nil
}

// VerifyKeyList checks the list against roots and returns the keys still valid at now.
func VerifyKeyList(roots map[string]ed25519.PublicKey, l SignedKeyList, now time.Time) (map[string]ed25519.PublicKey, error) {
	ks, err := VerifyKeyListKeys(roots, l, now)
	if err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range ks {
		keys[k.Kid] = k.PublicKey
	}
	return keys, nil
}

// VerifyKeyListKeys is VerifyKeyList keeping each key's notAfter, for a holder of the list to
// stop trusting a key once it passes.
func VerifyKeyListKeys(roots map[string]ed25519.PublicKey, l SignedKeyList, now time.Time) ([]PublicKey, error) {
	if l.V != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrBadSignature, l.V)
	}
	root, ok := roots[l.RootKid]
	if !ok {
		return nil, fmt.Errorf("%w: root %q", ErrUnknownKey, l.RootKid)
	}
	p, err := verify(root, keyListContext, l.Payload, l.Sig)
	if err != nil {
		return nil, err
	}
	var wl keyListPayload
	if err := json.Unmarshal(p, &wl); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	var keys []PublicKey
	for _, k := range wl.Keys {
		pub, err := b64.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key %q malformed", ErrBadSignature, k.Kid)
		}
		if now.Before(k.NotAfter) {
			keys = append(keys, PublicKey{Kid: k.Kid, PublicKey: pub, NotAfter: k.NotAfter})
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no key in the list is still valid", ErrExpired)
	}
	return keys, nil
}

func verify(key ed25519.PublicKey, context, payload, sig string) ([]byte, error) {
	p, err := canonical(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrBadSignature, err)
	}
	sg, err := canonical(sig)
	if err != nil {
		return nil, fmt.Errorf("%w: sig: %v", ErrBadSignature, err)
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(context), p...), sg) {
		return nil, ErrBadSignature
	}
	return p, nil
}

// canonical decodes s, refusing any encoding but the canonical one: the decoder skips \r and
// \n and ignores the last character's unused bits, so a replay could otherwise differ in bytes.
func canonical(s string) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err == nil && b64.EncodeToString(b) != s {
		err = errors.New("not canonical base64url")
	}
	return b, err
}
