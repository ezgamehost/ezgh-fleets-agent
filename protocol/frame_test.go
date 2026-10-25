package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, c := range []struct {
		off uint64
		p   []byte
	}{
		{0, []byte("hello")},
		{1 << 40, []byte{0, 1, 2}},
		{7, nil},
	} {
		b := EncodeData(c.off, c.p)
		if len(b) != 8+len(c.p) {
			t.Fatalf("len %d", len(b))
		}
		off, p, err := DecodeData(b)
		if err != nil {
			t.Fatal(err)
		}
		if off != c.off || !bytes.Equal(p, c.p) {
			t.Fatalf("got %d %q, want %d %q", off, p, c.off, c.p)
		}
	}
	if _, _, err := DecodeData([]byte{1, 2, 3, 4, 5, 6, 7}); err == nil {
		t.Fatal("short buffer decoded")
	}
}

func TestControlJSONNames(t *testing.T) {
	code := 3
	for _, c := range []struct {
		v    any
		want string
	}{
		{Resize{T: TypeResize, Cols: 80, Rows: 24}, `{"t":"resize","cols":80,"rows":24}`},
		{Ack{T: TypeAck, Offset: 9}, `{"t":"ack","offset":9}`},
		{Resume{T: TypeResume, Offset: 9}, `{"t":"resume","offset":9}`},
		{Exit{T: TypeExit, Code: 1}, `{"t":"exit","code":1}`},
		{Status{T: TypeStatus, State: "connected"}, `{"t":"status","state":"connected"}`},
		{Cancel{T: TypeCancel, RunID: "r"}, `{"t":"cancel","runId":"r"}`},
		{Rekey{T: TypeRekey, APIKey: "k"}, `{"t":"rekey","apiKey":"k"}`},
		{Refused{T: TypeRefused, ID: "i", Reason: "replayed"}, `{"t":"refused","id":"i","reason":"replayed"}`},
		{SessionEnded{T: TypeSessionEnded, SessionID: "s", Reason: "exited"}, `{"t":"sessionEnded","sessionId":"s","reason":"exited"}`},
		{InvocationResult{T: TypeInvocationResult, RunID: "r", Status: "failed", ExitCode: &code}, `{"t":"invocationResult","runId":"r","status":"failed","exitCode":3}`},
	} {
		b, err := json.Marshal(c.v)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != c.want {
			t.Errorf("got %s, want %s", b, c.want)
		}
	}
}
