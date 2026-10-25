package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestOutbox(t *testing.T) {
	var o Outbox
	var sent []byte
	chunk := make([]byte, 1024)
	for i := 0; i < 300; i++ {
		for j := range chunk {
			chunk[j] = byte(i + j)
		}
		if off := o.Write(chunk); off != uint64(len(sent)) {
			t.Fatalf("write %d at offset %d, want %d", i, off, len(sent))
		}
		sent = append(sent, chunk...)
		if i == 10 {
			o.Ack(10 * 1024) // acks lag far behind
		}
	}

	// 300 KiB written, 256 KiB kept: the first 44 KiB are gone.
	if _, err := o.From(10 * 1024); !errors.Is(err, ErrGap) {
		t.Fatalf("From an old offset: err = %v, want ErrGap", err)
	}
	kept := uint64(len(sent) - ResumeBuffer)
	got, err := o.From(kept)
	if err != nil || !bytes.Equal(got, sent[kept:]) {
		t.Fatalf("From the oldest kept offset: %d bytes, err %v", len(got), err)
	}

	o.Ack(100 * 1024)
	got, err = o.From(100 * 1024)
	if err != nil || !bytes.Equal(got, sent[100*1024:]) {
		t.Fatalf("From the acked offset: %d bytes, err %v", len(got), err)
	}
	if n := len(o.buf); n != len(sent)-100*1024 {
		t.Fatalf("Ack kept %d bytes, want %d", n, len(sent)-100*1024)
	}
	if _, err := o.From(99 * 1024); !errors.Is(err, ErrGap) {
		t.Fatalf("From before the ack: err = %v, want ErrGap", err)
	}

	o.Ack(uint64(len(sent)))
	if len(o.buf) != 0 {
		t.Fatalf("acking everything kept %d bytes", len(o.buf))
	}
	if got, err := o.From(uint64(len(sent))); err != nil || len(got) != 0 {
		t.Fatalf("From the end: %q, %v", got, err)
	}
	if _, err := o.From(uint64(len(sent)) + 1); !errors.Is(err, ErrGap) {
		t.Fatalf("From past the end: err = %v, want ErrGap", err)
	}
	o.Ack(1) // an old ack is a no-op
	if off := o.Write([]byte("x")); off != uint64(len(sent)) {
		t.Fatalf("offset after acks: %d", off)
	}
}

func TestOutboxFromIsACopy(t *testing.T) {
	var o Outbox
	o.Write([]byte("abc"))
	got, _ := o.From(0)
	got[0] = 'z'
	again, _ := o.From(0)
	if string(again) != "abc" {
		t.Fatalf("From shares the buffer: %q", again)
	}
}
