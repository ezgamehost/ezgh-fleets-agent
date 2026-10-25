package protocol

import (
	"errors"
	"sync"
)

// ErrGap means the bytes asked for were dropped (or never sent), so the stream can't resume.
var ErrGap = errors.New("resume offset outside the buffer")

// Outbox keeps the last ResumeBuffer unacknowledged bytes sent on a session stream, so they
// can be resent from the peer's resume offset. Writes never block: past ResumeBuffer the oldest
// bytes are dropped. The zero value is ready to use and safe for concurrent use.
type Outbox struct {
	mu   sync.Mutex
	base uint64 // stream offset of buf[0]
	buf  []byte
}

// Write appends p and returns the stream offset of its first byte.
func (o *Outbox) Write(p []byte) (offset uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	offset = o.base + uint64(len(o.buf))
	o.buf = append(o.buf, p...)
	if over := len(o.buf) - ResumeBuffer; over > 0 {
		o.drop(over)
	}
	return offset
}

// Ack frees every byte before offset.
func (o *Outbox) Ack(offset uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if offset <= o.base {
		return
	}
	o.drop(int(min(offset-o.base, uint64(len(o.buf)))))
}

// From returns a copy of the bytes from offset to the end.
func (o *Outbox) From(offset uint64) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if offset < o.base || offset > o.base+uint64(len(o.buf)) {
		return nil, ErrGap
	}
	return append([]byte(nil), o.buf[offset-o.base:]...), nil
}

// drop reslices; append reallocates once capacity runs out, copying only the live bytes.
func (o *Outbox) drop(n int) {
	o.buf = o.buf[n:]
	o.base += uint64(n)
}
