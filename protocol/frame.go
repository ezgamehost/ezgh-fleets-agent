package protocol

import (
	"encoding/binary"
	"errors"
)

// EncodeData makes a binary session frame: an 8-byte big-endian byte offset, then the payload.
func EncodeData(offset uint64, p []byte) []byte {
	return append(binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(p)), offset), p...)
}

// DecodeData splits a binary session frame. The payload aliases b.
func DecodeData(b []byte) (offset uint64, p []byte, err error) {
	if len(b) < 8 {
		return 0, nil, errors.New("data frame shorter than its 8-byte offset")
	}
	return binary.BigEndian.Uint64(b), b[8:], nil
}
