// Package capture opens Raw Capture envelopes with a pasted Store-Id and Store-Key.
package capture

import (
	"errors"
	"strings"

	"github.com/verirelay/protocol/avr1"
)

// Headers returns the Store-Id and Store-Key, taking them from response header lines when either value contains some.
func Headers(id, key string) (string, string) {
	for _, line := range strings.Split(strings.ReplaceAll(id+"\n"+key, "\r", ""), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "store-id", "x-verirelay-store-id":
			id = strings.TrimSpace(value)
		case "store-key", "x-verirelay-store-key":
			key = strings.TrimSpace(value)
		}
	}
	return strings.TrimSpace(id), strings.TrimSpace(key)
}

// Open decrypts a Raw Capture envelope and returns the request and response bodies.
func Open(data []byte, id, key string) ([]byte, []byte, error) {
	id, key = Headers(id, key)
	envelope, err := avr1.DecodeRawCapture(data)
	if err != nil {
		return nil, nil, err
	}
	k, err := avr1.DecodeBase64URL(key)
	if err != nil || len(k) != avr1.RawCaptureKeySize {
		return nil, nil, errors.New("Store-Key must be an unpadded base64url 32-byte key")
	}
	return avr1.OpenRawCapture(k, id, envelope)
}
