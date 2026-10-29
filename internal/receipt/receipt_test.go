package receipt

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/verirelay/protocol/avr1"
)

func TestEmptyBodiesAndInvalidReceipt(t *testing.T) {
	signer, e := avr1.NewReceiptSignerV1(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))
	if e != nil {
		t.Fatal(e)
	}
	r, e := avr1.BuildSignedReceiptV1(avr1.ReceiptFactsV1{RequestID: "empty", Timestamp: "2026-10-27T00:00:00Z", Method: "GET", UpstreamAuthority: "example.com", SNI: "example.com", UpstreamSPKISHA256: avr1.SHA256Hex([]byte("spki")), UpstreamPath: "/", ResponseStatus: 204, RequestBodySHA256: avr1.SHA256Hex(nil), ResponseBodySHA256: avr1.SHA256Hex(nil)}, signer)
	if e != nil {
		t.Fatal(e)
	}
	if v := Verify(r, []byte{}, []byte{}); v.Status != "pass" {
		t.Fatal(v)
	}
	if v := Verify(r, nil, []byte{}); v.Status != "unable" {
		t.Fatal(v)
	}
	altered := r
	altered.Method = "PUT"
	unsigned := r
	unsigned.Signature = nil
	for _, bad := range []avr1.SignedReceiptV1{{}, altered, unsigned} {
		if v := Verify(bad, []byte{}, []byte{}); v.Status != "fail" || v.Code != "receipt_invalid" {
			t.Fatal(v)
		}
	}
}
