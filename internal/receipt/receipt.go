// Package receipt verifies a signed Receipt and exact body matches.
package receipt

import (
	"github.com/verirelay/protocol/avr1"
	"github.com/verirelay/verifier/internal/report"
)

// Verify checks the field rules and signature of r, then compares the bodies; a nil body is absent.
func Verify(r avr1.SignedReceiptV1, request, response []byte) report.Verdict {
	if err := avr1.VerifySignedReceiptV1(r); err != nil {
		return report.Result("fail", "receipt_invalid", "The Receipt signature or signed fields are invalid.")
	}
	if request == nil || response == nil {
		return report.Result("unable", "bodies_missing", "The Receipt signature is valid, but both body files are needed to compare content.")
	}
	if avr1.SHA256Hex(request) != r.RequestBodySHA256 {
		return report.Result("fail", "request_mismatch", "The request body does not match the signed Receipt.")
	}
	if avr1.SHA256Hex(response) != r.ResponseBodySHA256 {
		return report.Result("fail", "response_mismatch", "The response body does not match the signed Receipt.")
	}
	return report.Result("pass", "bodies_match", "The Receipt signature is valid and both body hashes match.", report.Detail{Code: "signature_valid", Message: "Ed25519 signature verified using avr/1 JCS canonicalization."}, report.Detail{Code: "body_hashes_match", Message: "SHA-256 covers exact body bytes, not HTTP headers or framing."})
}
