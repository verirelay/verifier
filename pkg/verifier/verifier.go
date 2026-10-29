// Package verifier checks artifacts already held by a user. It never sends proxy requests.
package verifier

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/verirelay/protocol/avr1"
	"github.com/verirelay/verifier/internal/amd"
	"github.com/verirelay/verifier/internal/capture"
	"github.com/verirelay/verifier/internal/receipt"
	"github.com/verirelay/verifier/internal/registry"
	"github.com/verirelay/verifier/internal/report"
)

const DefaultRegistryURL = "https://registry.verirelay.com"

// DefaultReleaseKeys returns the independently pinned Release Keys, never obtained from Registry.
func DefaultReleaseKeys() []ed25519.PublicKey {
	key, _ := registry.DecodeKey("c0quXUfgy8ZYKZA-oXVzEDmU75WuaT2xKx5W-3EHqaI")
	return []ed25519.PublicKey{key}
}

type Inputs struct {
	// Evidence is the required Receipt Evidence Bundle.
	Evidence []byte
	// Capture is a Raw Capture envelope; it is ignored when either body is non-nil.
	Capture  []byte
	StoreID  string
	StoreKey string
	// Nil means absent; an empty non-nil slice is a valid empty body.
	RequestBody  []byte
	ResponseBody []byte
}

type Options struct {
	HTTPClient  *http.Client
	Clock       func() time.Time
	RegistryURL string
	// ReleaseKeys are the trusted Release Keys; empty uses DefaultReleaseKeys.
	ReleaseKeys []ed25519.PublicKey
	// Bootstrap, when non-nil, is the Bootstrap file the CVM must have booted with: HOST_DATA must be its SHA-256.
	Bootstrap []byte
	// Nil enables CRL checks; a pointer to false explicitly disables them.
	CheckRevocations *bool
	Offline          bool
}

type (
	Report       = report.Report
	Verdict      = report.Verdict
	Detail       = report.Detail
	ReceiptFacts = report.ReceiptFacts
	Release      = report.Release
	Bootstrap    = report.Bootstrap
)

func bodyInputs(in Inputs) ([]byte, []byte, *Verdict) {
	if in.Capture == nil || in.RequestBody != nil || in.ResponseBody != nil {
		return in.RequestBody, in.ResponseBody, nil
	}
	id, key := capture.Headers(in.StoreID, in.StoreKey)
	if id == "" || key == "" {
		v := report.Result("unable", "capture_key_missing", "Store-Id and Store-Key are needed to decrypt the body capture.")
		return nil, nil, &v
	}
	request, response, err := capture.Open(in.Capture, id, key)
	if err != nil {
		v := report.Result("unable", "capture_invalid", "The Raw Capture cannot be decrypted: "+err.Error())
		return nil, nil, &v
	}
	return request, response, nil
}

func Verify(ctx context.Context, in Inputs, o Options) Report {
	now := time.Now().UTC()
	if o.Clock != nil {
		now = o.Clock().UTC()
	}
	r := Report{Version: report.Version, GeneratedAt: now.Format(time.RFC3339Nano), Limitations: []Detail{
		{Code: "headers_not_covered", Message: "Receipts cover exact body bytes, not HTTP headers, trailers or wire framing."},
		{Code: "no_liveness", Message: "Archived evidence proves Receipt key binding, not current liveness or trusted exchange time."},
		{Code: "receipt_relative_integrity", Message: "Content integrity is relative to the signed Receipt; hardware and code trust are reported separately."},
	}}
	if o.Offline || (o.CheckRevocations != nil && !*o.CheckRevocations) {
		r.Limitations = append(r.Limitations, Detail{Code: "crl_skipped", Message: "AMD CRL checking was explicitly skipped; current hardware revocation status is unknown."})
	}
	bundle, err := avr1.DecodeReceiptEvidenceBundle(in.Evidence)
	if err != nil {
		r.Content = report.Result("unable", "evidence_invalid", "Cannot parse the Receipt Evidence Bundle: "+err.Error())
		r.Hardware = report.Result("unable", "evidence_invalid", "Valid archived evidence is required.")
		r.Code = r.Hardware
		return r
	}
	request, response, captureVerdict := bodyInputs(in)
	signed := bundle.Receipt
	r.Content = receipt.Verify(signed, request, response)
	if r.Content.Code == "receipt_invalid" {
		r.Hardware = report.Result("unable", "receipt_invalid", "A valid Receipt is required to verify key binding.")
		r.Code = r.Hardware
		return r
	}
	if captureVerdict != nil {
		r.Content = *captureVerdict
	}

	r.Receipt = &ReceiptFacts{RequestID: signed.RequestID, Method: signed.Method, UpstreamHost: signed.UpstreamAuthority, Path: signed.UpstreamPath, Status: signed.ResponseStatus, Time: signed.Timestamp, UpstreamTLSSPKI: signed.UpstreamTLS.SPKISHA256}
	crl := o.CheckRevocations == nil || *o.CheckRevocations
	h := amd.Verify(ctx, bundle.Attestation, signed, amd.Options{Client: o.HTTPClient, Now: now, Offline: o.Offline, CheckRevocations: crl, Bootstrap: o.Bootstrap})
	r.Hardware = h.Verdict
	r.Bootstrap = h.Bootstrap
	if o.Offline {
		r.Code = report.Result("unable", "offline", "Offline mode skips Registry lookup and current revocation status.")
		return r
	}
	if !h.Bound {
		r.Code = report.Result("unable", "measurement_untrusted", "No authenticated, Receipt-bound SNP measurement is available.")
		return r
	}
	keys := o.ReleaseKeys
	if len(keys) == 0 {
		keys = DefaultReleaseKeys()
	}
	base := o.RegistryURL
	if base == "" {
		base = DefaultRegistryURL
	}
	r.Code, r.Release = registry.Lookup(ctx, o.HTTPClient, base, h.Measurement, keys)
	return r
}
