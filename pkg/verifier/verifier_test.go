package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-sev-guest/verify/trust"
	"github.com/verirelay/protocol/avr1"
	"github.com/verirelay/verifier/internal/registry"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("../../internal/testdata", name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// otherBootstrap is a valid Bootstrap that no fixture discloses.
var otherBootstrap = []byte(`{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://other.example.com","identity_public_key":"` + b64(make([]byte, 32)) + `"}`)

// mutate returns the fixture evidence with change applied to its attestation.
func mutate(t *testing.T, change func(map[string]any)) []byte {
	t.Helper()
	var bundle map[string]any
	if err := json.Unmarshal(fixture(t, "evidence.json"), &bundle); err != nil {
		t.Fatal(err)
	}
	change(bundle["attestation"].(map[string]any))
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// disclosedBootstrap returns the Bootstrap file disclosed by the fixture evidence.
func disclosedBootstrap(t *testing.T) []byte {
	t.Helper()
	bundle, err := avr1.DecodeReceiptEvidenceBundle(fixture(t, "evidence.json"))
	if err != nil || bundle.Attestation == nil || bundle.Attestation.Bootstrap == "" {
		t.Fatalf("fixture evidence discloses no Bootstrap: %v", err)
	}
	data, err := avr1.DecodeBase64URL(bundle.Attestation.Bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVerification(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	ark, e := x509.ParseCertificate(fixture(t, "amd-ark.der"))
	if e != nil {
		t.Fatal(e)
	}
	ask, e := x509.ParseCertificate(fixture(t, "amd-ask.der"))
	if e != nil {
		t.Fatal(e)
	}
	previous := trust.DefaultRootCerts["Milan"]
	trust.DefaultRootCerts["Milan"] = &trust.AMDRootCerts{ProductLine: "Milan", ProductCerts: &trust.ProductCerts{Ark: ark, Ask: ask}}
	t.Cleanup(func() { trust.DefaultRootCerts["Milan"] = previous })
	sign := func(seed byte, tag string) (ed25519.PublicKey, registry.Record) {
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		public := private.Public().(ed25519.PublicKey)
		statement := registry.Statement{Version: registry.BuildRecordVersion, Repository: "https://github.com/verirelay/release", GitCommit: strings.Repeat("b", 40), GitTag: tag, Measurement: strings.Repeat("0", 96), CommittedAt: now}
		payload, e := registry.Canonical(statement)
		if e != nil {
			t.Fatal(e)
		}
		return public, registry.Record{Statement: statement, Proof: registry.Proof{Algorithm: "ed25519", KeyID: registry.KeyID(public), SignedPayload: b64(payload), Signature: b64(ed25519.Sign(private, payload))}}
	}
	public, record := sign(4, "v1.0.0")
	stranger, foreign := sign(5, "v0.9.0")
	cases := []struct {
		name                    string
		content, code, hardware string
		exit                    int
	}{
		{"all-pass", "pass bodies_match", "pass release_valid", "pass hardware_valid", 0},
		{"capture", "pass bodies_match", "pass release_valid", "pass hardware_valid", 0},
		{"tampered-request", "fail request_mismatch", "pass release_valid", "pass hardware_valid", 1},
		{"tampered-response", "fail response_mismatch", "pass release_valid", "pass hardware_valid", 1},
		{"wrong-key", "unable capture_invalid", "pass release_valid", "pass hardware_valid", 2},
		{"unknown", "pass bodies_match", "unable measurement_unknown", "pass hardware_valid", 2},
		{"revoked", "pass bodies_match", "fail release_revoked", "pass hardware_valid", 1},
		{"bad-signature", "pass bodies_match", "fail build_record_invalid", "pass hardware_valid", 1},
		{"untrusted-key", "pass bodies_match", "unable release_key_untrusted", "pass hardware_valid", 2},
		{"mixed-keys", "pass bodies_match", "pass release_valid", "pass hardware_valid", 0},
		{"registry-http", "pass bodies_match", "unable registry_url_invalid", "pass hardware_valid", 2},
		{"revoked-ask", "pass bodies_match", "unable measurement_untrusted", "fail amd_invalid", 1},
		{"offline", "pass bodies_match", "unable offline", "unable crl_skipped", 2},
		{"no-crl", "pass bodies_match", "pass release_valid", "unable crl_skipped", 2},
		{"null-attestation", "pass bodies_match", "unable measurement_untrusted", "unable attestation_missing", 2},
		{"missing-bodies", "unable bodies_missing", "pass release_valid", "pass hardware_valid", 2},
		{"missing-key", "unable capture_key_missing", "pass release_valid", "pass hardware_valid", 2},
		{"registry-down", "pass bodies_match", "unable registry_unavailable", "pass hardware_valid", 2},
		{"kds-down", "pass bodies_match", "unable measurement_untrusted", "unable amd_unavailable", 2},
		{"bad-binding", "pass bodies_match", "unable measurement_untrusted", "fail binding_invalid", 1},
		{"unsupported-format", "pass bodies_match", "unable measurement_untrusted", "unable attestation_invalid", 2},
		{"bootstrap-mismatch", "pass bodies_match", "pass release_valid", "fail bootstrap_mismatch", 1},
		{"expected-bootstrap", "pass bodies_match", "pass release_valid", "pass hardware_valid", 0},
		{"unexpected-bootstrap", "pass bodies_match", "pass release_valid", "fail bootstrap_unexpected", 1},
		{"invalid-bootstrap", "pass bodies_match", "unable measurement_untrusted", "unable bootstrap_invalid", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := Inputs{Evidence: fixture(t, "evidence.json"), RequestBody: fixture(t, "request.txt"), ResponseBody: fixture(t, "response.txt")}
			options := Options{Clock: func() time.Time { return now }, RegistryURL: "https://registry.test", ReleaseKeys: []ed25519.PublicKey{public}, Offline: tc.name == "offline"}
			switch tc.name {
			case "tampered-request":
				in.RequestBody = []byte("changed")
			case "tampered-response":
				in.ResponseBody = []byte("changed")
			case "null-attestation":
				in.Evidence = fixture(t, "evidence-null.json")
			case "capture", "wrong-key", "missing-key":
				in.Capture = fixture(t, "capture.json")
				in.RequestBody = nil
				in.ResponseBody = nil
				in.StoreKey = string(fixture(t, "store-headers.txt"))
				if tc.name == "wrong-key" {
					in.StoreID = b64(bytes.Repeat([]byte{3}, 16))
					in.StoreKey = b64(bytes.Repeat([]byte{9}, 32))
				}
				if tc.name == "missing-key" {
					in.StoreKey = ""
				}
			case "missing-bodies":
				in.RequestBody = nil
			case "untrusted-key":
				options.ReleaseKeys = []ed25519.PublicKey{stranger}
			case "registry-http":
				options.RegistryURL = "http://registry.test"
			case "no-crl":
				crl := false
				options.CheckRevocations = &crl
			case "bad-binding":
				in.Evidence = mutate(t, func(a map[string]any) { a["nonce"] = b64(bytes.Repeat([]byte{1}, 32)) })
			case "unsupported-format":
				in.Evidence = mutate(t, func(a map[string]any) { a["evidence"].(map[string]any)["format"] = "other/1" })
			case "bootstrap-mismatch":
				in.Evidence = mutate(t, func(a map[string]any) { a["bootstrap"] = b64(otherBootstrap) })
			case "expected-bootstrap":
				options.Bootstrap = disclosedBootstrap(t)
			case "unexpected-bootstrap":
				options.Bootstrap = otherBootstrap
			case "invalid-bootstrap":
				options.Bootstrap = []byte("{}")
			}
			calls := 0
			options.HTTPClient = &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
				calls++
				var data []byte
				switch req.URL.Host {
				case "registry.test":
					if tc.name == "registry-down" {
						return nil, fmt.Errorf("offline fixture")
					}
					if !strings.HasPrefix(req.URL.Path, "/v1/build-records/by-measurement/") {
						t.Fatalf("unexpected Registry call: %s", req.URL)
					}
					r := record
					if tc.name == "bad-signature" {
						r.Proof.Signature = b64(make([]byte, 64))
					}
					if tc.name == "revoked" {
						r.Revoked = true
					}
					items := []registry.Record{r}
					switch tc.name {
					case "unknown":
						items = []registry.Record{}
					case "mixed-keys":
						items = []registry.Record{foreign, r}
					}
					var err error
					data, err = json.Marshal(map[string]any{"items": items, "count": len(items)})
					if err != nil {
						t.Fatal(err)
					}
				case "kdsintf.amd.com":
					if tc.name == "kds-down" {
						return nil, fmt.Errorf("KDS fixture unavailable")
					}
					name := "amd.crl"
					if tc.name == "revoked-ask" {
						name = "amd-revoked.crl"
					}
					data = fixture(t, name)
				default:
					t.Fatalf("forbidden network call: %s", req.URL)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: req}, nil
			})}
			got := Verify(context.Background(), in, options)
			verdicts := []string{got.Content.Status + " " + got.Content.Code, got.Code.Status + " " + got.Code.Code, got.Hardware.Status + " " + got.Hardware.Code}
			if verdicts[0] != tc.content || verdicts[1] != tc.code || verdicts[2] != tc.hardware || got.ExitCode() != tc.exit {
				b, _ := json.MarshalIndent(got, "", "  ")
				t.Fatalf("unexpected report:\n%s", b)
			}
			if tc.name == "offline" && calls != 0 {
				t.Fatalf("offline made %d calls", calls)
			}
			// The fixture discloses a Bootstrap, so its facts appear whenever HOST_DATA binds it.
			if (got.Bootstrap != nil) != (got.Hardware.Status == "pass" || got.Hardware.Code == "crl_skipped" || got.Hardware.Code == "bootstrap_unexpected") {
				t.Fatalf("bootstrap facts %+v with hardware %s", got.Bootstrap, got.Hardware.Code)
			}
			if tc.name == "all-pass" {
				data, err := json.MarshalIndent(got, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, '\n')
				golden(t, "report.golden.json", data)
			}
		})
	}
}

func golden(t *testing.T, name string, data []byte) {
	t.Helper()
	path := filepath.Join("../../internal/testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := fixture(t, name)
	if !bytes.Equal(want, data) {
		t.Fatalf("%s mismatch: got\n%s", name, data)
	}
}

func TestIdentify(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want Kind
	}{
		{"x", `{"version":"avr/1","receipt":{},"attestation":null}`, Evidence},
		{"x", `{"version":"verirelay-raw-capture/1","algorithm":"AES-256-GCM"}`, Capture},
		{"x", `{"version":"avr/1","tee_type":"sev-snp"}`, Unknown},
		{"x", `{"api_version":"avr/1","receipt":{}}`, Unknown},
		{"x", `{"schema":"verirelay.raw_store.v1"}`, Unknown},
		{"request.bin", ``, RequestBody},
		{"response.bin", `a`, ResponseBody},
		{"unknown.bin", ``, Unknown},
		{"headers", "X-VeriRelay-Store-Key: k\n", StoreHeaders},
	} {
		if got := Identify(tc.name, []byte(tc.data)); got != tc.want {
			t.Errorf("%s %s: %s", tc.name, tc.data, got)
		}
	}
}

func TestIdentifyFixtures(t *testing.T) {
	for name, want := range map[string]Kind{"evidence.json": Evidence, "evidence-null.json": Evidence, "capture.json": Capture, "store-headers.txt": StoreHeaders} {
		if got := Identify("x", fixture(t, name)); got != want {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestInvalidAndEmptyEvidence(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(`{"version":"avr/1"}`), []byte(`{"version":"avr/1","receipt":{"version":"avr/1","extra":1}}`), append(fixture(t, "evidence.json"), []byte(`{}`)...)} {
		r := Verify(context.Background(), Inputs{Evidence: data}, Options{Offline: true})
		if r.ExitCode() != 2 || r.Content.Code != "evidence_invalid" || r.Version != "verifier-report/1" {
			t.Fatalf("%+v", r)
		}
	}
}

func TestBundleDecoding(t *testing.T) {
	signer, err := avr1.NewReceiptSignerV1(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	request, response := []byte("request"), []byte("response")
	receipt, err := avr1.BuildSignedReceiptV1(avr1.ReceiptFactsV1{RequestID: "r", Timestamp: "2026-10-27T00:00:00Z", Method: "POST", UpstreamAuthority: "api.example.com", UpstreamPath: "/", SNI: "api.example.com", UpstreamSPKISHA256: avr1.SHA256Hex([]byte("spki")), ResponseStatus: 200, RequestBodySHA256: avr1.SHA256Hex(request), ResponseBodySHA256: avr1.SHA256Hex(response)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	bundle := func(receipt any, extra string) []byte {
		data, err := json.Marshal(map[string]any{"version": "avr/1", "receipt": receipt, "attestation": nil, extra: true})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	altered := receipt
	altered.Method = "PUT"
	for _, tc := range []struct {
		name              string
		evidence          []byte
		content, hardware string
	}{
		{"unknown outer field", bundle(receipt, "future"), "pass bodies_match", "unable attestation_missing"},
		{"altered receipt", bundle(altered, "future"), "fail receipt_invalid", "unable receipt_invalid"},
	} {
		r := Verify(context.Background(), Inputs{Evidence: tc.evidence, RequestBody: request, ResponseBody: response}, Options{Offline: true})
		if r.Content.Status+" "+r.Content.Code != tc.content || r.Hardware.Status+" "+r.Hardware.Code != tc.hardware {
			t.Fatalf("%s: %+v", tc.name, r)
		}
	}
}

func TestPinnedReleaseKey(t *testing.T) {
	keys := DefaultReleaseKeys()
	sum := sha256.Sum256(keys[0])
	if len(keys) != 1 || hex.EncodeToString(sum[:]) != "7d646b0eef9f8fd623b1a12e6b83b1ee061622d96999c9ad3bc813cf8aaf929c" {
		t.Fatal("pinned Release Key changed")
	}
}
