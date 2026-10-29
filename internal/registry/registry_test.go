package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// decodeVector decodes a base64 value of the Release vector, which need not use the Registry's encoding.
func decodeVector(t *testing.T, s string) []byte {
	t.Helper()
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b
		}
	}
	t.Fatalf("invalid base64 in vector: %q", s)
	return nil
}

func TestReleaseVector(t *testing.T) {
	raw, err := os.ReadFile("../testdata/registry-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicKey string `json:"public_key"`
		Canonical string `json:"canonical"`
		Record    struct {
			Statement Statement `json:"statement"`
			Signature string    `json:"signature"`
		} `json:"record"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	key, err := DecodeKey(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Canonical(vector.Record.Statement)
	if err != nil || string(payload) != vector.Canonical {
		t.Fatalf("canonical mismatch: %s (%v)", payload, err)
	}
	signature := decodeVector(t, vector.Record.Signature)
	proof := Proof{Algorithm: "ed25519", KeyID: KeyID(key), SignedPayload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)}
	if err := VerifyProof(payload, proof, key); err != nil {
		t.Fatal(err)
	}
	// Registry stores only canonical statements, so Verifier rewrites nothing.
	for name, mutate := range map[string]func(*Statement){
		"empty version":         func(s *Statement) { s.Version = "" },
		"padded repository":     func(s *Statement) { s.Repository += " " },
		"uppercase commit":      func(s *Statement) { s.GitCommit = strings.ToUpper(s.GitCommit) },
		"padded tag":            func(s *Statement) { s.GitTag = " " + s.GitTag },
		"uppercase measurement": func(s *Statement) { s.Measurement = strings.ToUpper(s.Measurement) },
		"non-UTC time":          func(s *Statement) { s.CommittedAt = s.CommittedAt.In(time.FixedZone("offset", 3600)) },
		"sub-microsecond time":  func(s *Statement) { s.CommittedAt = s.CommittedAt.Add(999 * time.Nanosecond) },
	} {
		s := vector.Record.Statement
		mutate(&s)
		if _, err := Canonical(s); err == nil {
			t.Fatalf("%s: accepted a non-canonical statement", name)
		}
	}
	padded := proof
	padded.Signature = base64.StdEncoding.EncodeToString(signature)
	invalid := proof
	invalid.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	for _, p := range []Proof{padded, invalid} {
		if err := VerifyProof(payload, p, key); err == nil {
			t.Fatalf("accepted proof %+v", p)
		}
	}
}

type signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newSigner(seed byte) signer {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return signer{private, private.Public().(ed25519.PublicKey)}
}

func (s signer) proof(payload []byte) Proof {
	return Proof{Algorithm: "ed25519", KeyID: KeyID(s.public), SignedPayload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, payload))}
}

func (s signer) record(t *testing.T, statement Statement) Record {
	t.Helper()
	payload, err := Canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	return Record{Statement: statement, Proof: s.proof(payload)}
}

var now = time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)

func statement(measurement string) Statement {
	return Statement{Version: BuildRecordVersion, Repository: "https://example.com/release", GitCommit: strings.Repeat("b", 40), GitTag: "v1", Measurement: measurement, CommittedAt: now}
}

func TestRevocationProof(t *testing.T) {
	release, other := newSigner(7), newSigner(8)
	trusted := map[string]ed25519.PublicKey{KeyID(release.public): release.public}
	s := statement(strings.Repeat("a", 96))
	record := release.record(t, s)
	if v := verifyRecord(record, trusted); v != nil {
		t.Fatal(v)
	}
	revocation := RevocationStatement{Version: RevocationVersion, Repository: s.Repository, GitCommit: s.GitCommit, GitTag: s.GitTag, Measurement: s.Measurement, Reason: "security issue", RevokedAt: now}
	data, err := canonicalRevocation(revocation)
	if err != nil {
		t.Fatal(err)
	}
	record.Revocation = &Revocation{Statement: revocation, Proof: release.proof(data)}
	if v := verifyRecord(record, trusted); v == nil || v.Code != "release_revoked" {
		t.Fatalf("signed revocation not rejected: %+v", v)
	}
	record.Revocation.Statement.Reason = "altered"
	if v := verifyRecord(record, trusted); v == nil || v.Code != "revocation_invalid" {
		t.Fatalf("altered revocation not rejected: %+v", v)
	}
	record.Revocation.Proof = other.proof(data)
	if v := verifyRecord(record, trusted); v == nil || v.Code != "release_revoked" {
		t.Fatalf("revocation under an untrusted key not treated as revoked: %+v", v)
	}
}

func TestLookup(t *testing.T) {
	release, stranger := newSigner(7), newSigner(8)
	measurement := strings.Repeat("a", 96)
	good := release.record(t, statement(measurement))
	other := statement(measurement)
	other.GitTag = "v2"
	foreign := stranger.record(t, other)
	forged := good
	forged.Proof.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	elsewhere := release.record(t, statement(strings.Repeat("c", 96)))
	for _, tc := range []struct {
		name  string
		items []Record
		keys  []ed25519.PublicKey
		want  string
	}{
		{"trusted", []Record{good}, []ed25519.PublicKey{release.public}, "pass release_valid"},
		{"untrusted skipped", []Record{foreign, good}, []ed25519.PublicKey{release.public}, "pass release_valid"},
		{"several trusted keys", []Record{good}, []ed25519.PublicKey{stranger.public, release.public}, "pass release_valid"},
		{"only untrusted", []Record{foreign}, []ed25519.PublicKey{release.public}, "unable release_key_untrusted"},
		{"bad trusted signature", []Record{foreign, forged}, []ed25519.PublicKey{release.public}, "fail build_record_invalid"},
		{"bad untrusted signature", []Record{forged, foreign}, []ed25519.PublicKey{stranger.public}, "pass release_valid"},
		{"other measurement", []Record{elsewhere}, []ed25519.PublicKey{release.public}, "unable registry_invalid"},
		{"none", []Record{}, []ed25519.PublicKey{release.public}, "unable measurement_unknown"},
		{"invalid key", []Record{good}, []ed25519.PublicKey{{1}}, "unable release_key_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/build-records/by-measurement/"+measurement {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"items": tc.items, "count": len(tc.items)})
			}))
			defer server.Close()
			v, found := Lookup(context.Background(), nil, server.URL, measurement, tc.keys)
			if got := v.Status + " " + v.Code; got != tc.want || (found != nil) != (v.Status == "pass") {
				t.Fatalf("got %s %+v", got, found)
			}
		})
	}
}

func TestInvalidIdentities(t *testing.T) {
	old := statement(strings.Repeat("a", 96))
	old.Version = "verirelay-build-record/v1"
	for _, s := range []Statement{{}, {Version: "other"}, old} {
		if _, err := Canonical(s); err == nil {
			t.Fatal("accepted invalid identity")
		}
	}
	for _, value := range []string{
		"",
		"bad",
		"AA==",
		"v3i+paaE4tA24JpjAjfphAIl5Nu3ekFO6UOjnKzqYRY=",
		"v3i-paaE4tA24JpjAjfphAIl5Nu3ekFO6UOjnKzqYRY=",
		"v3i-paaE4tA24JpjAjfphAIl5Nu3ekFO6UOjnKzqYRZ",
		" v3i-paaE4tA24JpjAjfphAIl5Nu3ekFO6UOjnKzqYRY\n",
	} {
		if _, err := DecodeKey(value); err == nil {
			t.Fatalf("accepted invalid key %q", value)
		}
	}
	if _, err := DecodeKey("v3i-paaE4tA24JpjAjfphAIl5Nu3ekFO6UOjnKzqYRY"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "http://user@example.com", "https://example.com?x=1", "https://example.com#x", "file:///tmp/a", "http://example.com", "http://127.0.0.1.example.com", "ftp://127.0.0.1"} {
		if _, err := lookupURL(value, strings.Repeat("a", 96)); err == nil {
			t.Fatalf("accepted invalid Registry URL %q", value)
		}
	}
	for _, value := range []string{"https://example.com", "https://example.com/base/", "http://127.0.0.1:8080", "http://localhost:1", "http://[::1]:2"} {
		if _, err := lookupURL(value, strings.Repeat("a", 96)); err != nil {
			t.Fatalf("rejected Registry URL %q", value)
		}
	}
}
