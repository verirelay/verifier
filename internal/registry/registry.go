// Package registry verifies Build Records against trusted Release Keys.
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/verirelay/protocol/avr1"
	"github.com/verirelay/verifier/internal/network"
	"github.com/verirelay/verifier/internal/report"
)

const (
	BuildRecordVersion = "verirelay-build-record/1"
	RevocationVersion  = "verirelay-revocation/1"
)

type Statement struct {
	Version     string    `json:"version"`
	Repository  string    `json:"repository"`
	GitCommit   string    `json:"git_commit"`
	GitTag      string    `json:"git_tag"`
	Measurement string    `json:"measurement"`
	CommittedAt time.Time `json:"committed_at"`
}
type RevocationStatement struct {
	Version     string    `json:"version"`
	Repository  string    `json:"repository"`
	GitCommit   string    `json:"git_commit"`
	GitTag      string    `json:"git_tag"`
	Measurement string    `json:"measurement"`
	Reason      string    `json:"reason"`
	RevokedAt   time.Time `json:"revoked_at"`
}
type (
	Proof struct {
		Algorithm     string `json:"algorithm"`
		KeyID         string `json:"key_id"`
		SignedPayload string `json:"signed_payload"`
		Signature     string `json:"signature"`
	}
	Revocation struct {
		Statement RevocationStatement `json:"statement"`
		Proof     Proof               `json:"proof"`
	}
	Record struct {
		Statement  Statement   `json:"statement"`
		Proof      Proof       `json:"proof"`
		Revoked    bool        `json:"revoked"`
		Revocation *Revocation `json:"revocation"`
	}
)

var (
	commitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	hexPattern    = regexp.MustCompile(`^[0-9a-f]+$`)
)

// DecodeKey decodes the canonical unpadded base64url of a raw Ed25519 public key.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errors.New("release key must be the unpadded base64url of a 32-byte Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// KeyID is the proof key_id of a Release Key.
func KeyID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validMeasurement(s string) bool {
	if len(s) > 255 {
		return false
	}
	digest := s
	if algorithm, value, ok := strings.Cut(s, ":"); ok {
		length := map[string]int{"sha256": 64, "sha384": 96, "sha512": 128}[algorithm]
		if length == 0 || len(value) != length {
			return false
		}
		digest = value
	}
	return hexPattern.MatchString(digest) && (len(digest) == 64 || len(digest) == 96 || len(digest) == 128)
}

// canonicalText reports whether s is non-empty, at most limit bytes, and has
// no leading or trailing white space.
func canonicalText(s string, limit int) bool {
	return s != "" && len(s) <= limit && strings.TrimSpace(s) == s
}

// canonicalTime reports whether t is set, in UTC, and has whole microseconds.
func canonicalTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Nanosecond()%int(time.Microsecond) == 0
}

// checkIdentity applies Registry's statement rules. Registry accepts only
// canonical statements, so any other value is invalid.
func checkIdentity(s Statement, version string) error {
	u, err := url.ParseRequestURI(s.Repository)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || !canonicalText(s.Repository, 2048) {
		return errors.New("invalid repository")
	}
	if s.Version != version || !commitPattern.MatchString(s.GitCommit) || !canonicalText(s.GitTag, 255) || !canonicalTime(s.CommittedAt) || !validMeasurement(s.Measurement) {
		return errors.New("invalid build identity")
	}
	return nil
}

// Canonical is Registry's canonical struct JSON of a Build Record statement, not JCS.
func Canonical(s Statement) ([]byte, error) {
	if err := checkIdentity(s, BuildRecordVersion); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func canonicalRevocation(s RevocationStatement) ([]byte, error) {
	if err := checkIdentity(Statement{s.Version, s.Repository, s.GitCommit, s.GitTag, s.Measurement, s.RevokedAt}, RevocationVersion); err != nil {
		return nil, err
	}
	if !canonicalText(s.Reason, 1000) {
		return nil, errors.New("invalid revocation reason")
	}
	return json.Marshal(s)
}

// VerifyProof checks that p signs payload with key; the caller selects key by p.KeyID.
func VerifyProof(payload []byte, p Proof, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || p.Algorithm != "ed25519" || p.KeyID != KeyID(key) {
		return errors.New("proof is not an Ed25519 proof by this key")
	}
	signed, err := avr1.DecodeBase64URL(p.SignedPayload)
	if err != nil || !bytes.Equal(signed, payload) {
		return errors.New("build record signed payload does not match its statement")
	}
	sig, err := avr1.DecodeBase64URL(p.Signature)
	if err != nil || !ed25519.Verify(key, payload, sig) {
		return errors.New("invalid Release Key signature")
	}
	return nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func lookupURL(base, measurement string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
		return "", errors.New("invalid Registry URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/build-records/by-measurement/" + measurement
	return u.String(), nil
}

func rejection(code, reason string) *report.Verdict {
	v := report.Result("fail", code, reason)
	return &v
}

// verifyRecord checks a record whose proof names a key of trusted, the Release Keys by key_id.
func verifyRecord(r Record, trusted map[string]ed25519.PublicKey) *report.Verdict {
	payload, err := Canonical(r.Statement)
	if err != nil || VerifyProof(payload, r.Proof, trusted[r.Proof.KeyID]) != nil {
		return rejection("build_record_invalid", "A Registry Build Record has an invalid identity or trusted Release Key signature.")
	}
	if r.Revocation != nil {
		s := r.Revocation.Statement
		if revocationKey, ok := trusted[r.Revocation.Proof.KeyID]; ok {
			revPayload, err := canonicalRevocation(s)
			if err != nil || s.Repository != r.Statement.Repository || s.GitCommit != r.Statement.GitCommit || s.GitTag != r.Statement.GitTag || s.Measurement != r.Statement.Measurement || VerifyProof(revPayload, r.Revocation.Proof, revocationKey) != nil {
				return rejection("revocation_invalid", "The Registry revocation proof is invalid.")
			}
		}
	}
	if r.Revoked || r.Revocation != nil {
		return rejection("release_revoked", "Registry marks a matching release as revoked; it must not be trusted.")
	}
	return nil
}

// Lookup finds the Build Records of measurement and verifies those signed by one of keys; records under other keys are skipped.
func Lookup(ctx context.Context, client *http.Client, base, measurement string, keys []ed25519.PublicKey) (report.Verdict, *report.Release) {
	trusted := map[string]ed25519.PublicKey{}
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			return report.Result("unable", "release_key_invalid", "A configured Release Key is invalid."), nil
		}
		trusted[KeyID(key)] = key
	}
	address, err := lookupURL(base, measurement)
	if err != nil {
		return report.Result("unable", "registry_url_invalid", "Registry must be an absolute HTTPS URL without credentials, query or fragment; HTTP is allowed only for loopback hosts."), nil
	}
	raw, err := network.Get(ctx, client, address)
	if err != nil {
		return report.Result("unable", "registry_unavailable", "Registry lookup failed: "+err.Error()), nil
	}
	var response struct {
		Items []Record `json:"items"`
		Count int      `json:"count"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return report.Result("unable", "registry_invalid", "Registry returned invalid JSON."), nil
	}
	if response.Count != len(response.Items) {
		return report.Result("unable", "registry_incomplete", "Registry returned an inconsistent result count."), nil
	}
	if len(response.Items) == 0 {
		return report.Result("unable", "measurement_unknown", "No Registry Build Record matches the verified SNP measurement."), nil
	}
	var release *report.Release
	for _, r := range response.Items {
		if r.Statement.Measurement != measurement {
			return report.Result("unable", "registry_invalid", "Registry returned a Build Record for a different measurement."), nil
		}
		if _, ok := trusted[r.Proof.KeyID]; !ok {
			continue
		}
		if invalid := verifyRecord(r, trusted); invalid != nil {
			return *invalid, nil
		}
		if release == nil {
			release = &report.Release{Repository: r.Statement.Repository, Tag: r.Statement.GitTag, Commit: r.Statement.GitCommit}
		}
	}
	if release == nil {
		return report.Result("unable", "release_key_untrusted", "No Registry Build Record of the verified measurement is signed by a trusted Release Key."), nil
	}
	return report.Result("pass", "release_valid", "The verified measurement matches a Build Record signed by a trusted Release Key, and Registry reports it as not revoked.", report.Detail{Code: "release_signature_valid", Message: "Build Record canonical payload and Ed25519 signature verified locally against a trusted Release Key."}, report.Detail{Code: "registry_revocation_checked", Message: "Live Registry revocation status checked. The absence of a revocation is not a signed historical non-revocation proof."}), release
}
