// Package amd validates archived SNP evidence against independently trusted AMD roots.
package amd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/verirelay/protocol/avr1"
	"github.com/verirelay/protocol/guest"
	"github.com/verirelay/verifier/internal/network"
	"github.com/verirelay/verifier/internal/report"
)

type Options struct {
	Client           *http.Client
	Now              time.Time
	Offline          bool
	CheckRevocations bool
	// Bootstrap, when non-nil, is the Bootstrap file whose SHA-256 HOST_DATA must equal.
	Bootstrap []byte
}

type Result struct {
	Measurement string
	Bound       bool
	// Bootstrap describes the Bootstrap bound by HOST_DATA, when one is known.
	Bootstrap *report.Bootstrap
	Verdict   report.Verdict
}

type getter struct {
	ctx         context.Context
	client      *http.Client
	now         time.Time
	unavailable bool
}

func (g *getter) Get(address string) ([]byte, error) { return g.GetContext(g.ctx, address) }
func (g *getter) GetContext(_ context.Context, address string) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host != "kdsintf.amd.com" || u.User != nil {
		return nil, errors.New("only AMD KDS HTTPS URLs are allowed")
	}
	data, err := network.Get(g.ctx, g.client, address)
	if err != nil {
		g.unavailable = true
		return nil, err
	}
	if strings.HasSuffix(u.Path, "/crl") {
		crl, err := x509.ParseRevocationList(data)
		if err != nil {
			return nil, err
		}
		if crl.ThisUpdate.After(g.now) || !crl.NextUpdate.After(g.now) {
			g.unavailable = true
			return nil, errors.New("AMD CRL is not current")
		}
	}
	return data, nil
}

func failed(code, reason string) Result {
	return Result{Verdict: report.Result("fail", code, reason)}
}

func unable(code, reason string) Result {
	return Result{Verdict: report.Result("unable", code, reason)}
}

// evidence is a parsed attestation response.
type evidence struct {
	attestation *spb.Attestation
	public      ed25519.PublicKey
	nonce       []byte
	// bootstrap is the disclosed Bootstrap file, nil when none is disclosed.
	bootstrap []byte
	facts     *report.Bootstrap
}

// Verify checks a. Input it cannot read is unable; evidence that contradicts r, the AMD roots, the policy or a Bootstrap fails.
func Verify(ctx context.Context, a *avr1.AttestationResponse, r avr1.SignedReceiptV1, o Options) Result {
	var expected *report.Bootstrap
	if o.Bootstrap != nil {
		facts, err := bootstrapFacts(o.Bootstrap)
		if err != nil {
			return unable("bootstrap_invalid", "The expected Bootstrap file is invalid: "+err.Error())
		}
		expected = facts
	}
	if a == nil {
		return unable("attestation_missing", "The archived attestation is missing; hardware and key binding cannot be verified.")
	}
	e, err := parse(a)
	if err != nil {
		return unable("attestation_invalid", "The archived attestation cannot be read: "+err.Error())
	}
	att := e.attestation
	reportData, err := bind(a, r, e)
	if err != nil {
		return failed("binding_invalid", "The archived attestation does not bind the signed Receipt: "+err.Error()+".")
	}
	if info, err := abi.ParseSignerInfo(att.GetReport().GetSignerInfo()); err != nil || info.SigningKey != abi.VcekReportSigner {
		return unable("signer_unsupported", "Only VCEK-signed SEV-SNP evidence is supported.")
	}
	options := verify.DefaultOptions()
	options.Now = o.Now
	options.CheckRevocations = o.CheckRevocations && !o.Offline
	options.DisableCertFetching = o.Offline
	options.TrustedRoots = roots()
	g := &getter{ctx: ctx, client: o.Client, now: o.Now}
	options.Getter = g
	if err := verify.SnpAttestationContext(ctx, att, options); err != nil {
		if g.unavailable {
			return unable("amd_unavailable", "AMD certificates or a current CRL could not be obtained.")
		}
		return failed("amd_invalid", "AMD certificate, report signature or revocation verification failed: "+err.Error())
	}
	vmpl := 0
	policy := &validate.Options{GuestPolicy: abi.SnpPolicy{SMT: true}, ReportData: reportData, VMPL: &vmpl}
	if err := validate.SnpAttestation(att, policy); err != nil {
		return failed("policy_rejected", "TCB consistency or security policy failed: "+err.Error())
	}
	result := Result{Measurement: hex.EncodeToString(att.Report.Measurement), Bound: true}
	details := []report.Detail{{Code: "amd_chain_valid", Message: "VCEK and the SNP report verify against embedded AMD roots, not supplied trust anchors."}, {Code: "binding_valid", Message: "REPORT_DATA binds the archived nonce and the Receipt signing key."}, {Code: "policy_valid", Message: "VMPL 0; debug, migration agents and CXL forbidden; TCB relationships checked. No minimum firmware advisory baseline is configured."}}
	hostData := att.Report.GetHostData()
	if e.bootstrap != nil {
		if !bound(e.bootstrap, hostData) {
			result.Verdict = report.Result("fail", "bootstrap_mismatch", "HOST_DATA in the Attestation Report is not the SHA-256 of the disclosed Bootstrap.")
			return result
		}
		result.Bootstrap = e.facts
		details = append(details, report.Detail{Code: "bootstrap_valid", Message: "HOST_DATA is the SHA-256 of the disclosed Bootstrap."})
	}
	if o.Bootstrap != nil {
		if !bound(o.Bootstrap, hostData) {
			result.Verdict = report.Result("fail", "bootstrap_unexpected", "HOST_DATA in the Attestation Report is not the SHA-256 of the expected Bootstrap file.")
			return result
		}
		result.Bootstrap = expected
		details = append(details, report.Detail{Code: "bootstrap_expected", Message: "HOST_DATA is the SHA-256 of the expected Bootstrap file."})
	}
	if !options.CheckRevocations {
		details = append(details, report.Detail{Code: "crl_skipped", Message: "AMD CRL checking was skipped; revocation status is unknown."})
		result.Verdict = report.Result("unable", "crl_skipped", "The hardware signature and key binding are valid, but revocation was not checked.", details...)
	} else {
		details = append(details, report.Detail{Code: "crl_valid", Message: "Current ARK-signed CRL checked for ASK revocation. AMD does not enumerate individual VCEK revocations."})
		result.Verdict = report.Result("pass", "hardware_valid", "AMD certificate chain, report signature, CRL, policy and key binding checks passed.", details...)
	}
	return result
}

func bound(bootstrap, hostData []byte) bool {
	sum := guest.HostData(bootstrap)
	return bytes.Equal(sum[:], hostData)
}

func bootstrapFacts(data []byte) (*report.Bootstrap, error) {
	b, err := guest.DecodeBootstrap(data)
	if err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &report.Bootstrap{URL: b.URL, Profile: b.Profile, IdentityPublicKey: b.IdentityPublicKey}, nil
}

func roots() map[string][]*trust.AMDRootCerts {
	result := map[string][]*trust.AMDRootCerts{}
	for line, r := range trust.DefaultRootCerts {
		result[line] = []*trust.AMDRootCerts{{ProductLine: r.GetProductLine(), ProductCerts: r.ProductCerts, AskSev: r.AskSev, ArkSev: r.ArkSev}}
	}
	return result
}

func validFormat(a *avr1.AttestationResponse) bool {
	return a.Version == avr1.AVRVersion && a.TEEType == avr1.AttestationTEETypeSEVSNP && a.Evidence.Format == avr1.AttestationEvidenceFormat && a.Endorsements.Format == avr1.AttestationEndorsementsFormat && a.Endorsements.Encoding == avr1.AttestationEndorsementsEncoding && a.Endorsements.VLEK == ""
}

func validBinding(kb avr1.AttestationKeyBinding) bool {
	return kb.Rule == avr1.AttestationBindingRuleV1 && kb.ProtocolVersion == avr1.AVRVersion && kb.SignatureAlgorithm == avr1.AVRSignatureAlgorithm && kb.ReportDataEncoding == avr1.AttestationReportDataEncoding && kb.PublicKeyEncoding == avr1.AttestationPublicKeyEncoding && kb.NonceEncoding == avr1.AttestationNonceEncoding
}

// parse decodes the attestation response without judging whether its claims hold.
func parse(a *avr1.AttestationResponse) (evidence, error) {
	if !validFormat(a) || !validBinding(a.KeyBinding) {
		return evidence{}, errors.New("unsupported attestation format or key binding declaration")
	}
	public, err := avr1.DecodeEd25519PublicKeyBase64URL(a.ReceiptSigningPublicKey)
	if err != nil {
		return evidence{}, err
	}
	nonce, err := avr1.DecodeNonceBase64URL(a.Nonce)
	if err != nil {
		return evidence{}, err
	}
	raw, err := avr1.DecodeBase64URL(a.Evidence.Report)
	if err != nil || len(raw) != avr1.AttestationReportSize {
		return evidence{}, fmt.Errorf("evidence.report must be base64url of %d bytes", avr1.AttestationReportSize)
	}
	parsed, err := abi.ReportToProto(raw)
	if err != nil {
		return evidence{}, err
	}
	chain := new(spb.CertificateChain)
	for _, pair := range []struct {
		name, value string
		dst         *[]byte
	}{{"vcek", a.Endorsements.VCEK, &chain.VcekCert}, {"ask", a.Endorsements.ASK, &chain.AskCert}, {"ark", a.Endorsements.ARK, &chain.ArkCert}} {
		if pair.value == "" {
			continue
		}
		value, err := avr1.DecodeBase64URL(pair.value)
		if err != nil {
			return evidence{}, fmt.Errorf("endorsements.%s %w", pair.name, err)
		}
		*pair.dst = value
	}
	att := &spb.Attestation{Report: parsed, CertificateChain: chain}
	if parsed.GetCpuid1EaxFms() == 0 && len(chain.VcekCert) > 0 {
		// Reports before version 3 carry no CPUID, so the VCEK names the product.
		if att.Product, err = vcekProduct(chain.VcekCert); err != nil {
			return evidence{}, err
		}
	}
	e := evidence{attestation: att, public: public, nonce: nonce}
	if a.Bootstrap != "" {
		if e.bootstrap, err = avr1.DecodeBase64URL(a.Bootstrap); err != nil {
			return evidence{}, fmt.Errorf("bootstrap %w", err)
		}
		if e.facts, err = bootstrapFacts(e.bootstrap); err != nil {
			return evidence{}, err
		}
	}
	return e, nil
}

func vcekProduct(der []byte) (*spb.SevProduct, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("endorsements.vcek: %w", err)
	}
	exts, err := kds.VcekCertificateExtensions(cert)
	if err != nil {
		return nil, fmt.Errorf("endorsements.vcek: %w", err)
	}
	return kds.ParseProductName(exts.ProductName, abi.VcekReportSigner)
}

// bind checks that the attestation binds the Receipt's signing key and returns the expected REPORT_DATA.
func bind(a *avr1.AttestationResponse, r avr1.SignedReceiptV1, e evidence) ([]byte, error) {
	if a.ReceiptSigningPublicKey != r.ServicePublicKey || a.KeyID != r.KeyID || a.KeyID != avr1.ReceiptKeyID(e.public) {
		return nil, errors.New("the archived key is not the Receipt signing key")
	}
	expected, err := avr1.ReportDataAVR1(e.public, e.nonce)
	if err != nil {
		return nil, err
	}
	want := hex.EncodeToString(expected[:])
	if !bytes.Equal(e.attestation.Report.ReportData, expected[:]) || a.Evidence.ReportData != want || a.KeyBinding.ReportDataSHA512 != want {
		return nil, errors.New("REPORT_DATA does not bind the archived nonce and the Receipt signing key")
	}
	return expected[:], nil
}
