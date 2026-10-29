English | [简体中文](README.zh-CN.md)

# Verifier

Verifier is the local reference verification tool for VeriRelay. It takes evidence you already hold and checks content integrity, build identity and AMD hardware trust separately.

- [CLI reference](docs/cli.md): commands, flags, inputs, report fields and exit codes
- [Development](docs/development.md): checks, release builds and tests
- [Security](SECURITY.md): vulnerability reporting and security scope

## Start

Download the binary for your platform from [Releases](https://github.com/verirelay/verifier/releases) and check it against `SHA256SUMS`.

Binaries are not code-signed, but every release asset has a GitHub artifact attestation, which the GitHub CLI verifies:

```sh
gh attestation verify verifier-linux-amd64 \
  --repo verirelay/verifier \
  --signer-workflow verirelay/verifier/.github/workflows/release.yml
```

```sh
chmod +x verifier-linux-amd64
./verifier-linux-amd64
```

- **macOS**: if a downloaded binary is blocked, run `xattr -d com.apple.quarantine verifier-darwin-arm64` first.
- **From source**: run `make build` and start `./dist/verifier`.

The default command opens an embedded web interface on a random loopback port.

Its URL contains a per-run access token: keep it private, and close Verifier when finished.

Files stay on your device. Only Registry lookups and AMD KDS certificate and CRL requests use the network.

## Bring your evidence

- The Receipt Evidence Bundle returned by `/v1/avr/evidence/<request_id>`: a signed Receipt plus the Attestation Report archived at startup.
- Either the exact request and response body files, or the Raw Capture envelope plus Store-Id and Store-Key. Complete pasted response header lines are accepted.

For the CLI, name body files with `request` and `response`. An empty file is a valid empty body.

## Command line

```sh
verifier check evidence.json request.bin response.bin
verifier check evidence.json capture.json --store-id "$STORE_ID" --store-key "$STORE_KEY"
verifier check evidence.json request.bin response.bin --offline --json
verifier check evidence.json request.bin response.bin --bootstrap bootstrap.json
verifier --offline
verifier -h
```

The trusted Release Key is pinned in the binary, independently of Registry.

`--release-key` replaces it with a key that you trust by other means. Build Records signed by other keys are ignored.

## Understand the result

- **Content**: the Receipt signature is valid and exact body hashes match. This is integrity relative to that Receipt, not an independent claim that a genuine VeriRelay issued it.
- **Code**: the authenticated Launch Measurement matches a Signed Build Record whose signature by a trusted Release Key is verified locally, and Registry does not mark it revoked.
- **Hardware**: the following are checked:
  - VCEK, ASK and independently trusted AMD roots;
  - Attestation Report signature;
  - current CRL;
  - TCB consistency;
  - VMPL;
  - security policy;
  - `REPORT_DATA` key binding.

  Debug, migration agents and CXL are rejected. No minimum firmware advisory baseline is configured.

  When the archived attestation response discloses a Bootstrap, `HOST_DATA` must be its SHA-256, and the report shows the Bootstrap's VeriProv URL, profile and VeriProv Identity Key. `--bootstrap` also requires `HOST_DATA` to be the SHA-256 of the Bootstrap file you expect.

A verdict fails only when the evidence contradicts a check. Input Verifier cannot read, such as a Raw Capture it cannot decrypt or an unsupported format, makes the verdict unable.

- `--offline` makes no network calls and leaves code unable.
- With `--offline`, `--no-crl` or an AMD CRL that cannot be fetched, hardware revocation is unknown, so hardware is unable.
- Without the archived Attestation Report, hardware and code are unable.

AMD's ARK-signed CRL revokes ASK intermediates, not individual VCEKs.

## Boundaries

- Receipts cover bodies, not HTTP headers, trailers or wire framing.
- Upstream TLS SPKI is a signed Receipt fact, not a new live TLS observation.
- Archived evidence proves key binding, not current liveness or trusted historical time.
- Registry's current non-revocation response is not a signed historical non-revocation assertion.

Read all three verdicts.
