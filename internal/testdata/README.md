# Test artifacts

The fixtures the tests read, and how to regenerate them.

| File | Contents |
| --- | --- |
| `evidence.json` | Receipt Evidence Bundle with an archived attestation response, from VeriRelay's evidence endpoint. Its version 3 Milan Attestation Report is signed by the synthetic AMD chain, and it discloses a synthetic Bootstrap whose SHA-256 is the report's `HOST_DATA` |
| `evidence-null.json` | The same Receipt Evidence Bundle with `attestation` set to `null` |
| `request.txt`, `response.txt` | Exact request and response bodies covered by the Receipt |
| `capture.json` | Raw Capture envelope of those bodies, encrypted by VeriRelay |
| `store-headers.txt` | Store-Id and Store-Key header lines for `capture.json` |
| `amd-ark.der`, `amd-ask.der` | Synthetic AMD ARK and ASK certificates of the Attestation Report's certificate chain |
| `amd.crl`, `amd-revoked.crl` | ARK-signed CRLs; the second revokes the ASK |
| `registry-vector.json` | Registry Build Record canonicalization vector, including HTML escaping and Unicode, with a public test key and signature |
| `report.golden.json` | Expected report for the all-pass case |
| `cli.golden.txt`, `cli-pass.golden.txt` | Expected human-readable CLI output |
| `generate_server_fixtures.go.txt` | Generator for the VeriRelay-produced files |

All files are public synthetic test material. The fixture AES key is not a credential, `registry-vector.json` is not a production Build Record, and these AMD roots must never be installed in production. Tests use a fixed clock; the fixture CRLs expire and must not be accepted at the current time.

## Regenerate the VeriRelay fixtures

1. In a disposable VeriRelay checkout, copy `generate_server_fixtures.go.txt` to `internal/proxy/verifier_v2_fixture_test.go`. The generator discloses that checkout's `internal/attestation/testdata/guest-manifest.json`.
2. Make sure the output directory exists, then run:

   ```sh
   VERIFIER_FIXTURE_DIR=/absolute/path/to/verifier/internal/testdata go test ./internal/proxy -run '^TestGenerateVerifierV2Fixtures$' -v
   ```

3. Capture nonces and report signatures may change; decrypted bodies and verification facts stay the same. Update the report and CLI goldens only when their expected facts change, as described in [docs/development.md](../../docs/development.md).

`registry-vector.json` is copied verbatim from Release's [`scripts/testdata/registry-vector.json`](https://github.com/verirelay/release/blob/main/scripts/testdata/registry-vector.json).
