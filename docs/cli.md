English | [简体中文](cli.zh-CN.md)

# CLI reference

## Commands

- `verifier [options]` opens the embedded local web interface.
- `verifier version` prints its version.
- `verifier -h` prints help.

```text
verifier check FILE... [options]
```

`check` flags may appear before or after files. `--` ends flag parsing.

These options apply to both the web interface and `check`:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--registry URL` | `https://registry.verirelay.com` | Registry base URL |
| `--release-key KEY` | Independently pinned key | Trusted Release Key as an unpadded base64url raw Ed25519 public key |
| `--offline` | Off | No network; code and hardware unable |
| `--no-crl` | Off | Skip AMD CRL; hardware unable |

- `--registry` takes an HTTPS URL, or HTTP for a loopback host. Redirects are not followed.
- `--release-key` replaces the pinned key. Repeat it to trust several.

These options apply only to `check`:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--store-id VALUE` | Empty | Store-Id or pasted header lines |
| `--store-key VALUE` | Empty | Store-Key or pasted header lines |
| `--bootstrap FILE` | None | Expected Bootstrap file; `HOST_DATA` must be its SHA-256 |
| `--json` | Off | Emit JSON instead of human-readable output |

## Inputs

| Input | Identified by |
| --- | --- |
| Receipt Evidence Bundle (required) | JSON structure |
| Raw Capture envelope | JSON structure |
| Request body | Filename contains `request` or `请求` |
| Response body | Filename contains `response` or `响应` |
| Store-Id and Store-Key | Text file containing Store-Key header lines |

Unknown files and duplicate input types are usage errors. Supplied body files take precedence over Raw Capture.

The Receipt Evidence Bundle and Raw Capture are decoded by the rules in [`avr/1` Receipts](https://github.com/verirelay/protocol/blob/main/docs/avr1.md), section "Decoding".

## Report

`--json` output and web interface exports use `verifier-report/1`:

| Field | Content |
| --- | --- |
| `version` | `verifier-report/1` |
| `generated_at` | RFC 3339 UTC generation time |
| `content`, `code`, `hardware` | The three verdicts |
| `receipt` | Receipt facts, present when the Receipt is valid: `request_id`, `method`, `upstream_host`, `path`, `status`, `time`, `upstream_tls_spki` |
| `release` | Matching build identity, present when code passes: `repository`, `tag`, `commit` |
| `bootstrap` | The Bootstrap bound by `HOST_DATA`, present when the attestation response discloses it or `--bootstrap` supplies it: `url`, `profile` (empty when absent), `identity_public_key` |
| `limitations` | Verification boundaries, as a list of `code` and `message` |

Each verdict has these fields:

| Field | Content |
| --- | --- |
| `status` | `pass`, `fail` or `unable` |
| `code` | Stable result code |
| `reason` | English reason |
| `details` | Individual checks, as a list of `code` and `message` |

`status` is one of:

- `pass`;
- `fail` when the evidence contradicts a check;
- `unable` when a check cannot be completed, including input that cannot be read.

Reports do not contain body bytes or Store-Key.

## Release Key and Bootstrap results

| Case | Verdict | Code |
| --- | --- | --- |
| Build Record whose `proof.key_id` is not a trusted Release Key | Skipped | |
| No Build Record of the measurement is signed by a trusted Release Key | Code unable | `release_key_untrusted` |
| A Build Record or revocation under a trusted Release Key has an invalid signature | Code fails | `build_record_invalid`, `revocation_invalid` |
| `HOST_DATA` is not the SHA-256 of the disclosed `bootstrap` | Hardware fails | `bootstrap_mismatch` |
| `HOST_DATA` is not the SHA-256 of the `--bootstrap` file | Hardware fails | `bootstrap_unexpected` |
| The `--bootstrap` file is not a valid Bootstrap | Hardware unable | `bootstrap_invalid` |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All three verdicts pass |
| `1` | Any verdict fails; this takes precedence |
| `2` | Any verdict is unable, or a usage, file IO or output error occurred |

[Overview](../README.md)
