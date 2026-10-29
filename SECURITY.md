# Security policy

## Reporting a vulnerability

Report vulnerabilities privately to the maintainers. If the repository Security tab offers **Report a vulnerability**, use that private reporting channel.

## Scope

Verifier checks:

- archived evidence;
- signed Receipts;
- body integrity;
- the Attestation Report (certificate chain, signature, policy, TCB, key binding and the `HOST_DATA` binding of the Bootstrap);
- Signed Build Records from Registry;
- current revocation status.

Any of these is in scope:

- a false pass;
- leaked Store-Key/body;
- local API bypass;
- unexpected network destination;
- unsafe artifact handling.

The local web interface listens only on loopback, behind a random per-run path token and Host and Origin checks. Do not share its URL, and do not run untrusted local software while processing sensitive files.

The trusted Release Key is pinned independently of Registry and may be explicitly replaced by a set of keys the caller trusts. Build Records signed by any other key are ignored.

AMD trust anchors come from go-sev-guest, never the uploaded certificate chain.

Redirects are refused. AMD certificates and CRLs are fetched only from AMD KDS HTTPS URLs. Registry is reached only over HTTPS, except on loopback hosts.

Synthetic test fixtures and their AES keys are public test material, not production credentials.

Issues in VeriRelay itself belong to the VeriRelay repository.

## Limits

- Receipts do not cover HTTP headers.
- Content integrity alone is relative to the supplied Receipt.
- Archived evidence does not prove liveness, a trusted historical timestamp, current firmware advisory compliance or Upstream TLS identity beyond what the Receipt signer states.
- No minimum firmware advisory baseline is configured.
- AMD CRLs revoke ASK intermediates, not individual VCEK serials.
- Offline or disabled CRL checking cannot establish current revocation status.
- Registry non-revocation is an online observation, not a signed historical assertion.
