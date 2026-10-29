# Contributing

Before opening a pull request, run the [checks](docs/development.md#checks) that CI runs.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

The cross-repo contracts are:

- the `avr/1` Receipt, attestation response, Receipt Evidence Bundle and Raw Capture formats (defined in [Protocol](https://github.com/verirelay/protocol/blob/main/docs/avr1.md));
- the Bootstrap (defined in [Protocol](https://github.com/verirelay/protocol/blob/main/docs/guest.md));
- Registry Build Records;
- the `verifier-report/1` format.

Coordinate contract changes with the affected repositories.

Verifier must remain artifact-only: never add fetching from VeriRelay, request forwarding or Receipt polling.
