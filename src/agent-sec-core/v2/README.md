# AgentSecCore V2 foundation contracts and daemon service framework

This workspace slice contains the dependency-light contracts shared by later
AgentSecCore V2 Policy and daemon work packages, plus the protocol-independent
Unix-domain-socket service framework. It deliberately contains no daemon binary,
daemon wire protocol, persistence implementation, Policy engine, PAP, Policy
runtime, or target Adapter.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy, prepared Policy/Scope/Binding,
  backend-independent IR, and target Adapter contracts.
- `asc-daemon-service`: bounded UDS admission, one-request framing, kernel peer
  credentials, dispatcher injection, connection isolation, and controlled drain.

`asc-daemon-service` is a `PARTIAL_MIGRATION` work package. It preserves the V1
one-request-per-connection LF/EOF framing, bounded first-frame read, bounded
connection admission, and socket ownership cleanup, while leaving all response
encoding to an injected dispatcher. Its acceptance type is current-version
contract testing with socket bytes and a fake dispatcher. The V1 Python daemon is
discovery evidence only and is not linked or executed by the Rust runtime.

The service framework does not deserialize a daemon request, generate protocol
request IDs, choose authorization roles, or render protocol errors. The later
protocol adapter receives either a bounded raw request frame or a typed service
rejection and owns those decisions. The later `asc-daemon` composition root owns
signals, singleton/stale-socket policy, system paths, concrete adapters,
readiness, and process observability.

Daemon protocol, client, binary/bootstrap, persistence, and Policy runtime crates
belong to later work packages and are intentionally absent from this slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
