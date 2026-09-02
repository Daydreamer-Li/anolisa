# AgentSecCore V2 foundation contracts and daemon service bring-up

This workspace slice contains the dependency-light contracts shared by later
AgentSecCore V2 Policy and daemon work packages, plus the protocol-independent
Unix-domain-socket service framework and a runnable foreground process bootstrap.
It deliberately contains no daemon wire protocol, persistence implementation,
Policy engine, PAP, Policy runtime, or target Adapter.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy, prepared Policy/Scope/Binding,
  backend-independent IR, and target Adapter contracts.
- `asc-daemon-service`: bounded UDS admission, one-request framing, kernel peer
  credentials, dispatcher/rejection-encoder injection, connection isolation,
  dispatch cancellation, and controlled drain.
- `asc-daemon`: foreground process/bootstrap that installs Unix signal handling,
  selects explicit transport limits, binds an explicitly supplied socket, and
  runs `asc-daemon-service`.

`asc-daemon-service` is a `PARTIAL_MIGRATION` work package. It preserves the V1
one-request-per-connection LF/EOF framing, bounded first-frame read, bounded
connection admission, and socket ownership cleanup. Normal response encoding
belongs to an injected dispatcher; transport rejection encoding belongs to a
separate protocol-only port. Its acceptance type is current-version contract
testing with socket bytes and fake handlers. The V1 Python daemon is discovery
evidence only and is not linked or executed by the Rust runtime.

The service framework does not deserialize a daemon request, generate protocol
request IDs, choose authorization roles, or render protocol errors. The concrete
dispatcher receives a bounded raw request frame and owns method routing. Method
allowlist routing is internal to that one dispatcher implementation; it is not a
second service dispatch layer. A separate `RejectionEncoder` receives typed
transport failures and must remain independent of PAP/Repository state.

The current bootstrap bounds frame read, application dispatch, rejection
encoding, response write, connection drain, and final Tokio runtime shutdown.
Dispatch timeout releases transport capacity and signals cooperative cancellation;
it cannot forcibly stop an application blocking call that ignores that signal.
The framework also cannot prove that a concrete PAP/Repository avoids global
locks; that remains a required direct-consumer concurrency test at integration.

The current `asc-daemon` executable deliberately registers no wire methods. It
can start and exercise the real UDS lifecycle, but it closes complete requests
without a response until the daemon protocol is merged. Socket presence therefore
does not mean application readiness. It also requires an explicit absolute socket
path because packaging-owned system paths, singleton/stale-socket policy, runtime
directory hardening, and readiness remain later process-integration work.

Run the independent transport process in the foreground:

```bash
cargo run -p asc-daemon -- serve --socket /absolute/existing-directory/daemon.sock
```

After protocol integration, the existing daemon handler should implement
`RequestDispatcher` directly and be injected by this bootstrap. A small
protocol-only error encoder implements `RejectionEncoder`. PAP becomes one
registered method family inside the dispatcher; the service framework and
rejection path remain independent of PAP, its compiler, and its repository.

Daemon protocol, client, persistence, and Policy runtime crates belong to later
work packages and are intentionally absent from this slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
