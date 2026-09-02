# AgentSecCore V2 Policy and daemon foundations

This workspace slice contains the dependency-light contracts, Policy
Administration Point, protocol-independent Unix-domain-socket service framework,
and runnable foreground process bootstrap used by later AgentSecCore V2 work
packages. It deliberately contains no daemon wire protocol, concrete persistence
or Policy compiler, Policy runtime, reconciliation worker, outbox, or target
Adapter.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy and immutable prepared Policy/Scope/Binding specs,
  backend-independent IR, and target Adapter contracts.
- `asc-pap`: transport-independent Policy/Scope revision CRUD and Binding
  spec/lifecycle CRUD over explicit compiler and repository ports.
- `asc-daemon-service`: bounded UDS admission, one-request framing, kernel peer
  credentials, dispatcher/rejection-encoder injection, connection isolation,
  dispatch cancellation, and controlled drain.
- `asc-daemon`: foreground process/bootstrap that installs Unix signal handling,
  selects explicit transport limits, binds an explicitly supplied socket, and
  runs `asc-daemon-service`.

## Daemon service boundary

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

## Binding spec and lifecycle boundary

`PreparedBinding` is immutable content. The pair
`(binding_id, binding_revision)` identifies exactly one complete Policy/Scope
spec and must never be reused for different content. Mutable status is
deliberately outside that spec:

- `BindingStatus` contains only the lifecycle state; it carries no duplicated
  Binding ID or revision.
- `BindingView { spec, status }` joins one immutable spec with its status for
  GET/LIST responses.
- `bindingRevision` changes only for different immutable content. Lifecycle
  transitions do not manufacture a new spec revision.

All legal lifecycle states are shared in `asc-policy-types::binding`, next to
`PreparedBinding`, so PAP, the future outbox, and the future reconciler use one
contract:

| State | Meaning | Written by | Terminal without a new request? |
|---|---|---|---|
| `PENDING_APPLY` | Apply request accepted but not claimed | PAP | no |
| `APPLYING` | Apply work claimed and running | reconciler | no |
| `READY` | referenced spec applied successfully | reconciler | yes, success |
| `APPLY_FAILED` | Apply permanently failed or exhausted retries | reconciler | yes, failure |
| `PENDING_DELETE` | Delete request accepted but not claimed | PAP | no |
| `DELETING` | detach work claimed and running | reconciler | no |
| `DELETED` | detach completed successfully | reconciler | yes, success |
| `DELETE_FAILED` | detach permanently failed or exhausted retries | reconciler | yes, failure |

“Terminal” means that no automatic transition remains. A later user request can
still move lifecycle from a terminal state to a new pending state.

The successful creation path is:

```text
none --CREATE--> PENDING_APPLY --claim--> APPLYING --success--> READY
```

The successful deletion path is:

```text
apply-side state --DELETE--> PENDING_DELETE --claim--> DELETING --success--> DELETED
```

The complete legal transition set is:

| Current | Event | Next | Spec revision rule |
|---|---|---|---|
| none | CREATE valid spec | `PENDING_APPLY` | allocate revision 1 |
| `PENDING_APPLY`, `APPLYING`, `READY` | UPDATE identical spec | no-op | unchanged |
| `APPLY_FAILED`, `PENDING_DELETE`, `DELETING`, `DELETED`, `DELETE_FAILED` | UPDATE identical spec | `PENDING_APPLY` | unchanged |
| any state | UPDATE changed spec | `PENDING_APPLY` | allocate next revision |
| `PENDING_APPLY`, `APPLYING`, `READY`, `APPLY_FAILED` | DELETE | `PENDING_DELETE` | unchanged |
| `PENDING_DELETE`, `DELETING`, `DELETED` | DELETE | no-op | unchanged |
| `DELETE_FAILED` | DELETE retry | `PENDING_DELETE` | unchanged |
| `PENDING_APPLY` | worker claim | `APPLYING` | unchanged |
| `APPLYING` | success | `READY` | unchanged |
| `APPLYING` | retryable failure | `PENDING_APPLY` | unchanged |
| `APPLYING` | permanent/retry-exhausted failure | `APPLY_FAILED` | unchanged |
| `PENDING_DELETE` | worker claim | `DELETING` | unchanged |
| `DELETING` | success | `DELETED` | unchanged |
| `DELETING` | retryable failure | `PENDING_DELETE` | unchanged |
| `DELETING` | permanent/retry-exhausted failure | `DELETE_FAILED` | unchanged |

There are no other legal transitions. In particular, UPDATE received while an
older Delete is `PENDING_DELETE` or `DELETING` moves lifecycle to
`PENDING_APPLY`. DELETE received while Apply is pending or running follows the
symmetric rule.

Repositories persist immutable specs and mutable status separately. A new spec
revision and its initial status form one transaction; a status-only transition
does not rewrite spec content. Status CAS APIs identify the target explicitly by
`binding_id` and `binding_revision` and require the expected current status, so
the read model does not need to duplicate those fields. The PAP
revision-allocation wrapper carries `last_allocated_revision` plus status, not a
duplicate spec.

The shared state machine is defined and tested now, but the PAP-only phase
implements no outbox, dispatcher, or reconciler. Therefore
PAP writes only `PENDING_APPLY` and `PENDING_DELETE`; nothing in this phase
advances them. TODO(policy-reconciliation): persist each request transition and
its reconcile intent atomically; define the operation ordering/CAS token needed
to reject stale results and ABA; then implement claim, retry, completion,
failure, restart recovery, and cancellation using the transitions above.

Daemon protocol, client, concrete persistence/compiler, Policy runtime,
reconciliation worker, outbox, and target Adapter belong to later work packages
and are intentionally absent from this slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
