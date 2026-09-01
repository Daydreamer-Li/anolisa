# AgentSecCore V2 foundation contracts

This workspace slice contains the dependency-light contracts shared by later
AgentSecCore V2 Policy and daemon work packages. It deliberately contains no
daemon process, persistence implementation, Policy engine, PAP, Policy runtime,
or target Adapter.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy, prepared Policy/Scope/Binding,
  backend-independent IR, and target Adapter contracts.

Daemon protocol, client, process, persistence, and Policy runtime crates belong
to later work packages and are intentionally absent from this foundation slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
