# AGENTS.md — vaultcrdt-server

Rust/Axum + SQLite sync server for VaultCRDT. Plugin, WASM and CRDT crates
live in the separate repo `../vaultcrdt-plugin`. Global behaviour rules live
The maintainer's global development rules apply; this file carries only
what differs for this repo.

## Checks (gate before every commit)

- `cargo fmt --all -- --check`, `cargo clippy --workspace --locked -- -D warnings`,
  `cargo test --workspace --locked` (as in CI); `ulimit -n 65536` first for the full suite.
- Rust Edition 2024, MSRV 1.94 (toolchain pinned in `rust-toolchain.toml`).

## Hard invariants

- Auth errors stay generic; no vault enumeration.
- Tombstones sticky until retention; no server-side resurrection logic.
- Loro bumps always in lockstep with `../vaultcrdt-plugin`; same for
  `docs/blob-path-key-vectors.json` and the protocol version.
- Migrations are append-only: `001`–`003` taken, `004` reserved for the blob lane.
- No deploy, restart, DB or infrastructure step without the maintainer's explicit release.
- No secrets, JWT/admin tokens, DB or vault contents in files or answers.
- One slice per run; no drive-by refactors, no new dependency without an order.
  Worker runs never commit; the executing session commits after checks exit 0.
