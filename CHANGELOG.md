# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.2] - 2026-09-06

### Changed

- Loro 1.13.9 -> 1.16.0 (lockstep with the plugin): atomic imports with
  rollback (a failed import no longer detaches a document), concurrent
  updates to shallow roots reject instead of panicking, faster
  out-of-order imports, bounded decoded-value cache.
- sqlx -> rusqlite 0.40.2 (bundled SQLite 3.53.2): one connection per
  process (structurally avoids the multi-connection WAL race class),
  migrations via user_version with one-shot adoption of existing sqlx
  migration state, dependency count 321 -> 263.
- Toolchain 1.98.1 (toolchain + CI); Docker image deliberately stays
  rust:1.95.0-alpine3.23 until a 1.98.1-alpine tag exists (1.98.0
  carries a vtable miscompilation).
- Dependency refresh (axum 0.8.9, tokio 1.53.1 and patch lines);
  compose gains init: true and stop_grace_period 20s.


## [0.3.1] - 2026-09-06

### Added

- Operator CLI: `vaultcrdt-server vault create NAME [--server-url URL]
  [--json]`, `vault list [--json]`, `invite mint VAULT [--server-url URL]
  [--json]` — runs against the same database as the running server, no auth
  (container exec is the trust boundary). Prints a generated 190-bit secret
  (argon2id at rest) and the `obsidian://vaultcrdt/setup?...` link; invite
  mint reuses the server's token logic (15-minute TTL, single use,
  SHA-256 at rest). Unknown first arguments exit 2 with usage instead of
  starting a second server.
- README: CLI-first self-hoster trail (first vault, first device, further
  devices via the plugin's invite screen).

### Changed

- Docs rewritten in terse English (README, ARCHITECTURE, ops handbook);
  frozen contracts (VV serialisation, blob path key v1) unchanged.

## [0.2.14] - 2026-09-06

### Changed
- Loro 1.13.9 (lockstep with plugin 0.4.5): snapshot-import checksum
  validation (hardens stored blobs), checkout-hang fix after snapshot
  import, faster concurrent-replay base; compat proven by roundtrip of
  1.13.6 blobs and re-verified U43 frontier predicate.
- jsonwebtoken 11 (breaking APIs unused — no source changes).
- Dependency round: argon2 0.6.0 stable, patch bumps.

### Changed
- Update jsonwebtoken from 10.4.0 to 11.0.0; retain HS256 signing and default validation with one-hour token expiry.

## [0.2.13] - 2026-09-05

### Fixed
- `sync_push` refuses deltas whose history begins at the empty frontier
  when the stored doc already has history — the last text-doubling path
  (device-proven twice in RUN-B3 S7: a loser's independent create arrived
  as a sync_push delta and was merged). Replies `create_conflict`; the
  shipped client conflict-copies and adopts. Predicate verified against
  the loro-1.13.6 sources (decode_import_blob_meta start_frontiers) and
  an empirical probe: legitimate incrementals (adopted-doc first edit,
  same-peer edits, shallow snapshots) never refuse; empty deltas never
  refuse (U43).

- sync_push refuses deltas whose history starts from the empty frontier into an existing doc with `create_conflict` (server-side twin of U38).

## [0.2.12] - 2026-09-05

### Changed
- WebSocket authentication now uses a first-frame `auth { token, protocol_version }` handshake answered by `auth_ok`. URL-token and Bearer-header authentication are removed; unauthenticated sockets close with 1008 after a bad/missing first frame or 10 seconds.
- Protocol version is 1; mismatches receive `error { code: "protocol_version_mismatch" }` then close. `/health` reports `protocol_version`.
- Error frames carry stable `code` values and generic client text (U09). Internals stay in server logs except decoder details that could echo raw client bytes: these use fixed text and byte length. JSON rejection responses and logs are sanitised too.
- Oversized-frame `error.message` is unchanged.

### Fixed
- Refuse `doc_create` with disjoint histories or corrupt stored version vectors via `create_conflict { doc_uuid }`, without changing the stored document or broadcasting.

## [0.2.11] - 2026-09-05

### Security
- Admin-token comparisons are constant-time (Bench-C U06, A4.2 minimum).
- `POST /auth/verify` is rate-limited: 10 requests per 60 s per client
  (429), checked before body parsing. Client identity is `CF-Connecting-IP`
  when `VAULTCRDT_TRUST_PROXY` is set (a trusted Cloudflare front sets it
  authoritatively), else the socket address; `X-Forwarded-For` is never
  trusted. The key map is bounded (65 536 entries, fail-closed).
- `create_vault` honours `rows_affected`: a lost registration race falls
  back to key verification instead of silently proceeding (Bench-C U04).

## [0.2.10] - 2026-09-05

### Fixed
- `doc_create` mit `replace_tombstone` verwarf zuvor eine noch lebende Server-Version
  (Last-Write-Wins, Datenverlust bei nebenläufigen Recreates); das Flag greift jetzt nur
  bei tatsächlich getombstoneten Dokumenten (Bench-C U07).
- `doc_delete` löscht Dokument-Zeile und schreibt den Tombstone in einer Transaktion
  (`delete_doc_and_tombstone`) — kein Zwischenzustand mit nur einem der beiden mehr
  (Bench-C U03/U08).
- Frames über 50 MiB werden nicht mehr still verworfen; der Client erhält jetzt eine
  Error-Antwort statt dauerhaftem stillen Desync (Bench-C U18).
- `DocLocks`-Map wächst nicht mehr unbegrenzt: ungenutzte Einträge werden beim nächsten
  `get` evakuiert (Bench-C U01).
- JWT-Fehler liefern jetzt `401 Unauthorized` statt `500` mit JWT-Detailtext (Bench-C U26).

## [0.2.9] - 2026-07-07

### Added
- Operations runbook (`docs/ops-daily.md`) with daily/weekly/monthly checks and
  `scripts/health-check.sh` for automated health verification, including an
  optional DB-growth guard (`BASELINE_DB_SIZE_MB`) and a documented restore drill.
- `DELETE /vault/peers/{peer_id}` retires a single device from a vault's peer
  retention. Admin-token auth, vault-scoped (`?vault_id=` required), and
  confirmation-gated via `?device_name=` (mismatch returns the stored name and
  `last_seen_at`). Reports an upper-bound `tombstones_possibly_freed` hint.

### Changed
- Weekly database maintenance no longer runs a blocking `VACUUM`. It now runs
  `PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA optimize`; full `VACUUM` is a
  manual, downtime-aware maintenance-window step (`db::run_full_vacuum`).
- Updated Loro to 1.13.6 (lockstep with plugin 0.4.0) and refreshed transitive dependencies.

### Removed
- Blob schema/policy module removed from `main` — parked on `feat/blob-schema-policy`
  until the attachment wave (A3). Fresh installs no longer create blob tables.

## [0.2.8] - 2026-06-06

### Added
- Tombstone cleanup now waits for retained peers that have not been seen since a deletion.
- `VAULTCRDT_PEER_RETENTION_DAYS` documents when old devices are considered retired.

### Changed
- Updated Loro to 1.13, SQLx to 0.9.0, jsonwebtoken to 10.4.0 and compatible transitive dependencies.
- Restore and peer-retention documentation now explains resurrection risk from long-offline devices.

## [0.2.7] - 2026-05-01

### Changed
- Raise the WebSocket idle timeout to 120 seconds for more mobile reconnect headroom.
- Keep per-document server logs at debug level by default and suppress Loro internal noise.
- Document private-deployment tombstone retention, backup/restore, operator access, and Docker restart behavior.
- Install `sqlite` in the runtime image so the documented SQLite backup command works inside the container.

## [0.2.6] - 2026-04-08

### Changed
- Release flow: tag-pushed `v*` now runs a dedicated `release.yml` workflow
  (cargo fmt/clippy/test + auto-generated GitHub Release notes) instead of
  relying on manually created Release entries. The existing `docker.yml`
  workflow (GHCR image publish) is unchanged.

Note: CHANGELOG entries for 0.2.2..0.2.5 were skipped; see the corresponding
GitHub Releases for details.

## [0.2.1] - 2026-03-24

### Changed
- Rename user-facing terminology: "Registration Key" → "Admin Token", "API Key" → "Vault Secret"
- Accept `device` query parameter on WebSocket connect for human-readable server logs
- Store device name in connection tracking for future presence feature

## [0.2.0] - 2026-03-19

### Changed
- Reduced WebSocket idle timeout from 300s to 60s for faster cleanup of stale connections
- Replaced `lock().unwrap()` with `lock().expect()` for clearer panic messages on mutex poisoning

### Added
- WebSocket message size limit (50 MB) to prevent malicious oversized payloads
- Configurable SQLite connection pool size via `VAULTCRDT_POOL_SIZE` environment variable (default: 5)
- `.env.example` with documented configuration options

## [0.1.0] - 2026-03-15

### Added
- Initial release
- WebSocket-based CRDT sync server using Loro
- SQLite storage with WAL mode
- JWT authentication with vault isolation
- MessagePack binary protocol
- Real-time delta broadcasting
- Document tombstones with automatic expiry
- Multi-arch Docker image with cargo-chef caching
- Health and debug endpoints
