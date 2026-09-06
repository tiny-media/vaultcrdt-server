# VaultCRDT — Architecture and sync reference

Server v0.3.1 · Loro 1.13 (lockstep with the plugin) · Rust 1.94 · protocol version 1.

Self-hosted CRDT sync for Obsidian. The server is a passive merger: it holds one Loro document per note, merges client deltas, stores the snapshot, and forwards the client's delta to the other connected clients of the same vault. It has no knowledge of note text beyond the Loro binary.

Plugin-side sections (event wiring, echo suppression, conflict files) describe the client as designed together with this protocol; the plugin repository is the source of truth for its current code.

## Contents

1. [Stack](#stack)
2. [Loro basics](#loro-basics)
3. [Protocol](#protocol)
4. [Server](#server)
5. [Frozen contracts](#frozen-contracts)
6. [Plugin](#plugin)
7. [Echo suppression](#echo-suppression)
8. [Conflict handling](#conflict-handling)
9. [Tests](#tests)

---

## Stack

```
Obsidian (device A)                 Obsidian (device B)
  SyncEngine (TypeScript)             SyncEngine (TypeScript)
    WasmSyncDocument (Loro/WASM)        WasmSyncDocument (Loro/WASM)
          │ WebSocket (MessagePack)           │
          └────────────────┬──────────────────┘
                           ▼
              Rust server (Axum, tokio)
              LoroDoc merge per document
              SQLite (snapshots + version vectors)
```

Each client holds a local `LoroDoc` per file. Edits become CRDT operations, exported as binary deltas and relayed through the server. The server merges with its own `LoroDoc` and stores the resulting snapshot.

---

## Loro basics

| Term | Meaning |
|---|---|
| `LoroDoc` | Container with an `OpLog` (all operations) and `DocState` (materialised state) |
| `LoroText` | Text CRDT inside a `LoroDoc`; every character has a stable position id |
| Version vector (VV) | `Map<PeerId, Counter>`: which ops a peer knows. `PeerId` is the per-device id |
| Operation | Immutable edit with `OpId = (PeerId, Counter)`; operations form a DAG |
| Snapshot | Serialised `LoroDoc` (`ExportMode::Snapshot`), importable by any peer |
| Delta | Only the ops after a given VV (`ExportMode::updates(&vv)`) |

`import()` is idempotent: ops already present are ignored. This is what makes the relay safe to replay.

APIs used by the server:

```rust
let doc = LoroDoc::new();
doc.import(&bytes)?;                                // merge snapshot or delta
doc.oplog_vv();                                     // VersionVector
doc.export(ExportMode::Snapshot)?;                  // full snapshot
doc.export(ExportMode::updates(&client_vv))?;       // delta since client VV
LoroDoc::decode_import_blob_meta(&delta, true)?;    // header only: change_num, start_frontiers
```

Disk → CRDT diffing (plugin, `sync_from_disk`): character-level diff up to 1 KiB of text, word-level diff above. Word-level keeps the op count bounded on long files; convergence is the same.

---

## Protocol

### Wire format

MessagePack over WebSocket. Messages are tagged enums (`#[serde(tag = "type", rename_all = "snake_case")]`, `src/ws.rs`). Byte fields (`delta`, `snapshot`, `client_vv`, `server_vv`) are MessagePack binary.

### HTTP endpoints (`src/lib.rs`)

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | `{status, version, server_epoch, protocol_version}` |
| `POST /auth/verify` | body | `{vault_id, api_key, admin_token?}` → `{token, vault_id}` |
| `GET /ws` | first WS message | sync connection |
| `POST /invite` | vault JWT | create a 15-minute single-use invite for a new device |
| `POST /invite/redeem` | invite token | redeem invite → device key |
| `POST /auth/device` | device key | device key → vault JWT |
| `GET /vault/peers` | vault JWT | peer list of the vault |
| `DELETE /vault/peers/{peer_id}` | admin token | retire one peer (see README) |
| `GET /debug/vault-stats` | vault JWT | doc count, snapshot bytes, largest docs |
| `GET /debug/connections` | admin token | open WS connections |

`/auth/verify` rules:

- Vault exists: `api_key` is verified against the Argon2id hash → token, else 401.
- Vault does not exist and `admin_token` matches `VAULTCRDT_ADMIN_TOKEN` → vault created, token returned.
- Vault does not exist and `admin_token` missing or wrong → 401.

Auth errors are generic. The response does not reveal whether a vault exists. `vault_id` is lowercase letters, digits, `-`, `_`; starts with a letter or digit; at most 64 bytes.

`/auth/verify` and the invite routes are rate limited per client address (10 requests per 60 s window; the limiter fails closed above 65 536 tracked keys). The key is the socket address. When `VAULTCRDT_TRUST_PROXY` is set, the server reads the client address from the header set by a reverse proxy with TLS in front instead. Off by default.

### JWT and `VaultAuth`

- HS256 with `VAULTCRDT_JWT_SECRET`; claims `sub = vault_id`, `exp = now + 3600 s` (`JWT_EXPIRY_SECS`, `src/auth.rs`).
- `VaultAuth` (`src/lib.rs`) is an Axum extractor: reads `Authorization: Bearer <jwt>`, verifies it, yields the `vault_id`. Handlers scoped by `VaultAuth` never see another vault.
- Admin routes compare the bearer token against `VAULTCRDT_ADMIN_TOKEN` in constant time; they do not accept a vault JWT.
- WebSocket: the JWT travels in the first binary message (`auth`), not in the URL.

### WebSocket handshake (`src/ws.rs`)

1. Client opens `GET /ws?device=<name>&peer_id=<id>`.
2. Within 10 s the client sends `auth {token, protocol_version}`. Otherwise the socket closes with `auth_timeout` / `auth_required`.
3. Invalid JWT → close `auth_invalid`.
4. `protocol_version != 1` → `error {code: "protocol_version_mismatch"}` and close.
5. Server replies `auth_ok {protocol_version}` and upserts the peer row (`peers.last_seen_at`).
6. Idle timeout 120 s without a client frame (the plugin pings every 30 s).

### Frame guard

Binary frames above 50 MiB (`MAX_WS_MSG_BYTES = 50 * 1024 * 1024`) are dropped. The server answers `error {code: "frame_too_large"}` and keeps the connection open. The document in that frame is not synced.

### Messages

Client → server:

| Type | Fields | Purpose |
|---|---|---|
| `auth` | `token`, `protocol_version` | first message |
| `ping` | — | heartbeat |
| `request_doc_list` | — | all server docs and tombstones |
| `sync_start` | `doc_uuid`, `client_vv?` | request delta since client VV (`null` = full snapshot) |
| `sync_push` | `doc_uuid`, `delta`, `peer_id` | send own ops |
| `doc_create` | `doc_uuid`, `snapshot`, `peer_id`, `replace_tombstone?` | create a document |
| `doc_delete` | `doc_uuid`, `peer_id` | delete → tombstone |

Server → client:

| Type | Fields | Purpose |
|---|---|---|
| `auth_ok` | `protocol_version` | handshake accepted |
| `pong` | — | heartbeat reply |
| `ack` | — | push/create/delete accepted |
| `error` | `code`, `message` | error |
| `doc_list` | `docs: [{doc_uuid, updated_at, server_vv}]`, `tombstones: [doc_uuid]` | reply to `request_doc_list` |
| `sync_delta` | `doc_uuid`, `delta`, `server_vv` | reply to `sync_start` |
| `doc_unknown` | `doc_uuid` | server has no such document |
| `delta_broadcast` | `doc_uuid`, `delta`, `peer_id`, `server_vv` | another client pushed |
| `doc_deleted` | `doc_uuid` | another client deleted |
| `doc_tombstoned` | `doc_uuid` | push refused: document is tombstoned |
| `create_conflict` | `doc_uuid` | push/create refused: disjoint history |

### Initial sync

```
client                                   server
  request_doc_list ──────────────────────▶
  ◀────────────── doc_list {docs, tombstones}

  per document:
  [server only]  sync_start {vv: null} ──▶   full snapshot back
  [both]         sync_start {vv: local} ─▶   delta since local VV back
                 sync_push {own ops since server_vv}
  [local only]   doc_create {snapshot} ──▶
  [tombstoned]   local file to trash
```

Sync modes on first connect: pull (server docs only), push (local docs only), merge (both). Reconnects use merge. Server-only documents are fetched five at a time; documents with existing local CRDT state are skipped.

### Live sync

```
edit → debounce 700 ms → sync_from_disk → export delta since previous VV
     → sync_push → server merges, stores snapshot, broadcasts the client delta
     → other clients import → apply to editor buffer
```

### VV gap recovery

After every `delta_broadcast` the client checks whether its local VV covers `server_vv`. If not (a lost broadcast), it sends `sync_start` with its local VV. This prevents silent divergence.

---

## Server

### Merge (`src/handlers.rs`)

`sync_push`:

1. If the document is tombstoned → `doc_tombstoned`, nothing stored.
2. If the document exists and the delta has no shared history with the stored VV → `create_conflict`, nothing stored. Predicate: stored VV non-empty, `change_num > 0`, `start_frontiers` empty (`decode_import_blob_meta`). A VV blob that fails to decode counts as disjoint.
3. Otherwise import the stored snapshot, import the delta, export a new snapshot and VV, store both.
4. Broadcast the client's original delta with the new `server_vv`. The delta is not re-exported; forwarding the original bytes preserves causal consistency.

`doc_create`:

1. Tombstoned and `replace_tombstone` false → `doc_tombstoned`.
2. Tombstoned and `replace_tombstone` true → the tombstone is removed after the snapshot is stored, never before.
3. Existing document and disjoint history (no peer id in common between stored VV and incoming VV) → `create_conflict`.
4. Otherwise merge as in `sync_push`.

`sync_start`: unknown document → `doc_unknown`; `client_vv` present → `ExportMode::updates(client_vv)`; absent → stored snapshot.

`doc_delete`: removes the document row and writes a tombstone `(vault_id, doc_uuid, deleted_by, deleted_at)`; broadcasts `doc_deleted`.

`sync_push`, `doc_create` and `doc_delete` on the same `(vault_id, doc_uuid)` are serialised through a per-document async lock (`DocLocks`). The tombstone checks are check-then-act and hold only under this lock.

### Echo suppression (server side)

Broadcasts carry `sender_conn_id`. The forwarding task delivers a `delta_broadcast` or `doc_deleted` only to connections of the same vault whose `conn_id` differs from the sender. A client never receives its own delta back.

### Retention

Hourly background task (`src/main.rs`):

- `expire_tombstones`: deletes tombstones older than `VAULTCRDT_TOMBSTONE_DAYS` (default 365) for which no peer of that vault has `last_seen_at <= deleted_at`. A peer offline since before the deletion keeps the tombstone.
- `expire_stale_peers`: deletes peers with `last_seen_at` older than `VAULTCRDT_PEER_RETENTION_DAYS` (default 365).

Weekly background task: `PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA optimize`. No `VACUUM`; that is a manual step with downtime (`docs/ops-daily.md`).

Tombstones are sticky until retention. There is no server-side resurrection logic; a client that wants a deleted path back sends `doc_create` with `replace_tombstone: true`.

### Storage

SQLite, WAL mode, `synchronous = NORMAL`, pool size `VAULTCRDT_POOL_SIZE` (default 5). Migrations are embedded (`sqlx::migrate!("./migrations")`) and run on startup.

| Migration | Contents |
|---|---|
| `001_init.sql` | `vaults(vault_id PK, api_key, created_at)`, `documents(vault_id, doc_uuid PK, snapshot_blob, vv_blob, updated_at)`, `tombstones(vault_id, doc_uuid PK, deleted_by, deleted_at)` |
| `002_peers.sql` | `peers(vault_id, peer_id PK, device_name, last_seen_at)` |
| `003_invites_device_keys.sql` | `invites(id, vault_id, token_hash, inviter_peer_id, device_name, created_at, expires_at, used_at)`, `device_keys(vault_id, peer_id PK, key_hash, device_name, created_at, revoked_at)` |
| `004` | reserved for the blob (attachment) lane |

`vaults.api_key` holds an Argon2id PHC string. Legacy plaintext entries are upgraded on first successful verification.

`documents.snapshot_blob` is `ExportMode::Snapshot`; `documents.vv_blob` is the Loro-native VV encoding (see below).

Invite tokens are 22 characters of URL-safe alphabet, stored as SHA-256, valid for 15 minutes, single use. Device keys are stored as Argon2id hashes; `POST /auth/device` exchanges a device key for a vault JWT.

---

## Operator CLI

`vaultcrdt-server` doubles as an operator tool inside the container
(docker compose exec). Subcommands run against the same SQLite database
while the server keeps running; no authentication (container exec is the
trust boundary):

- `vault create NAME [--server-url URL] [--json]` — registers a vault,
  generates and prints a 190-bit secret (argon2id at rest, same policy as
  the HTTP path) and, with `--server-url`, the setup link
  `obsidian://vaultcrdt/setup?v=1&server=…&vaultId=NAME`.
- `vault list [--json]` — vault ids and creation times.
- `invite mint VAULT [--server-url URL] [--json]` — mints a one-use
  invite (15-minute TTL, SHA-256 at rest) via the same code path as the
  HTTP route; the setup link carries the token as `&invite=…`.

Exit codes: 0 ok, 1 runtime error, 2 usage, 3 vault exists/not found.
Secrets print on stdout only. Unknown first arguments exit 2 with usage —
a typo never starts a second server against the same database.

## Frozen contracts

Both contracts below are shared between plugin and server. A change on one side without the other breaks sync; the vectors and formats change only by version bump.

### VV serialisation (`src/vv_serde.rs`)

Two formats for two purposes:

| Context | Format | Reason |
|---|---|---|
| Wire (client ↔ server) | JSON: `{"12345":47}` — object keyed by peer id as decimal string, value counter | TypeScript compatible |
| DB (`documents.vv_blob`) | Loro-native binary VV encoding | compact |

```rust
pub fn vv_to_json_bytes(vv: &VersionVector) -> Vec<u8>;              // → b'{"12345":47}'
pub fn vv_from_json_bytes(bytes: &[u8]) -> Result<VersionVector, _>;
pub fn vv_to_db_bytes(vv: &VersionVector) -> Vec<u8>;                // → Loro binary
pub fn vv_from_db_bytes(bytes: &[u8]) -> Result<VersionVector, _>;
```

`client_vv`, `server_vv` and `doc_list.docs[].server_vv` on the wire are always the JSON form. The DB form never leaves the server.

### Blob path key v1 (attachment lane, frozen)

The attachment lane (slices S0–S5, design 2026-09-06) uses its own versioned path key. Like the VV serialisation it is a contract frozen on both sides:

- `path_key = NFC(casefold_full(NFC(path)))`, computed ONLY in the plugin (Rust, `crates/vaultcrdt-core`, WASM export `blob_path_key`).
- `key_version = 1`. The oracle is `docs/blob-path-key-vectors.json`, which lies identically in BOTH repositories (lockstep rule as for Loro). Its header carries the `unicode_version` (reported by `unicode-normalization` 0.1.25: 17.0.0).
- The server computes NO key and has no Unicode dependency. It stores `(path_key, display_path)` and validates only structurally: no ASCII uppercase in the key (cheap sanity check), structure rules, extension whitelist, length. The oracle for the reject cases is the same JSON file.
- A vector changes only as `key_version` 2; old rows stay valid.
- A client that computes the key wrongly creates a second row for the same path → path-local duplicate/ping-pong on correct clients; ASCII paths are immune; nothing breaks at rest (hash addressing).

---

## Plugin

### Event wiring (`main.ts`)

```
editor-change  → guard: !isWritingFromRemote && !isUpdatingEditorFromRemote
               → syncEngine.onFileChanged(path, content)         (debounced 700 ms)
vault.modify   → guard: !isWritingFromRemote → onFileChangedImmediate
vault.create   → guard: !isWritingFromRemote → onFileChangedImmediate
vault.delete   → guard: !isWritingFromRemote → onFileDeleted(path)
vault.rename   → onFileRenamed(oldPath, newPath, content)
window.focus   → fileWatcher.scanForExternalChanges()
```

### State persistence

CRDT state is stored per file as a `.loro` snapshot under `.obsidian/plugins/vaultcrdt/state/`. With a persisted VV a reconnect requests only the missing ops instead of a full snapshot.

### WASM bridge

Loro runs as WASM. The bridge exports: `insert_text`, `delete_text`, `get_text`, `text_matches`, `version`, `export_snapshot`, `import_snapshot`, `sync_from_disk`, `export_vv_json`, `export_delta_since_vv_json`. The WASM binary is inlined as Base64 in `main.js` (esbuild binary loader); no separate fetch.

---

## Echo suppression

Without guards, a remote write on device B fires `editor-change`, which pushes the same content back to the server. Three layers prevent this:

1. **`isWritingFromRemote` guard (`main.ts`)** — `editor-change` and `vault.modify` are ignored for a path while `writeToVault()` runs; the marker is cleared after 500 ms.
2. **Content echo guard (`sync-engine.ts`)** — `lastRemoteWrite: Map<path, content>` is set on every remote write. A push whose content equals that entry is dropped and the entry removed (one shot).
3. **Editor-level apply (`applyToEditor`)** — remote content is written into open editor buffers via `editor.setValue()` with `updatingEditorFromRemote` set, cursor restored and clamped. All editors for the same path are updated. This avoids the "modified externally" dialog and autosave races; Obsidian's autosave persists to disk. If no editor is open for the path, the plugin falls back to `vault.modify()`.

Server side: broadcasts skip the sending connection (see [Server](#echo-suppression-server-side)).

---

## Conflict handling

Loro merges concurrent inserts at the same position deterministically, but two independently written texts merge into interleaved characters. That is correct as a CRDT and useless as a note.

Rule: two histories without a common peer id are never merged.

- Server: `sync_push` and `doc_create` refuse disjoint history with `create_conflict` (see [Merge](#merge-srchandlersrs)).
- Plugin: on `create_conflict`, or when `hasSharedHistory(clientVV, serverVV)` is false, the local content is forked to `<name> (conflict <date>).md`, the server version is adopted for the original path, and the user resolves by hand.

Scenarios: concurrent create (both devices create the same path offline), disjoint VV (both devices edited offline with no shared history).

Deletion: a document tombstoned on the server is not resurrected by a push (`doc_tombstoned`). The plugin renames such a note to `<name> (deleted-remote).md` and syncs it under the new name, or re-creates the original path with `replace_tombstone: true` when the user deleted and re-created locally.

---

## Tests

| Suite | Command |
|---|---|
| Rust (server unit + integration, `src/tests`) | `cargo test --workspace` |
| Plugin (Vitest) | `bun run test` in the plugin repository — not `bun test` |

Raise `ulimit -n 65536` before the full Rust suite.
