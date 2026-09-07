# VaultCRDT Server

VaultCRDT Server is the self-hosted sync companion for the [VaultCRDT Obsidian plugin](https://github.com/tiny-media/vaultcrdt-plugin). It keeps notes and supported attachments in sync between your devices.

It needs only a small host: a 1-CPU home server or a cheap VPS is enough for personal use. It uses SQLite and local files for storage, with no external database to install.

The server sees note text in plaintext. Run it yourself, or let someone you trust run it. End-to-end encryption (E2EE) is not implemented; neither notes nor attachments are encrypted against the server operator.

## For developers

- **axum** — Rust HTTP server on Tokio; see [Stack](docs/ARCHITECTURE.md#stack).
- **SQLite / rusqlite** — bundled SQLite, WAL mode and automatic migrations; see [Storage](docs/ARCHITECTURE.md#storage).
- **Loro snapshots** — note snapshots and version vectors, with delta merging; see [Loro basics](docs/ARCHITECTURE.md#loro-basics).
- **WebSocket fan-out** — MessagePack deltas forwarded within each vault; see [Protocol](docs/ARCHITECTURE.md#protocol).
- **Blob store** — content-addressed, sharded files with SQLite metadata; see [Storage](docs/ARCHITECTURE.md#storage).
- **Device keys** — per-device credentials exchanged for vault JWTs; see [Storage](docs/ARCHITECTURE.md#storage).
- **Invites** — single-use, 15-minute onboarding tokens; see [Operator CLI](docs/ARCHITECTURE.md#operator-cli).
- **Docker image** — published to GHCR for linux/amd64; see [Run it](#run-it) and [Operations](docs/ops-daily.md).

This repository contains only the server. The plugin and its Rust/WASM crates live in the plugin repository. The current server release is v0.4.2, with protocol version 1. Keep plugin and server protocol-compatible; database migrations run automatically on startup.

## Run it

The image is `ghcr.io/tiny-media/vaultcrdt-server:0.4.2`. Set `VAULTCRDT_JWT_SECRET` and `VAULTCRDT_ADMIN_TOKEN` to separate, strong random secrets in your shell before running this command; do not put their values in shell history:

```bash
docker run -d --name vaultcrdt-server --restart unless-stopped \
  -p 127.0.0.1:3737:8080 \
  -v vaultcrdt-data:/var/lib/vaultcrdt \
  -e VAULTCRDT_JWT_SECRET -e VAULTCRDT_ADMIN_TOKEN \
  ghcr.io/tiny-media/vaultcrdt-server:0.4.2

curl http://127.0.0.1:3737/health
```

`GET /health` needs no authentication. It returns `status`, the server `version`, a per-start `server_epoch`, `protocol_version: 1`, and `features: ["invite", "device_keys", "blobs"]`.

The server listens on port 8080 in the container. The volume holds the SQLite database and blob files. For remote access, put a TLS reverse proxy in front of the loopback port and forward WebSocket upgrades for `/ws`; the server itself does not provide TLS.

A step-by-step Compose guide for a home server or 1-CPU VPS is planned.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VAULTCRDT_JWT_SECRET` | required | Signs one-hour vault session tokens |
| `VAULTCRDT_ADMIN_TOKEN` | required | Authorizes HTTP vault registration and admin endpoints; not needed by the CLI |
| `VAULTCRDT_DB_PATH` | `./vaultcrdt.db`; image: `/var/lib/vaultcrdt/data.db` | SQLite database file |
| `VAULTCRDT_BIND` | `0.0.0.0:8080` | Listen address |
| `VAULTCRDT_BLOB_DIR` | `/var/lib/vaultcrdt/blobs` | Blob files and upload staging directory |
| `VAULTCRDT_DEFAULT_VAULT_QUOTA` | `5368709120` (5 GiB) | Default blob quota per vault, in bytes; `0` means unlimited |
| `VAULTCRDT_TOMBSTONE_DAYS` | `365` | Minimum note tombstone retention; retained peers can block expiry |
| `VAULTCRDT_PEER_RETENTION_DAYS` | `365` | Retention after a peer's last connection |
| `VAULTCRDT_TRUST_PROXY` | off | Trusts `CF-Connecting-IP` for auth rate limiting when nonempty and not `0` or `false`; enable only behind a trusted proxy that controls this header |
| `RUST_LOG` | `info,loro=warn,loro_internal=warn` | Log filter |

Blob path limits match the plugin: 10 MiB for images and PDFs, 25 MiB for audio, and 2 MiB for allowlisted `.obsidian` files. Only selected settings, snippets and theme files are allowed under `.obsidian`; workspace and plugin files are excluded. See [Storage](docs/ARCHITECTURE.md#storage) for the allowlist.

## Managing vaults

The operator CLI opens the same SQLite database as the server and can run while the server is running. It does not require a JWT or admin token: local database access is the trust boundary. When running outside Docker, set `VAULTCRDT_DB_PATH` to the server's database and use the same default quota configuration.

### Create a vault

```bash
docker exec vaultcrdt-server vaultcrdt-server vault create family-notes \
  --server-url https://sync.example.com
```

Prints the vault name and a generated 32-character secret. Store the secret securely: it is shown once and cannot be recovered. It is the vault password for manual setup and recovery. The optional `--server-url` adds a setup URI containing the server URL and vault name, **not** the secret.

Vault names use lowercase letters, digits, hyphens and underscores, start with a letter or digit, and are at most 64 bytes.

### Mint an invite

```bash
docker exec vaultcrdt-server vaultcrdt-server invite mint family-notes \
  --server-url https://sync.example.com
```

Prints a single-use invite and its expiry (15 minutes). With `--server-url`, it also prints an `obsidian://vaultcrdt/setup?...` link carrying the invite. Open it on the new device, or render it with a QR tool. Redemption gives the device its own key; it does not need the vault secret. An authenticated device can also request an invite through `POST /invite`.

### List vaults and set blob quotas

```bash
docker exec vaultcrdt-server vaultcrdt-server vault list
docker exec vaultcrdt-server vaultcrdt-server vault quota family-notes 1073741824
```

`vault list` shows names, creation times, stored quotas and effective quotas. `vault quota NAME BYTES` sets the blob quota; `0` means unlimited and `default` restores the environment default.

### Scripting

All four commands accept `--json` and print one JSON value on stdout. `vault create` returns `vault_id` and `secret`; `invite mint` returns `vault_id`, `invite` and `expires_at`. With `--server-url`, both also return `server_url` and `setup_uri`. `vault list` returns an array including `quota_bytes` and `effective_quota_bytes`; `vault quota` returns those fields for one vault. Treat secret and invite output as credentials.

Exit codes: `0` success, `1` runtime error, `2` usage error, `3` vault already exists or was not found. Errors go to stderr. `help`, `--help` and `-h` show usage; no arguments starts the server. Unknown first arguments exit with usage instead of starting a server.

`POST /auth/verify` can also register a vault using an admin token and a chosen password; see [HTTP endpoints](docs/ARCHITECTURE.md#http-endpoints-srclibrs).

## Security and peers

Vault passwords and device keys are stored as Argon2id hashes; invite tokens are stored as SHA-256 hashes. Protect the database, blob directory, backups and operator credentials. TLS protects transport, not data from the operator.

Default logs suppress per-document debug events, but authentication and operational logs can include vault or peer identifiers. Enabling `RUST_LOG=vaultcrdt_server=debug` also exposes document identifiers; use it briefly and redact logs before sharing.

Note deletions leave tombstones with content hashes when available. Hourly cleanup removes old tombstones only if no retained peer has `last_seen_at <= deleted_at`. Long-offline peers therefore delay expiry until they reconnect or their peer row expires.

`GET /vault/peers` lists peers with a vault JWT. The admin endpoint `DELETE /vault/peers/{peer_id}?vault_id=...&device_name=...` requires the exact stored device name, removes the peer and revokes its device key. It does not invalidate already-issued JWTs. Do not retire a device that may return with unsynced edits. See [peer operations](docs/ops-daily.md#peers).

## Backup and restore

Back up **both** SQLite and `VAULTCRDT_BLOB_DIR`. A database-only backup does not contain attachments. For a consistent full backup, stop the server and copy the database, any remaining `-wal`/`-shm` files, and the entire blob directory together. The image defaults keep them in the same data volume.

SQLite's `.backup` is safe online for the database alone; copying `data.db` alone while running is not, because committed writes may still be in the WAL. See [backup operations](docs/ops-daily.md#backup).

### Restore

Pause clients before restoring. Stop the server, restore a matching database and blob directory, and remove stale working WAL/SHM files before installing a standalone SQLite backup. Start the server, sync one known-good client first, then reconnect others one at a time.

An older backup can lack recent edits, tombstones and attachments. CRDT merge can preserve newer client edits, but cannot make an old backup complete; deleted notes may reappear. Review conflict copies and unexpected files before deleting anything permanently.

## Building and testing

The manifest requires Rust 1.95 or newer; `rust-toolchain.toml` pins 1.98.1 for local builds.

```bash
cargo build --release -p vaultcrdt-server
ulimit -n 65536
cargo test
```

The binary is `target/release/vaultcrdt-server`. For a source install, choose writable database and blob paths and set the two required secrets before starting it.

## Operations

See [docs/ops-daily.md](docs/ops-daily.md) for health checks, peer retirement, maintenance and recovery. `scripts/health-check.sh` checks health and database storage, with optional backup-age and growth checks; it is not a blob backup integrity check.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
