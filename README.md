# VaultCRDT Server

The sync server for the [VaultCRDT Obsidian plugin](https://github.com/tiny-media/vaultcrdt-plugin).

The server receives CRDT operations from connected Obsidian clients over a WebSocket connection, merges them with [Loro](https://loro.dev), and forwards the result to the other connected clients of the same vault. Document snapshots and version vectors are stored in a SQLite database.

This repository contains only the server. The Rust crates that build the WASM module for the plugin live in the [vaultcrdt-plugin](https://github.com/tiny-media/vaultcrdt-plugin) repository under `crates/`.

## Status

Pre-release (0.3.0). The sync protocol and database schema are not stable across versions. Plugin and server are released together. Schema migrations run automatically on startup.

## Requirements

- Docker and Docker Compose, or Rust 1.94 and Cargo to build from source
- A reverse proxy with TLS in front for production use. The server does not handle TLS.

## Running with Docker Compose

The shipped `docker-compose.yml` has no default values for `VAULTCRDT_JWT_SECRET` and `VAULTCRDT_ADMIN_TOKEN`. `docker compose up` fails if either is unset. Copy `.env.example` and fill in random values:

```
cp .env.example .env
# edit .env and set VAULTCRDT_JWT_SECRET and VAULTCRDT_ADMIN_TOKEN
docker compose up -d
```

The server listens on port 8080 inside the container, mapped to `3737` on the host. Data is stored in `./data/` on the host.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `VAULTCRDT_DB_PATH` | no | `/var/lib/vaultcrdt/data.db` | Path to the SQLite database file |
| `VAULTCRDT_BIND` | no | `0.0.0.0:8080` | Address and port to listen on |
| `VAULTCRDT_JWT_SECRET` | yes | — | Secret for signing JWT session tokens |
| `VAULTCRDT_ADMIN_TOKEN` | yes | — | Admin token. Required for vault registration and admin endpoints. Not needed for the CLI. |
| `VAULTCRDT_TOMBSTONE_DAYS` | no | `365` | Days a tombstone is retained before expiry. Expiry is also blocked while a known peer has not been seen since that deletion. |
| `VAULTCRDT_PEER_RETENTION_DAYS` | no | `365` | Days a peer entry is kept after its last connection. After this period the peer no longer blocks tombstone expiry. |
| `RUST_LOG` | no | `info,loro=warn,loro_internal=warn` | `tracing-subscriber` filter. The default keeps per-document operations at `debug` (off) and silences Loro internals. `RUST_LOG=vaultcrdt_server=debug` enables verbose output. |

## Managing vaults

Vaults are created by the operator on the server. The plugin does not
create vaults. All commands run inside the container and use the same
database as the server; the server may keep running.

### First vault, first device

    docker compose exec server vaultcrdt-server vault create family-notes --server-url https://sync.example.com

Prints the vault name, a generated secret and a setup link. The secret
is shown once; store it. It is the vault password for the plugin's
manual setup and the recovery credential if all devices are lost.

Then mint an invite for the first device:

    docker compose exec server vaultcrdt-server invite mint family-notes --server-url https://sync.example.com

Prints an invite (valid 15 minutes, single use) and a setup link
`obsidian://vaultcrdt/setup?...`. Open the link on the device, or render
it as a QR code with any QR tool and scan it with the phone. The device
receives its own device key; the vault secret is not needed on the
device.

### Further devices

From a device that is already synced, use the plugin's *Invite device*
action. It mints an invite and shows a QR code. The server CLI is not
needed.

### Listing vaults

    docker compose exec server vaultcrdt-server vault list

### Scripting

Every command accepts `--json` and prints one JSON value on stdout. Exit
codes: `0` ok, `1` error, `2` usage, `3` vault exists / not found.
Errors go to stderr.

### HTTP alternative

`POST /auth/verify` with `admin_token` still registers a vault with a
chosen password (see ARCHITECTURE). Use the CLI unless you script
against the API.

### Synced devices and retiring old peers

The server stores one peer entry per connected device (`peer_id`, `device_name`, `last_seen_at`). Tombstone expiry uses this list: a tombstone is removed only when no retained peer has `last_seen_at` before or equal to the deletion time. A device that has been offline since before a deletion therefore keeps that tombstone alive.

The current peer list of a vault is available with a vault JWT:

```bash
curl -H "Authorization: Bearer YOUR_VAULT_JWT" \
  https://your-server.example.com/vault/peers
```

A peer row expires after `VAULTCRDT_PEER_RETENTION_DAYS` (default `365`). To stop a specific device from extending tombstone retention earlier, retire it with the admin endpoint below. Do not retire a peer that may return with unsynced local edits.

#### Retiring a single peer (admin)

`DELETE /vault/peers/{peer_id}` removes one device from one vault. It requires the admin token, not a vault JWT, and is confirmation-gated: the exact stored `device_name` must be passed as a query parameter. It does not cross vault boundaries; a peer present in several vaults is retired one vault at a time.

```bash
curl -X DELETE \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  "https://your-server.example.com/vault/peers/PEER_ID?vault_id=my-vault&device_name=My%20Laptop"
```

- **200** — peer removed. The response echoes the retired peer and `tombstones_possibly_freed`, an upper bound of tombstones this peer was blocking (other retained peers may still block the same ones).
- **409** — `device_name` did not match. The body returns the stored `device_name` and `last_seen_at`; nothing was deleted. Repeat with the exact name to confirm.
- **404** — no such peer in this vault. **400** — missing `vault_id` or `device_name`. **401** — missing or wrong admin token.

The next hourly cleanup can then expire tombstones this device was the last to block.

## Building from source

```
cargo build --release -p vaultcrdt-server
```

The binary is at `target/release/vaultcrdt-server`.

## Tests

```
cargo test --workspace
```

## Security model

The server does not perform end-to-end encryption. Document snapshots are stored as plaintext CRDT binaries in SQLite; the server operator can read user data from disk. Vault passwords are hashed with Argon2id before storage. The server sees the user-supplied password only for verification.

Default logs are minimal. Per-document operations (sync_start, sync_push, doc_create, doc_delete, refused tombstone pushes) are emitted at `debug` and stay off. Aggregate events (server start, WS connect/disconnect, request_doc_list counts, maintenance, tombstone expiry, vault registration) are emitted at `info`. With `RUST_LOG=vaultcrdt_server=debug`, document identifiers appear in the logs; treat them as private user data.

- Run behind a reverse proxy with TLS (WSS, not WS).
- Restrict access to the SQLite database file.
- Treat `VAULTCRDT_JWT_SECRET` and `VAULTCRDT_ADMIN_TOKEN` as secrets.
- Keep `RUST_LOG` at the default; raise it deliberately and for a short time.

## Backup and restore

All state is in one SQLite database (`VAULTCRDT_DB_PATH`, default `/var/lib/vaultcrdt/data.db`). With the shipped `docker-compose.yml`, the database lives in `./data/` on the host, next to `data.db-wal` and `data.db-shm` (SQLite WAL mode).

Do not copy `data.db` alone while the server is running. The WAL file may hold committed transactions not yet merged into the main file. Use one of the methods below.

### Online backup with `sqlite3 .backup`

`sqlite3 .backup` is safe while the server is up. Run it inside the container so it uses the same path as the server:

```
docker compose exec server \
  sqlite3 /var/lib/vaultcrdt/data.db ".backup '/var/lib/vaultcrdt/data.db.bak'"

# the backup appears on the host as ./data/data.db.bak — copy it off the host:
cp ./data/data.db.bak /path/to/safe/backup/vaultcrdt-$(date +%F).db
```

The `.db.bak` is a single self-contained file. WAL/SHM files are not needed with it.

### Cold backup (server stopped)

With the server stopped, copy the whole `./data/` directory including `data.db`, `data.db-wal` and `data.db-shm`:

```
docker compose stop server
cp -a ./data /path/to/safe/backup/vaultcrdt-$(date +%F)
docker compose start server
```

### Restore

A restore can make the server state older than one or more clients. Deleted documents are protected by tombstones, and tombstone cleanup waits for retained peers not seen since the deletion. An old backup may still lack recent tombstones, recent peer `last_seen_at` values, or recent edits. Long-offline clients can then offer old content again. Treat a restore as an operational event.

Procedure:

1. Tell users to stop editing and close or pause Obsidian on secondary devices.
2. Stop the server.
3. Replace the database from the backup.
4. Start the server.
5. Open one known-good client first and let it complete initial sync.
6. Open further clients one by one and check for conflict copies or `deleted on another device` warnings.
7. If unexpected notes reappear, keep them under a new name, check Trash and other devices, and reconcile by hand.

```
docker compose stop server
# remove the working DB and any leftover WAL/SHM
rm -f ./data/data.db ./data/data.db-wal ./data/data.db-shm
cp /path/to/safe/backup/vaultcrdt-YYYY-MM-DD.db ./data/data.db
docker compose start server
```

Clients resync from the restored state. CRDT merge keeps newer client edits as long as those clients still hold their local state; a restore can reintroduce deleted or older content if the backup predates the tombstones or edits. Review conflicts and reappearing notes before deleting anything permanently.

## Reverse proxy

The plugin connects over WebSocket (WSS in production). The server must be reachable at a WSS URL, which requires a reverse proxy with TLS in front that forwards the WebSocket upgrade to port 8080 (or the port set in `VAULTCRDT_BIND`).

## Operations

Day-to-day operations, checks and recovery steps are in [docs/ops-daily.md](docs/ops-daily.md):

- Daily: health endpoint, log review, database size
- Weekly: backup verification, peer review, tombstone inventory, growth baseline
- Monthly: manual `VACUUM` (downtime; automatic weekly maintenance is `wal_checkpoint` + `optimize` only), restore drill, dependency updates
- Recovery: unresponsive server, suspected corruption, disk usage

### Health check script

```bash
./scripts/health-check.sh
```

The script checks that `/health` responds, that the database file exists and is readable, that its size is within bounds, and optionally the backup age (`BACKUP_PATH`) and growth against a baseline (`BASELINE_DB_SIZE_MB`). Set `SERVER_URL` and `VAULTCRDT_DB_PATH` before running.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
