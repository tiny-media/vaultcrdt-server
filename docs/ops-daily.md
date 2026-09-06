# VaultCRDT Server — Operations

Daily, weekly and monthly procedures for one VaultCRDT server. Commands assume the shipped `docker-compose.yml` (data in `./data/`, DB at `/var/lib/vaultcrdt/data.db` inside the container). Replace `http://your-server:8080` with the address of your instance; in production this is the URL of the reverse proxy with TLS in front.

Placeholders: `$ADMIN_TOKEN` is the value of `VAULTCRDT_ADMIN_TOKEN`; `$VAULT_JWT` is a token from `POST /auth/verify` for one vault.

## Daily

### Health

```bash
./scripts/health-check.sh
# or
curl http://your-server:8080/health
```

Expected: HTTP 200 with `{"status":"ok","version":"<server version>","server_epoch":"<uuid>","protocol_version":1}`.

### Logs

```bash
# Docker:
docker compose logs server --tail 100 | grep -i error

# systemd (manual install; no unit ships with this repo):
journalctl -u vaultcrdt-server -n 100 --no-pager | grep -i error
```

Look for: connection or TLS errors, database lock timeouts, JWT verification failures (clock skew, secret mismatch), `tombstone expiry failed`, `peer expiry failed`, `DB maintenance failed`.

Log levels: the default filter is `info,loro=warn,loro_internal=warn`. Per-document events are at `debug`. For a debugging window set `RUST_LOG=vaultcrdt_server=debug` and restart; document identifiers then appear in the log. Reset afterwards.

### Database size

```bash
ls -lh ./data/data.db
# inside the container:
docker compose exec server ls -lh /var/lib/vaultcrdt/data.db
```

Growth of tens to a few hundred KB per day per active vault is normal. A jump without a matching change in usage points to a sync loop or oversized payloads; check the logs.

### Vaults and connections

```bash
sqlite3 ./data/data.db "SELECT vault_id, created_at FROM vaults ORDER BY created_at DESC;"

curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://your-server:8080/debug/connections | jq .
```

## Weekly

### Backup

`.backup` is safe while the server runs. Run it inside the container, then move the file off the host and check it.

```bash
docker compose exec server \
  sqlite3 /var/lib/vaultcrdt/data.db ".backup '/var/lib/vaultcrdt/data.db.weekly.bak'"

cp ./data/data.db.weekly.bak /path/to/backup/vaultcrdt-$(date +%Y-W%V).db

sqlite3 /path/to/backup/vaultcrdt-$(date +%Y-W%V).db "PRAGMA integrity_check;"
sqlite3 /path/to/backup/vaultcrdt-$(date +%Y-W%V).db "SELECT COUNT(*) FROM vaults;"
```

The health-check script reports backup age when `BACKUP_PATH` is set:

```bash
BACKUP_PATH=/path/to/backup/vaultcrdt-latest.db ./scripts/health-check.sh
```

### Peers

Peers not seen for more than `VAULTCRDT_PEER_RETENTION_DAYS` (default 365) are removed by the hourly cleanup. List the candidates:

```bash
sqlite3 ./data/data.db <<EOF
SELECT vault_id, peer_id, device_name, last_seen_at,
       CAST((julianday('now') - julianday(last_seen_at)) AS INTEGER) AS days_ago
FROM peers
WHERE last_seen_at < datetime('now', '-365 days')
ORDER BY last_seen_at ASC;
EOF
```

A device that is in use but appears here has not connected; check that client.

Retiring a device before retention expires: take a backup first. Only retire a peer that will not return with unsynced local edits. The endpoint requires the admin token and the exact stored `device_name`; it acts on one vault at a time.

```bash
sqlite3 ./data/data.db \
  "SELECT peer_id, device_name FROM peers WHERE vault_id = 'my-vault';"

curl -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://your-server:8080/vault/peers/PEER_ID?vault_id=my-vault&device_name=My%20Laptop"
```

`409`: name mismatch; the body contains the stored `device_name` and `last_seen_at`, nothing was deleted. `200`: peer removed; `tombstones_possibly_freed` is an upper bound of tombstones this peer was blocking.

### Tombstones

```bash
sqlite3 ./data/data.db "SELECT vault_id, COUNT(*) FROM tombstones GROUP BY vault_id;"
```

Tombstones expire after `VAULTCRDT_TOMBSTONE_DAYS` (default 365) unless a retained peer has `last_seen_at <= deleted_at`. A large count is expected after a bulk delete or an onboarding that trashed many notes. A count that never shrinks after 365 days points to an old peer row blocking expiry; see [Peers](#peers).

### Fragmentation

```bash
sqlite3 ./data/data.db "PRAGMA freelist_count; PRAGMA page_count;"
```

`freelist_count / page_count` above about 10 % is a reason for a manual `VACUUM` (see [Monthly](#monthly)).

### Growth baseline

Record these numbers weekly. `/debug/vault-stats` and `/vault/peers` are per vault and need a vault JWT; the `sqlite3` variants aggregate across all vaults.

```bash
# DB size on disk:
ls -lh ./data/data.db

# one vault, via API:
curl -s -H "Authorization: Bearer $VAULT_JWT" http://your-server:8080/debug/vault-stats | jq .
curl -s -H "Authorization: Bearer $VAULT_JWT" http://your-server:8080/debug/vault-stats | jq '.largest_docs[:3]'
curl -s -H "Authorization: Bearer $VAULT_JWT" http://your-server:8080/debug/vault-stats | jq '.total_snapshot_bytes'
curl -s -H "Authorization: Bearer $VAULT_JWT" http://your-server:8080/vault/peers | jq '.peers | length'

# all vaults, via sqlite3:
sqlite3 ./data/data.db <<EOF
SELECT COALESCE(SUM(LENGTH(snapshot_blob)), 0) AS total_snapshot_bytes FROM documents;
SELECT vault_id, doc_uuid, LENGTH(snapshot_blob) AS snapshot_bytes
FROM documents ORDER BY snapshot_bytes DESC LIMIT 10;
SELECT COUNT(*) AS peer_count FROM peers;
EOF

# warnings and errors of the past 7 days:
docker compose logs server --since 168h | grep -iE 'error|warn'
```

| Date | DB (MB) | Top-3 docs (bytes) | Snapshot bytes | Peer count |
|---|---|---|---|---|
| YYYY-MM-DD | | | | |

Set `BASELINE_DB_SIZE_MB` in the environment of `scripts/health-check.sh` to a recent DB size; the script then warns when the database has grown more than `DB_GROWTH_THRESHOLD_PCT` (default 50) beyond it.

## Monthly

### Manual VACUUM

The server runs `PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA optimize` once a week on its own. Neither reclaims fragmented space. `VACUUM` rewrites the file under an exclusive lock and is a manual step with downtime. Run it when fragmentation is high:

```bash
docker compose stop server
sleep 5
docker compose run --rm --no-deps server sqlite3 /var/lib/vaultcrdt/data.db "VACUUM; ANALYZE;"
docker compose start server
curl http://your-server:8080/health
```

Alternative without a container: `sqlite3 ./data/data.db "VACUUM; ANALYZE;"` on the host while the server is stopped.

### Restore drill

Pick a backup from two to three months back and verify it can be restored.

```bash
mkdir -p /tmp/restore-test
cp /path/to/backup/vaultcrdt-YYYY-MM-DD.db /tmp/restore-test/data.db

sqlite3 /tmp/restore-test/data.db "PRAGMA integrity_check;"
sqlite3 /tmp/restore-test/data.db <<EOF
SELECT COUNT(*) FROM vaults;
SELECT COUNT(*) FROM documents;
SELECT COUNT(*) FROM peers;
EOF
```

Boot a throwaway instance against the copy. Use a different port and DB path so the live server and its database are not touched. Dummy secrets are sufficient for a boot and `/health` check; the live values are needed only to query authenticated endpoints.

```bash
VAULTCRDT_DB_PATH=/tmp/restore-test/data.db \
  VAULTCRDT_BIND=127.0.0.1:18080 \
  VAULTCRDT_JWT_SECRET="$JWT_SECRET" \
  VAULTCRDT_ADMIN_TOKEN="$ADMIN_TOKEN" \
  ./target/release/vaultcrdt-server &
DRILL_PID=$!
sleep 3

curl -s http://127.0.0.1:18080/health | jq .
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:18080/debug/connections | jq .

kill "$DRILL_PID" 2>/dev/null
rm -rf /tmp/restore-test
```

Record date, backup used, health result and row counts.

### Dependencies

```bash
cargo update --dry-run
cargo audit
```

Plugin and server are released together; a server update that changes the protocol requires the matching plugin version.

### Secret rotation

```bash
openssl rand -hex 32   # new VAULTCRDT_JWT_SECRET
openssl rand -hex 32   # new VAULTCRDT_ADMIN_TOKEN
```

Update `.env`, then `docker compose restart server`. Vault JWTs signed with the old secret are rejected from the restart on; clients re-authenticate with vault name and password. Tokens expire after 3600 s (`JWT_EXPIRY_SECS`, `src/auth.rs`).

## Recovery

### Server unresponsive

```bash
docker compose ps
docker compose logs server --tail 200
docker compose restart server
sleep 5
curl http://your-server:8080/health
```

If the restart does not help, check disk space and permissions on `./data/`:

```bash
df -h ./data
ls -la ./data/
```

Last resort, restore from the newest backup (see README, "Restore", for the client-side consequences):

```bash
docker compose stop server
rm -f ./data/data.db ./data/data.db-wal ./data/data.db-shm
cp /path/to/backup/vaultcrdt-latest.db ./data/data.db
docker compose start server
```

### Suspected corruption

```bash
docker compose exec server sqlite3 /var/lib/vaultcrdt/data.db "PRAGMA integrity_check;"
```

On errors: restore from the newest backup that passes `integrity_check`, then tell vault users to check for conflict copies after their next sync.

### Disk usage

```bash
du -h ./data/
```

If `data.db` dominates: run a manual `VACUUM` (above). If `data.db-wal` is large: the weekly maintenance truncates it; to force it now, stop the server and run `sqlite3 ./data/data.db "PRAGMA wal_checkpoint(TRUNCATE);"`.

## Restarts and updates

A restart drops all WebSocket connections; clients reconnect with backoff and resync via version vectors. No client action is needed.

```bash
docker compose up -d --build
```

Migrations run on startup. Take a backup before updating.

Do not point two server instances at the same SQLite file. One server per database.

## Support

Issues: <https://github.com/tiny-media/vaultcrdt-server/issues>. Attach the server version from `/health` and the relevant log lines; remove tokens and vault names before posting.
