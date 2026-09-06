-- VaultCRDT v2 — clean schema (no legacy)

CREATE TABLE IF NOT EXISTS vaults (
  vault_id   TEXT PRIMARY KEY,
  api_key    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS documents (
  vault_id      TEXT NOT NULL,
  doc_uuid      TEXT NOT NULL,
  snapshot_blob BLOB NOT NULL,
  vv_blob       BLOB NOT NULL,
  updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (vault_id, doc_uuid)
);

CREATE TABLE IF NOT EXISTS tombstones (
  vault_id   TEXT NOT NULL,
  doc_uuid   TEXT NOT NULL,
  deleted_by TEXT NOT NULL,
  deleted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (vault_id, doc_uuid)
);
