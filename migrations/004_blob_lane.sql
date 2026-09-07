-- Attachment blob lane. Files live on disk at
-- ${VAULTCRDT_BLOB_DIR:-/var/lib/vaultcrdt/blobs}/<vault_id>/<hash[0:2]>/<hash>.
-- Uploads stage at <blob_dir>/tmp/<upload_id>. Quota NULL means the env default.

ALTER TABLE vaults ADD COLUMN quota_bytes INTEGER;  -- NULL = env default

CREATE TABLE blobs(
  vault_id   TEXT NOT NULL,
  hash       TEXT NOT NULL,            -- 64 hex blake3
  size       INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(vault_id, hash)
);
CREATE TABLE blob_path_states(
  vault_id     TEXT NOT NULL,
  path_key     TEXT NOT NULL,
  display_path TEXT NOT NULL,
  key_version  INTEGER NOT NULL DEFAULT 1,
  generation   INTEGER NOT NULL,
  state        TEXT NOT NULL CHECK(state IN ('live','deleted')),
  content_hash TEXT,
  size         INTEGER,
  peer_id      TEXT NOT NULL,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
  seq          INTEGER NOT NULL,
  env_json     TEXT,
  PRIMARY KEY(vault_id, path_key)
);
CREATE INDEX idx_blob_path_seq ON blob_path_states(vault_id, seq);
CREATE TABLE blob_uploads(
  vault_id       TEXT NOT NULL,
  upload_id      TEXT NOT NULL PRIMARY KEY,
  hash_claimed   TEXT NOT NULL,
  size_claimed   INTEGER NOT NULL,
  received_bytes INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_blob_uploads_vault ON blob_uploads(vault_id);
CREATE TABLE counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO counters(name, value) VALUES ('blob_seq', 0);
