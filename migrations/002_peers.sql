CREATE TABLE IF NOT EXISTS peers (
  vault_id    TEXT NOT NULL,
  peer_id     TEXT NOT NULL,
  device_name TEXT NOT NULL DEFAULT '',
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (vault_id, peer_id)
);
