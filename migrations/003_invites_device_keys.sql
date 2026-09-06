CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vault_id TEXT NOT NULL CHECK (length(vault_id) > 0),
  token_hash TEXT NOT NULL CHECK (length(token_hash) > 0),
  inviter_peer_id TEXT NOT NULL CHECK (length(inviter_peer_id) > 0),
  device_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL CHECK (length(expires_at) > 0),
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS device_keys (
  vault_id TEXT NOT NULL CHECK (length(vault_id) > 0),
  peer_id TEXT NOT NULL CHECK (length(peer_id) > 0),
  key_hash TEXT NOT NULL CHECK (length(key_hash) > 0),
  device_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  PRIMARY KEY (vault_id, peer_id)
);
