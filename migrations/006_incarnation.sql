-- Incarnation tokens guard document deletes (ADR 0006). Token 0 is
-- reserved ("expect absence"); allocation starts at 1. Existing rows
-- backfill to 1 and the vault counter seeds to 2 — the baseline is
-- per-(vault, doc), not vault-unique history recovery.
ALTER TABLE documents ADD COLUMN incarnation INTEGER NOT NULL DEFAULT 1;
ALTER TABLE tombstones ADD COLUMN incarnation INTEGER NOT NULL DEFAULT 1;
CREATE TABLE vault_incarnation (
  vault_id         TEXT PRIMARY KEY,
  next_incarnation INTEGER NOT NULL CHECK (next_incarnation >= 2)
);
INSERT INTO vault_incarnation (vault_id, next_incarnation)
  SELECT vault_id, 2 FROM (
    SELECT vault_id FROM documents
    UNION
    SELECT vault_id FROM tombstones
  );
