-- Capture the deleted document's content hash at tombstone time so a
-- reconnecting peer can tell identical local files from unsynced edits.
-- Existing rows stay NULL (pre-005 deletes have no captured hash).

ALTER TABLE tombstones ADD COLUMN content_hash TEXT;
