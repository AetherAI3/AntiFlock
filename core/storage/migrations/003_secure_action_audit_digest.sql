ALTER TABLE secure_action_audit_events
ADD COLUMN request_digest BLOB NOT NULL DEFAULT X'';
