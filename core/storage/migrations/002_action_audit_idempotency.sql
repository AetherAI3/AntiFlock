ALTER TABLE secure_actions ADD COLUMN operation_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS secure_actions_operation_idx
ON secure_actions(operation_id) WHERE operation_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS secure_action_audit_events (
    event_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES secure_actions(id) ON DELETE CASCADE,
    lifecycle TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS secure_action_audit_action_idx
ON secure_action_audit_events(action_id, occurred_at);
