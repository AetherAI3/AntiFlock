CREATE UNIQUE INDEX IF NOT EXISTS secure_action_one_execution_start_idx
ON secure_action_audit_events(action_id)
WHERE lifecycle = 'SDK_ACTION_EXECUTION_STARTED';

CREATE UNIQUE INDEX IF NOT EXISTS secure_action_one_execution_terminal_idx
ON secure_action_audit_events(action_id)
WHERE lifecycle IN ('SDK_ACTION_EXECUTION_SUCCEEDED', 'SDK_ACTION_EXECUTION_FAILED');
