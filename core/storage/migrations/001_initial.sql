CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deployment_state (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    scope_json TEXT NOT NULL,
    created_by_principal_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_by_node_id TEXT,
    consumed_request_id TEXT,
    consumed_request_digest BLOB
);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    node_type TEXT NOT NULL,
    platform TEXT NOT NULL,
    platform_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    tags_json TEXT NOT NULL DEFAULT '[]',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    capabilities_verification TEXT NOT NULL CHECK (capabilities_verification IN ('CLAIMED', 'VERIFIED')),
    public_key BLOB NOT NULL UNIQUE,
    certificate_pem TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT,
    last_policy_revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    ingest_ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    boot_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    sensitivity TEXT NOT NULL,
    envelope_proto BLOB NOT NULL,
    UNIQUE(node_id, boot_id, sequence)
);

CREATE TABLE IF NOT EXISTS enrollment_requests (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL UNIQUE REFERENCES enrollment_tokens(id),
    request_id TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED')),
    proposed_node_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    node_type TEXT NOT NULL,
    platform TEXT NOT NULL,
    platform_version TEXT NOT NULL,
    public_key BLOB NOT NULL UNIQUE,
    capabilities_json TEXT NOT NULL,
    allowed_tags_json TEXT NOT NULL DEFAULT '[]',
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decision_reason_code TEXT,
    decision_operation_id TEXT UNIQUE,
    decided_by_principal_id TEXT,
    decided_at TEXT,
    approved_tags_json TEXT,
    node_id TEXT UNIQUE REFERENCES nodes(id),
    UNIQUE(token_id, request_id)
);

CREATE INDEX IF NOT EXISTS enrollment_requests_status_idx
ON enrollment_requests(status, requested_at);

CREATE INDEX IF NOT EXISTS events_kind_time_idx ON events(kind, observed_at DESC);
CREATE INDEX IF NOT EXISTS events_node_time_idx ON events(node_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS events_received_idx ON events(received_at, id);
CREATE INDEX IF NOT EXISTS events_ingest_idx ON events(ingest_ordinal);

CREATE TABLE IF NOT EXISTS node_event_state (
    node_id TEXT PRIMARY KEY,
    current_boot_id TEXT NOT NULL,
    highest_contiguous_sequence INTEGER NOT NULL,
    last_event_id TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_event_boots (
    node_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    highest_contiguous_sequence INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(node_id, boot_id)
);

CREATE TABLE IF NOT EXISTS projection_cursors (
    projection TEXT PRIMARY KEY,
    last_ingest_ordinal INTEGER NOT NULL DEFAULT 0,
    last_received_at INTEGER NOT NULL,
    last_event_id TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    source_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(source_entity_id, target_entity_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL,
    title TEXT NOT NULL,
    condition_text TEXT NOT NULL,
    consequence TEXT NOT NULL,
    current_fact TEXT NOT NULL,
    expected_fact TEXT NOT NULL,
    explanation TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    false_positive_note TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    opened_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(rule_id, node_id, status)
);

CREATE INDEX IF NOT EXISTS findings_status_idx ON findings(status, severity, updated_at DESC);

CREATE TABLE IF NOT EXISTS audit_entries (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    key_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_retention_tombstones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_ingest_ordinal INTEGER NOT NULL,
    last_ingest_ordinal INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    batch_hash TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    cutoff_at TEXT NOT NULL,
    pruned_at TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    tombstone_hash TEXT NOT NULL UNIQUE,
    UNIQUE(first_ingest_ordinal, last_ingest_ordinal)
);

CREATE TABLE IF NOT EXISTS event_retention_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tombstone_count INTEGER NOT NULL,
    head_hash TEXT NOT NULL
);

INSERT OR IGNORE INTO event_retention_state(id, tombstone_count, head_hash)
VALUES (1, 0, '');

CREATE TABLE IF NOT EXISTS audit_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    entry_count INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    head_hash TEXT NOT NULL
);

INSERT OR IGNORE INTO audit_state(id, entry_count, sequence, head_hash)
VALUES (1, 0, 0, '');

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL,
    source_yaml TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    status TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    applied_at TEXT,
    verified_at TEXT,
    rolled_back_at TEXT,
    UNIQUE(node_id, revision)
);

CREATE TABLE IF NOT EXISTS secure_actions (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    application_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    request_json TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    released_at TEXT,
    bypass_expires_at TEXT
);

CREATE TABLE IF NOT EXISTS field_reports (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    geometry_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    last_verified_at TEXT,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    source_license TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS footprint_assets (
    id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scrambler_states (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    current_state_json TEXT NOT NULL,
    candidate_state_json TEXT,
    verification_json TEXT,
    simulated INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
