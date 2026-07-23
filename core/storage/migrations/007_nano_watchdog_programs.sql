CREATE TABLE IF NOT EXISTS nano_watchdog_programs (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    program_digest TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ADMITTED', 'DISABLED')),
    operation_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE (node_id, program_digest)
);

CREATE INDEX IF NOT EXISTS idx_nano_watchdog_programs_node_status
    ON nano_watchdog_programs(node_id, status, updated_at DESC);
