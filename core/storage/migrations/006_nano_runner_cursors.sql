CREATE TABLE IF NOT EXISTS nano_runner_cursors (
    program_digest TEXT NOT NULL,
    node_id TEXT NOT NULL,
    initialized INTEGER NOT NULL CHECK(initialized IN (0, 1)),
    next_due_unix INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (program_digest, node_id),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
