CREATE TABLE node_identity_registry (
    node_id TEXT PRIMARY KEY,
    first_enrollment_id TEXT NOT NULL UNIQUE,
    claimed_at TEXT NOT NULL
);

-- Existing active identities win any pre-migration cross-table collision. A
-- colliding pending request then remains unable to approve over that node.
INSERT INTO node_identity_registry(node_id, first_enrollment_id, claimed_at)
SELECT id, 'legacy:' || id, enrolled_at
FROM nodes;

-- Enrollment requests intentionally outlive denial and expiry, so every
-- proposed identity that does not already name an admitted node is burned.
INSERT OR IGNORE INTO node_identity_registry(node_id, first_enrollment_id, claimed_at)
SELECT proposed_node_id, id, requested_at
FROM enrollment_requests;
