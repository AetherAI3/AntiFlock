package storage

import (
	"context"
	"time"

	"github.com/DBarr3/AntiFlock/internal/model"
)

// AuditedMutation is a closed capability: only this package can implement it.
// Each implementation commits one reviewed domain transition and the supplied
// signed audit entry in the same SQLite transaction. This prevents callers
// from acknowledging an audit entry after an unrelated mutation committed.
type AuditedMutation interface {
	commitWithAudit(context.Context, model.AuditEntry) error
}

type auditedMutationFunc func(context.Context, model.AuditEntry) error

func (mutation auditedMutationFunc) commitWithAudit(ctx context.Context, entry model.AuditEntry) error {
	return mutation(ctx, entry)
}

func CommitAuditedMutation(ctx context.Context, mutation AuditedMutation, entry model.AuditEntry) error {
	if mutation == nil {
		return ErrAuditedMutationRequired
	}
	return mutation.commitWithAudit(ctx, entry)
}

func (database *DB) AuditEntryMutation() AuditedMutation {
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.InsertAuditEntry(ctx, entry)
	})
}

func (database *DB) CreateEnrollmentTokenMutation(token EnrollmentTokenRecord) AuditedMutation {
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.CreateEnrollmentTokenWithAudit(ctx, token, entry)
	})
}

func (database *DB) SubmitEnrollmentRequestMutation(tokenHash []byte, now time.Time, record EnrollmentRequestRecord) AuditedMutation {
	hashCopy := append([]byte(nil), tokenHash...)
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.SubmitEnrollmentRequestWithAudit(ctx, hashCopy, now, record, entry)
	})
}

func (database *DB) ApproveEnrollmentRequestMutation(
	enrollmentID, actorID, operationID, reasonCode string,
	tags []string,
	now time.Time,
	node model.Node,
) AuditedMutation {
	tagsCopy := append([]string(nil), tags...)
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.ApproveEnrollmentRequestWithAudit(
			ctx, enrollmentID, actorID, operationID, reasonCode, tagsCopy, now, node, entry,
		)
	})
}

func (database *DB) DenyEnrollmentRequestMutation(
	enrollmentID, actorID, operationID, reasonCode string,
	now time.Time,
) AuditedMutation {
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.DenyEnrollmentRequestWithAudit(ctx, enrollmentID, actorID, operationID, reasonCode, now, entry)
	})
}

func (database *DB) SetNodeStatusMutation(nodeID string, status model.NodeStatus, now time.Time) AuditedMutation {
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.SetNodeStatusWithAudit(ctx, nodeID, status, now, entry)
	})
}

func (database *DB) UpdateNodeMetadataMutation(nodeID, name string, tags []string) AuditedMutation {
	tagsCopy := append([]string(nil), tags...)
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.UpdateNodeMetadataWithAudit(ctx, nodeID, name, tagsCopy, entry)
	})
}

func (database *DB) CreateSecureActionMutation(record SecureActionRecord) AuditedMutation {
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.CreateSecureActionWithAudit(ctx, record, entry)
	})
}

func (database *DB) UpdateSecureActionMutation(record SecureActionRecord) AuditedMutation {
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.UpdateSecureActionWithAudit(ctx, record, entry)
	})
}

func (database *DB) AppendSecureActionLifecycleMutation(
	eventID, actionID, lifecycle string,
	requestDigest []byte,
	occurredAt, now time.Time,
) AuditedMutation {
	digestCopy := append([]byte(nil), requestDigest...)
	return auditedMutationFunc(func(ctx context.Context, entry model.AuditEntry) error {
		return database.AppendSecureActionLifecycleWithAudit(ctx, eventID, actionID, lifecycle, digestCopy, occurredAt, now, entry)
	})
}
