package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/storage"
)

const (
	eventRetentionBatchSize  = 500
	eventRetentionMaxBatches = 20
)

func runEventRetention(ctx context.Context, database *storage.DB, retention time.Duration, logger *slog.Logger) {
	if database == nil || retention <= 0 {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	run := func() {
		cutoff := time.Now().UTC().Add(-retention)
		var total int64
		for range eventRetentionMaxBatches {
			result, err := database.PruneEvents(ctx, cutoff, []string{events.APIProjection}, eventRetentionBatchSize)
			if errors.Is(err, storage.ErrRetentionProjectionNotReady) {
				logger.Info("event retention is waiting for the durable API cursor", "projection", events.APIProjection)
				return
			}
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("event retention pass failed", "error", err)
				}
				return
			}
			total += result.Deleted
			if result.Deleted != 0 {
				logger.Info("event retention batch committed",
					"deleted", result.Deleted, "safeThroughOrdinal", result.SafeThroughOrdinal,
					"safeThroughEvent", result.SafeThroughID, "tombstoneHash", result.TombstoneHash,
				)
			}
			if result.Deleted < eventRetentionBatchSize {
				break
			}
		}
		if total != 0 {
			logger.Info("event retention pass complete", "deleted", total, "cutoff", cutoff)
		}
	}

	run()
	ticker := time.NewTicker(eventRetentionInterval(retention))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func eventRetentionInterval(retention time.Duration) time.Duration {
	interval := retention / 24
	if interval < time.Minute {
		return time.Minute
	}
	if interval > time.Hour {
		return time.Hour
	}
	return interval
}
