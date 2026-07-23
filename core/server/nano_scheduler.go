package server

import (
	"context"
	"log/slog"
	"time"
)

// startNanoWatchdogScheduler executes only the explicitly configured admitted
// program IDs. It never accepts remote input, authorizes a proposal, or
// executes an action. A single loop intentionally prevents overlapping passes.
func (server *Server) startNanoWatchdogScheduler(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if server.nano == nil || server.nanoRunInterval <= 0 || len(server.nanoRunProgramIDs) == 0 {
		close(done)
		return done
	}
	programIDs := append([]string(nil), server.nanoRunProgramIDs...)
	go func() {
		defer close(done)
		ticker := time.NewTicker(server.nanoRunInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				server.runConfiguredNanoWatchdogs(ctx, programIDs)
			}
		}
	}()
	return done
}

func (server *Server) runConfiguredNanoWatchdogs(ctx context.Context, programIDs []string) {
	timeout := server.nanoRunInterval
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	for _, programID := range programIDs {
		if ctx.Err() != nil {
			return
		}
		runContext, cancel := context.WithTimeout(ctx, timeout)
		result, err := server.runWatchdogOpenFindings(runContext, programID)
		cancel()
		if err != nil {
			slog.Warn("Nano watchdog scheduled pass failed", "programId", programID, "error", err)
			continue
		}
		slog.Debug("Nano watchdog scheduled pass completed", "programId", programID, "evaluated", result.EvaluatedCount, "stale", result.SkippedStale)
	}
}
