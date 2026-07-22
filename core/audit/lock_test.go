package audit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestAnchorKernelLockCannotBeStolenAndReleasesCleanly(t *testing.T) {
	t.Parallel()
	service := &Service{anchorPath: filepath.Join(t.TempDir(), "audit-anchor.jsonl")}
	release, err := service.acquireAnchorLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.acquireAnchorLock(canceled); !errors.Is(err, context.Canceled) {
		release()
		t.Fatalf("second lock acquisition error = %v, want context cancellation", err)
	}
	release()

	releaseAgain, err := service.acquireAnchorLock(context.Background())
	if err != nil {
		t.Fatalf("reacquire released audit lock: %v", err)
	}
	releaseAgain()
}
