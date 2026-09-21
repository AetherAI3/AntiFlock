package trust

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestFreshnessCheck(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	fresh := Freshness{Skew: time.Minute, MaxAge: 24 * time.Hour}
	cases := []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
		want      Taint
	}{
		{"fresh", now.Add(-time.Hour), now.Add(time.Hour), 0},
		{"no expiry", now.Add(-time.Hour), time.Time{}, 0},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), TaintStale},
		{"expired within skew", now.Add(-time.Hour), now.Add(-30 * time.Second), 0},
		{"expired beyond skew", now.Add(-time.Hour), now.Add(-61 * time.Second), TaintStale},
		{"unissued", time.Time{}, now.Add(time.Hour), TaintStale},
		{"future issue within skew", now.Add(30 * time.Second), now.Add(time.Hour), 0},
		{"future issue beyond skew", now.Add(2 * time.Minute), now.Add(time.Hour), TaintStale},
		{"older than max age", now.Add(-25 * time.Hour), now.Add(time.Hour), TaintStale},
		{"at max age", now.Add(-24 * time.Hour), now.Add(time.Hour), 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fresh.Check("d", tc.issuedAt, tc.expiresAt, now, nil); got != tc.want {
				t.Errorf("Check = %s, want %s", got, tc.want)
			}
		})
	}
	zero := Freshness{}
	if got := zero.Check("d", now.Add(-1000*time.Hour), time.Time{}, now, nil); got != 0 {
		t.Errorf("zero Freshness applies a max age: %s", got)
	}
	if got := zero.Check("d", now.Add(time.Second), time.Time{}, now, nil); got != TaintStale {
		t.Errorf("zero Freshness allows skew: %s", got)
	}
}

func TestCheckReceiptReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	issued, expires := now.Add(-time.Minute), now.Add(time.Hour)
	seen := NewSeenSet(2)
	if got := CheckReceipt("a", issued, expires, now, seen); got != 0 {
		t.Errorf("first a = %s", got)
	}
	if got := CheckReceipt("a", issued, expires, now, seen); got != TaintReplayed {
		t.Errorf("second a = %s", got)
	}
	// A stale receipt is recorded too, so it cannot be replayed as fresh later.
	if got := CheckReceipt("b", issued, now.Add(-time.Hour), now, seen); got != TaintStale {
		t.Errorf("stale b = %s", got)
	}
	if got := CheckReceipt("b", issued, expires, now, seen); got != TaintReplayed {
		t.Errorf("replayed b = %s", got)
	}
	if got := CheckReceipt("c", issued, expires, now, nil); got != 0 {
		t.Errorf("nil seen = %s", got)
	}
	// Stale and replayed combine.
	if got := CheckReceipt("b", time.Time{}, expires, now, seen); got != TaintStale|TaintReplayed {
		t.Errorf("stale replay = %s", got)
	}
}

func TestSeenSetEvictsLeastRecentlyObserved(t *testing.T) {
	t.Parallel()
	seen := NewSeenSet(3)
	for _, digest := range []string{"a", "b", "c"} {
		if seen.Observe(digest) {
			t.Fatalf("%s already seen", digest)
		}
	}
	if !seen.Observe("a") { // a is now most recent
		t.Fatal("a forgotten")
	}
	if seen.Observe("d") { // evicts b
		t.Fatal("d already seen")
	}
	if seen.Contains("b") {
		t.Error("b should have been evicted")
	}
	if !seen.Contains("a") || !seen.Contains("c") || !seen.Contains("d") {
		t.Error("wrong survivors")
	}
	if seen.Len() != 3 {
		t.Errorf("Len = %d", seen.Len())
	}
	if seen.Observe("b") {
		t.Error("evicted digest must read as new")
	}
	if NewSeenSet(0).capacity != DefaultSeenCapacity {
		t.Error("default capacity not applied")
	}
}

func TestSeenSetConcurrent(t *testing.T) {
	t.Parallel()
	seen := NewSeenSet(64)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				seen.Observe(fmt.Sprintf("w%d-%d", worker, i%40))
				seen.Contains("w0-1")
			}
		}(worker)
	}
	wg.Wait()
	if seen.Len() > 64 {
		t.Errorf("Len = %d exceeds capacity", seen.Len())
	}
}
