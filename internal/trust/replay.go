package trust

import (
	"container/list"
	"sync"
	"time"
)

// Freshness bounds how old or how far in the future a receipt may be.
// The zero value applies no maximum age and no clock skew allowance.
type Freshness struct {
	// MaxAge, when positive, marks receipts issued more than MaxAge before
	// now as stale even if they have not expired.
	MaxAge time.Duration
	// Skew is the clock tolerance applied to both the issue and expiry
	// comparisons.
	Skew time.Duration
}

// DefaultFreshness is used by CheckReceipt: one minute of skew, no MaxAge.
var DefaultFreshness = Freshness{Skew: time.Minute}

// Check classifies one receipt. It returns TaintStale when issuedAt is zero,
// issuedAt is after now+Skew, expiresAt is non-zero and before now-Skew, or
// MaxAge is exceeded; and TaintReplayed when digest was already recorded in
// seen. A nil seen disables replay detection. Every call with a non-nil seen
// records the digest, including stale ones, so a stale receipt cannot later
// be replayed as fresh after a clock change.
func (f Freshness) Check(digest string, issuedAt, expiresAt, now time.Time, seen *SeenSet) Taint {
	var taint Taint
	switch {
	case issuedAt.IsZero():
		taint |= TaintStale
	case issuedAt.After(now.Add(f.Skew)):
		taint |= TaintStale
	case f.MaxAge > 0 && now.Sub(issuedAt) > f.MaxAge:
		taint |= TaintStale
	}
	if !expiresAt.IsZero() && expiresAt.Before(now.Add(-f.Skew)) {
		taint |= TaintStale
	}
	if seen != nil && seen.Observe(digest) {
		taint |= TaintReplayed
	}
	return taint
}

// CheckReceipt applies DefaultFreshness.
func CheckReceipt(digest string, issuedAt, expiresAt, now time.Time, seen *SeenSet) Taint {
	return DefaultFreshness.Check(digest, issuedAt, expiresAt, now, seen)
}

// SeenSet is a bounded, concurrency-safe set of digests with least-recently
// observed eviction. It is a detection aid, not a durable replay registry:
// once a digest is evicted it can be observed again without TaintReplayed.
// Callers that need durable replay protection must persist elsewhere.
type SeenSet struct {
	mu       sync.Mutex
	capacity int
	order    *list.List
	index    map[string]*list.Element
}

// DefaultSeenCapacity is used when NewSeenSet receives a non-positive size.
const DefaultSeenCapacity = 4096

// NewSeenSet returns a set that remembers at most capacity digests.
func NewSeenSet(capacity int) *SeenSet {
	if capacity <= 0 {
		capacity = DefaultSeenCapacity
	}
	return &SeenSet{capacity: capacity, order: list.New(), index: map[string]*list.Element{}}
}

// Observe records digest and reports whether it was already present. An
// existing digest is moved to most-recently-observed.
func (s *SeenSet) Observe(digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.index[digest]; ok {
		s.order.MoveToFront(element)
		return true
	}
	element := s.order.PushFront(digest)
	s.index[digest] = element
	for s.order.Len() > s.capacity {
		oldest := s.order.Back()
		s.order.Remove(oldest)
		delete(s.index, oldest.Value.(string))
	}
	return false
}

// Contains reports presence without recording or reordering.
func (s *SeenSet) Contains(digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.index[digest]
	return ok
}

// Len returns the number of remembered digests.
func (s *SeenSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}
