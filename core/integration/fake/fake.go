// Package fake provides in-memory implementations of every core/integration
// seam for tests and composition-root wiring in development. Each fake obeys
// the seam contract exactly (validation, sentinel errors, context handling)
// so a test written against a fake also holds against a conforming adapter.
// Every fake is safe for concurrent use and records what it received.
package fake

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/DBarr3/AntiFlock/core/integration"
)

// Clock is an injectable time source.
type Clock func() time.Time

func defaultClock() time.Time { return time.Now().UTC() }

// Witness is an in-memory ExternalWitness that signs receipts with an Ed25519
// key and enforces per-deployment sequence monotonicity.
type Witness struct {
	id         string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	clock      Clock
	mu         sync.Mutex
	last       map[string]uint64
	records    []integration.Checkpoint
	// Fail, when set, is returned by Submit after validation (wrapped as
	// ErrUnavailable) to simulate an outage.
	Fail bool
}

// NewWitness creates a witness with a fresh key. A nil clock uses wall time.
func NewWitness(id string, clock Clock) (*Witness, error) {
	if !integration.ValidIdentifier(id) {
		return nil, fmt.Errorf("%w: fake witness id must be a canonical identifier", integration.ErrInvalidInput)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = defaultClock
	}
	return &Witness{id: id, privateKey: private, publicKey: public, clock: clock, last: make(map[string]uint64)}, nil
}

// PublicKey returns the verification key for receipts.
func (witness *Witness) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), witness.publicKey...)
}

// Sign produces a receipt for checkpoint without recording it. HTTP test
// servers use it to act as a remote witness.
func (witness *Witness) Sign(checkpoint integration.Checkpoint) (integration.WitnessReceipt, error) {
	digest, err := integration.CheckpointDigest(checkpoint)
	if err != nil {
		return integration.WitnessReceipt{}, err
	}
	return integration.SignReceipt(integration.WitnessReceipt{WitnessID: witness.id, CheckpointDigest: digest, WitnessedAt: witness.clock()}, witness.privateKey)
}

// Submit implements integration.ExternalWitness.
func (witness *Witness) Submit(ctx context.Context, checkpoint integration.Checkpoint) (integration.WitnessReceipt, error) {
	if err := ctx.Err(); err != nil {
		return integration.WitnessReceipt{}, err
	}
	if err := checkpoint.Validate(); err != nil {
		return integration.WitnessReceipt{}, err
	}
	witness.mu.Lock()
	defer witness.mu.Unlock()
	if witness.Fail {
		return integration.WitnessReceipt{}, fmt.Errorf("%w: fake witness outage", integration.ErrUnavailable)
	}
	if last, seen := witness.last[checkpoint.DeploymentDigest]; seen && checkpoint.Sequence <= last {
		return integration.WitnessReceipt{}, integration.ErrSequenceRegression
	}
	receipt, err := witness.Sign(checkpoint)
	if err != nil {
		return integration.WitnessReceipt{}, err
	}
	witness.last[checkpoint.DeploymentDigest] = checkpoint.Sequence
	witness.records = append(witness.records, checkpoint)
	return receipt, nil
}

// Records returns a copy of every accepted checkpoint in order.
func (witness *Witness) Records() []integration.Checkpoint {
	witness.mu.Lock()
	defer witness.mu.Unlock()
	return append([]integration.Checkpoint(nil), witness.records...)
}

// IdentityProvider maps credentials to principals from a fixed table.
type IdentityProvider struct {
	clock Clock
	mu    sync.RWMutex
	table map[integration.Credential]integration.Principal
}

// NewIdentityProvider creates an empty provider.
func NewIdentityProvider(clock Clock) *IdentityProvider {
	if clock == nil {
		clock = defaultClock
	}
	return &IdentityProvider{clock: clock, table: make(map[integration.Credential]integration.Principal)}
}

// Add registers a credential → principal mapping. The principal must be valid
// at registration time.
func (provider *IdentityProvider) Add(credential integration.Credential, principal integration.Principal) error {
	if err := credential.Validate(); err != nil {
		return err
	}
	if err := principal.Validate(provider.clock()); err != nil {
		return err
	}
	principal.Scopes = append([]string(nil), principal.Scopes...)
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.table[credential] = principal
	return nil
}

// Authenticate implements integration.IdentityProvider.
func (provider *IdentityProvider) Authenticate(ctx context.Context, credential integration.Credential) (integration.Principal, error) {
	if err := ctx.Err(); err != nil {
		return integration.Principal{}, err
	}
	if err := credential.Validate(); err != nil {
		return integration.Principal{}, err
	}
	provider.mu.RLock()
	principal, found := provider.table[credential]
	provider.mu.RUnlock()
	if !found {
		return integration.Principal{}, fmt.Errorf("%w: unknown credential", integration.ErrUnauthenticated)
	}
	if err := principal.Validate(provider.clock()); err != nil {
		return integration.Principal{}, fmt.Errorf("%w: principal expired", integration.ErrUnauthenticated)
	}
	principal.Scopes = append([]string(nil), principal.Scopes...)
	return principal, nil
}

// PolicySource serves signed policies from memory and fans out Watch
// notifications.
type PolicySource struct {
	mu       sync.Mutex
	policies map[integration.PolicyRef]integration.SignedPolicy
	watchers []chan integration.PolicyRef
}

// NewPolicySource creates an empty source.
func NewPolicySource() *PolicySource {
	return &PolicySource{policies: make(map[integration.PolicyRef]integration.SignedPolicy)}
}

// Put stores a policy and notifies watchers. The source does not verify the
// signature: that is core's job.
func (source *PolicySource) Put(policy integration.SignedPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.policies[policy.Ref] = policy.Clone()
	for _, watcher := range source.watchers {
		select {
		case watcher <- policy.Ref:
		default:
		}
	}
	return nil
}

// Fetch implements integration.PolicySource.
func (source *PolicySource) Fetch(ctx context.Context, ref integration.PolicyRef) (integration.SignedPolicy, error) {
	if err := ctx.Err(); err != nil {
		return integration.SignedPolicy{}, err
	}
	if err := ref.Validate(); err != nil {
		return integration.SignedPolicy{}, err
	}
	source.mu.Lock()
	policy, found := source.policies[ref]
	source.mu.Unlock()
	if !found {
		return integration.SignedPolicy{}, fmt.Errorf("%w: policy %s@%d", integration.ErrNotFound, ref.ID, ref.Revision)
	}
	return policy.Clone(), nil
}

// Watch implements integration.PolicySource. The channel closes when ctx is
// done.
func (source *PolicySource) Watch(ctx context.Context) (<-chan integration.PolicyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	channel := make(chan integration.PolicyRef, 16)
	source.mu.Lock()
	source.watchers = append(source.watchers, channel)
	source.mu.Unlock()
	go func() {
		<-ctx.Done()
		source.mu.Lock()
		for index, watcher := range source.watchers {
			if watcher == channel {
				source.watchers = append(source.watchers[:index], source.watchers[index+1:]...)
				break
			}
		}
		source.mu.Unlock()
		close(channel)
	}()
	return channel, nil
}

// EventSink records emitted events.
type EventSink struct {
	mu     sync.Mutex
	events []integration.Event
	Fail   bool
}

// NewEventSink creates an empty sink.
func NewEventSink() *EventSink { return &EventSink{} }

// Emit implements integration.EventSink.
func (sink *EventSink) Emit(ctx context.Context, event integration.Event) error {
	return sink.EmitBatch(ctx, []integration.Event{event})
}

// EmitBatch implements integration.EventSink.
func (sink *EventSink) EmitBatch(ctx context.Context, events []integration.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := integration.ValidateBatch(events); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.Fail {
		return fmt.Errorf("%w: fake sink outage", integration.ErrUnavailable)
	}
	sink.events = append(sink.events, events...)
	return nil
}

// Events returns a copy of everything accepted.
func (sink *EventSink) Events() []integration.Event {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]integration.Event(nil), sink.events...)
}

// FindingSink records the latest summary per finding id.
type FindingSink struct {
	mu      sync.Mutex
	latest  map[string]integration.FindingSummary
	history []integration.FindingSummary
}

// NewFindingSink creates an empty sink.
func NewFindingSink() *FindingSink {
	return &FindingSink{latest: make(map[string]integration.FindingSummary)}
}

// Publish implements integration.FindingSink.
func (sink *FindingSink) Publish(ctx context.Context, summary integration.FindingSummary) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := summary.Validate(); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.history = append(sink.history, summary)
	if current, exists := sink.latest[summary.ID]; !exists || !summary.UpdatedAt.Before(current.UpdatedAt) {
		sink.latest[summary.ID] = summary
	}
	return nil
}

// Latest returns the newest summary for id.
func (sink *FindingSink) Latest(id string) (integration.FindingSummary, bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	summary, found := sink.latest[id]
	return summary, found
}

// DecisionConsumer verifies and records decisions.
type DecisionConsumer struct {
	publicKey ed25519.PublicKey
	mu        sync.Mutex
	decisions []integration.Decision
}

// NewDecisionConsumer creates a consumer that verifies under publicKey.
func NewDecisionConsumer(publicKey ed25519.PublicKey) (*DecisionConsumer, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: decision public key must be Ed25519", integration.ErrInvalidInput)
	}
	return &DecisionConsumer{publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

// Consume implements integration.DecisionConsumer.
func (consumer *DecisionConsumer) Consume(ctx context.Context, decision integration.Decision) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := integration.VerifyDecision(decision, consumer.publicKey); err != nil {
		return err
	}
	decision.ReasonCodes = append([]string(nil), decision.ReasonCodes...)
	decision.Signature = append([]byte(nil), decision.Signature...)
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	consumer.decisions = append(consumer.decisions, decision)
	return nil
}

// Decisions returns a copy of everything accepted.
func (consumer *DecisionConsumer) Decisions() []integration.Decision {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return append([]integration.Decision(nil), consumer.decisions...)
}

// RecoveryVerifier answers from a fixed reachability table keyed by node
// digest. Unknown nodes produce a REPORTED unreachable verdict.
type RecoveryVerifier struct {
	id        string
	clock     Clock
	mu        sync.RWMutex
	reachable map[string]bool
}

// NewRecoveryVerifier creates a verifier.
func NewRecoveryVerifier(id string, clock Clock) (*RecoveryVerifier, error) {
	if !integration.ValidIdentifier(id) {
		return nil, fmt.Errorf("%w: fake verifier id must be a canonical identifier", integration.ErrInvalidInput)
	}
	if clock == nil {
		clock = defaultClock
	}
	return &RecoveryVerifier{id: id, clock: clock, reachable: make(map[string]bool)}, nil
}

// SetReachable records what the verifier will observe for a node digest.
func (verifier *RecoveryVerifier) SetReachable(nodeDigest string, reachable bool) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.reachable[nodeDigest] = reachable
}

// VerifyRecovery implements integration.RecoveryVerifier.
func (verifier *RecoveryVerifier) VerifyRecovery(ctx context.Context, claim integration.RecoveryClaim) (integration.RecoveryVerdict, error) {
	if err := ctx.Err(); err != nil {
		return integration.RecoveryVerdict{}, err
	}
	if err := claim.Validate(); err != nil {
		return integration.RecoveryVerdict{}, err
	}
	verifier.mu.RLock()
	reachable, known := verifier.reachable[claim.NodeDigest]
	verifier.mu.RUnlock()
	class := integration.VerdictObserved
	if !known {
		class = integration.VerdictReported
	}
	return integration.RecoveryVerdict{
		VerifierID: verifier.id, Nonce: claim.Nonce, Class: class, Reachable: known && reachable, ObservedAt: verifier.clock(),
	}, nil
}

// Compile-time seam checks.
var (
	_ integration.ExternalWitness  = (*Witness)(nil)
	_ integration.IdentityProvider = (*IdentityProvider)(nil)
	_ integration.PolicySource     = (*PolicySource)(nil)
	_ integration.EventSink        = (*EventSink)(nil)
	_ integration.FindingSink      = (*FindingSink)(nil)
	_ integration.DecisionConsumer = (*DecisionConsumer)(nil)
	_ integration.RecoveryVerifier = (*RecoveryVerifier)(nil)
)
