// Package conformance is the executable contract for every core/integration
// seam. An adapter (in-tree reference or downstream, out-of-tree) proves it
// honours the seam by calling the Run* function for its kind from its own
// test package. The suites check validation behaviour, sentinel errors,
// context handling, signature and digest bindings, and that nothing the
// adapter returns can be mistaken for authorization.
package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/integration"
)

// WitnessFactory builds a fresh witness and returns the public key that
// verifies its receipts. The factory registers any cleanup with t.
type WitnessFactory func(t *testing.T) (integration.ExternalWitness, ed25519.PublicKey)

func validCheckpoint(sequence uint64) integration.Checkpoint {
	return integration.Checkpoint{
		DeploymentDigest: integration.DigestString("conformance-deployment"),
		AuditHeadDigest:  integration.DigestString("conformance-head"),
		Sequence:         sequence, IssuedAt: time.Date(2026, 8, 23, 12, 0, int(sequence), 0, time.UTC), NodeCountBucket: integration.NodeCountSmall,
	}
}

// RunExternalWitness checks an ExternalWitness implementation.
func RunExternalWitness(t *testing.T, factory WitnessFactory) {
	t.Helper()
	t.Run("rejects invalid checkpoints without recording", func(t *testing.T) {
		witness, _ := factory(t)
		for name, checkpoint := range map[string]integration.Checkpoint{
			"zero":           {},
			"raw deployment": {DeploymentDigest: "deployment-1", AuditHeadDigest: integration.DigestString("h"), Sequence: 1, IssuedAt: time.Now()},
			"zero sequence":  {DeploymentDigest: integration.DigestString("d"), AuditHeadDigest: integration.DigestString("h"), Sequence: 0, IssuedAt: time.Now()},
			"exact count":    {DeploymentDigest: integration.DigestString("d"), AuditHeadDigest: integration.DigestString("h"), Sequence: 1, IssuedAt: time.Now(), NodeCountBucket: "17"},
		} {
			if _, err := witness.Submit(context.Background(), checkpoint); !errors.Is(err, integration.ErrInvalidInput) {
				t.Errorf("%s: Submit() = %v, want ErrInvalidInput", name, err)
			}
		}
	})
	t.Run("returns a receipt bound to the checkpoint and signed by the witness key", func(t *testing.T) {
		witness, publicKey := factory(t)
		checkpoint := validCheckpoint(1)
		receipt, err := witness.Submit(context.Background(), checkpoint)
		if err != nil {
			t.Fatalf("Submit() = %v", err)
		}
		if err := integration.VerifyReceiptFor(receipt, checkpoint, publicKey); err != nil {
			t.Fatalf("receipt does not verify: %v", err)
		}
		if receipt.WitnessedAt.IsZero() || !integration.ValidIdentifier(receipt.WitnessID) {
			t.Fatal("receipt is missing witness identity or time")
		}
		other := validCheckpoint(2)
		if err := integration.VerifyReceiptFor(receipt, other, publicKey); !errors.Is(err, integration.ErrInvalidReceipt) {
			t.Fatalf("receipt verifies for a different checkpoint: %v", err)
		}
		forged, _, _ := ed25519.GenerateKey(rand.Reader)
		if err := integration.VerifyReceipt(receipt, forged); !errors.Is(err, integration.ErrInvalidReceipt) {
			t.Fatalf("receipt verifies under a foreign key: %v", err)
		}
	})
	t.Run("advancing sequences are accepted and regressions are refused or receipted, never silently altered", func(t *testing.T) {
		witness, publicKey := factory(t)
		for sequence := uint64(1); sequence <= 3; sequence++ {
			receipt, err := witness.Submit(context.Background(), validCheckpoint(sequence))
			if err != nil {
				t.Fatalf("sequence %d: %v", sequence, err)
			}
			if err := integration.VerifyReceiptFor(receipt, validCheckpoint(sequence), publicKey); err != nil {
				t.Fatalf("sequence %d receipt: %v", sequence, err)
			}
		}
		regression := validCheckpoint(2)
		receipt, err := witness.Submit(context.Background(), regression)
		switch {
		case err == nil:
			if verr := integration.VerifyReceiptFor(receipt, regression, publicKey); verr != nil {
				t.Fatalf("regression accepted but receipt does not bind to it: %v", verr)
			}
		case errors.Is(err, integration.ErrInvalidInput):
		default:
			t.Fatalf("regression error must wrap ErrInvalidInput, got %v", err)
		}
	})
	t.Run("honours a cancelled context", func(t *testing.T) {
		witness, _ := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := witness.Submit(ctx, validCheckpoint(1)); err == nil {
			t.Fatal("Submit() succeeded with a cancelled context")
		}
	})
}

// IdentityFixture is a credential the provider under test accepts and the
// principal it should return.
type IdentityFixture struct {
	Credential integration.Credential
	Expected   integration.Principal
}

// IdentityFactory builds a fresh provider and a fixture it recognises.
type IdentityFactory func(t *testing.T) (integration.IdentityProvider, IdentityFixture)

// RunIdentityProvider checks an IdentityProvider implementation.
func RunIdentityProvider(t *testing.T, factory IdentityFactory) {
	t.Helper()
	t.Run("authenticates the fixture into a valid principal", func(t *testing.T) {
		provider, fixture := factory(t)
		principal, err := provider.Authenticate(context.Background(), fixture.Credential)
		if err != nil {
			t.Fatalf("Authenticate() = %v", err)
		}
		if err := principal.Validate(time.Now()); err != nil {
			t.Fatalf("returned principal is invalid: %v", err)
		}
		if principal.SubjectDigest != fixture.Expected.SubjectDigest {
			t.Fatal("subject digest differs from the fixture")
		}
		if len(principal.Scopes) != len(fixture.Expected.Scopes) {
			t.Fatalf("scopes = %v, want %v", principal.Scopes, fixture.Expected.Scopes)
		}
		for index := range principal.Scopes {
			if principal.Scopes[index] != fixture.Expected.Scopes[index] {
				t.Fatalf("scopes = %v, want %v", principal.Scopes, fixture.Expected.Scopes)
			}
		}
	})
	t.Run("rejects malformed, altered, and unknown credentials", func(t *testing.T) {
		provider, fixture := factory(t)
		altered := fixture.Credential
		altered.Value = altered.Value[:len(altered.Value)-1] + flip(altered.Value[len(altered.Value)-1])
		for name, credential := range map[string]integration.Credential{
			"empty":         {},
			"unknown kind":  {Kind: "oauth", Value: fixture.Credential.Value},
			"altered value": altered,
			"unknown":       {Kind: integration.CredentialCertificateFingerprint, Value: integration.DigestString("nobody")},
		} {
			_, err := provider.Authenticate(context.Background(), credential)
			if err == nil {
				t.Errorf("%s: credential accepted", name)
				continue
			}
			if !errors.Is(err, integration.ErrUnauthenticated) && !errors.Is(err, integration.ErrInvalidInput) {
				t.Errorf("%s: error %v must wrap ErrUnauthenticated or ErrInvalidInput", name, err)
			}
		}
	})
	t.Run("honours a cancelled context", func(t *testing.T) {
		provider, fixture := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := provider.Authenticate(ctx, fixture.Credential); err == nil {
			t.Fatal("Authenticate() succeeded with a cancelled context")
		}
	})
}

func flip(b byte) string {
	if b == '0' {
		return "1"
	}
	return "0"
}

// PolicyFixture is a reference the source under test can serve, and an
// optional hook that publishes a new revision (nil disables the Watch
// delivery check; the close-on-cancel check always runs).
type PolicyFixture struct {
	Known   integration.PolicyRef
	Publish func(t *testing.T, policy integration.SignedPolicy)
}

// PolicyFactory builds a fresh source and its fixture.
type PolicyFactory func(t *testing.T) (integration.PolicySource, PolicyFixture)

// RunPolicySource checks a PolicySource implementation.
func RunPolicySource(t *testing.T, factory PolicyFactory) {
	t.Helper()
	t.Run("fetches opaque signed material the caller owns", func(t *testing.T) {
		source, fixture := factory(t)
		policy, err := source.Fetch(context.Background(), fixture.Known)
		if err != nil {
			t.Fatalf("Fetch() = %v", err)
		}
		if err := policy.Validate(); err != nil {
			t.Fatalf("returned policy is invalid: %v", err)
		}
		if policy.Ref != fixture.Known {
			t.Fatalf("returned ref %+v, want %+v", policy.Ref, fixture.Known)
		}
		policy.Payload[0] ^= 0xff
		again, err := source.Fetch(context.Background(), fixture.Known)
		if err != nil {
			t.Fatal(err)
		}
		if again.Payload[0] == policy.Payload[0] {
			t.Fatal("source shares its payload buffer with callers")
		}
	})
	t.Run("unknown and invalid references fail closed", func(t *testing.T) {
		source, fixture := factory(t)
		if _, err := source.Fetch(context.Background(), integration.PolicyRef{ID: fixture.Known.ID, Revision: fixture.Known.Revision + 1_000_000}); !errors.Is(err, integration.ErrNotFound) {
			t.Fatalf("unknown revision = %v, want ErrNotFound", err)
		}
		if _, err := source.Fetch(context.Background(), integration.PolicyRef{}); !errors.Is(err, integration.ErrInvalidInput) {
			t.Fatalf("empty ref = %v, want ErrInvalidInput", err)
		}
	})
	t.Run("watch closes on cancel and delivers published references", func(t *testing.T) {
		source, fixture := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		updates, err := source.Watch(ctx)
		if err != nil {
			t.Fatalf("Watch() = %v", err)
		}
		if fixture.Publish != nil {
			next := integration.PolicyRef{ID: fixture.Known.ID, Revision: fixture.Known.Revision + 1}
			fixture.Publish(t, integration.SignedPolicy{Ref: next, Payload: []byte("{}"), Signature: []byte("sig"), KeyID: "policy:conformance"})
			select {
			case ref, open := <-updates:
				if !open || ref != next {
					t.Fatalf("watch delivered %+v (open=%v), want %+v", ref, open, next)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("watch did not deliver the published reference")
			}
		}
		cancel()
		select {
		case _, open := <-updates:
			for open {
				_, open = <-updates
			}
		case <-time.After(5 * time.Second):
			t.Fatal("watch channel did not close after cancel")
		}
	})
}

// EventSinkFactory builds a fresh sink.
type EventSinkFactory func(t *testing.T) integration.EventSink

func validEvent(index int) integration.Event {
	return integration.Event{
		ID: "event-" + hex.EncodeToString([]byte{byte(index)}), Kind: "network.route_changed", EvidenceClass: integration.EvidenceDetected,
		OccurredAt: time.Now().UTC(), TrustEnvelopeDigest: integration.DigestString("envelope"), PayloadDigest: integration.DigestString("payload"),
	}
}

// RunEventSink checks an EventSink implementation.
func RunEventSink(t *testing.T, factory EventSinkFactory) {
	t.Helper()
	t.Run("accepts valid events and batches up to the bound", func(t *testing.T) {
		sink := factory(t)
		if err := sink.Emit(context.Background(), validEvent(0)); err != nil {
			t.Fatalf("Emit() = %v", err)
		}
		batch := make([]integration.Event, integration.MaxEventBatch)
		for index := range batch {
			batch[index] = validEvent(index)
		}
		if err := sink.EmitBatch(context.Background(), batch); err != nil {
			t.Fatalf("EmitBatch(max) = %v", err)
		}
		if err := sink.EmitBatch(context.Background(), append(batch, validEvent(999))); !errors.Is(err, integration.ErrBatchTooLarge) {
			t.Fatalf("EmitBatch(max+1) = %v, want ErrBatchTooLarge", err)
		}
	})
	t.Run("rejects invalid events and relabelled evidence", func(t *testing.T) {
		sink := factory(t)
		relabelled := validEvent(0)
		relabelled.EvidenceClass = "CONFIRMED"
		noDigest := validEvent(1)
		noDigest.PayloadDigest = "raw payload bytes"
		for name, event := range map[string]integration.Event{"zero": {}, "relabelled": relabelled, "raw payload": noDigest} {
			if err := sink.Emit(context.Background(), event); !errors.Is(err, integration.ErrInvalidInput) {
				t.Errorf("%s: Emit() = %v, want ErrInvalidInput", name, err)
			}
		}
		if err := sink.EmitBatch(context.Background(), nil); !errors.Is(err, integration.ErrInvalidInput) {
			t.Fatalf("empty batch = %v, want ErrInvalidInput", err)
		}
	})
	t.Run("honours a cancelled context", func(t *testing.T) {
		sink := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sink.Emit(ctx, validEvent(0)); err == nil {
			t.Fatal("Emit() succeeded with a cancelled context")
		}
	})
}

// FindingSinkFactory builds a fresh sink.
type FindingSinkFactory func(t *testing.T) integration.FindingSink

// RunFindingSink checks a FindingSink implementation.
func RunFindingSink(t *testing.T, factory FindingSinkFactory) {
	t.Helper()
	summary := integration.FindingSummary{
		ID: "finding-1", Severity: integration.SeverityHigh, Status: integration.StatusOpen,
		EvidenceClass: integration.EvidenceDetected, Digest: integration.DigestString("finding"), UpdatedAt: time.Now().UTC(),
	}
	t.Run("accepts summaries and tolerates duplicates", func(t *testing.T) {
		sink := factory(t)
		for range 2 {
			if err := sink.Publish(context.Background(), summary); err != nil {
				t.Fatalf("Publish() = %v", err)
			}
		}
	})
	t.Run("rejects invalid summaries", func(t *testing.T) {
		sink := factory(t)
		bad := summary
		bad.Digest = "this is the finding title, not a digest"
		for name, value := range map[string]integration.FindingSummary{"zero": {}, "content instead of digest": bad} {
			if err := sink.Publish(context.Background(), value); !errors.Is(err, integration.ErrInvalidInput) {
				t.Errorf("%s: Publish() = %v, want ErrInvalidInput", name, err)
			}
		}
	})
	t.Run("honours a cancelled context", func(t *testing.T) {
		sink := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sink.Publish(ctx, summary); err == nil {
			t.Fatal("Publish() succeeded with a cancelled context")
		}
	})
}

// DecisionConsumerFactory builds a fresh consumer and returns the private key
// whose public half the consumer trusts.
type DecisionConsumerFactory func(t *testing.T) (integration.DecisionConsumer, ed25519.PrivateKey)

// RunDecisionConsumer checks a DecisionConsumer implementation.
func RunDecisionConsumer(t *testing.T, factory DecisionConsumerFactory) {
	t.Helper()
	now := time.Now().UTC()
	unsigned := integration.Decision{
		DecisionID: "decision-1", ActionDigest: integration.DigestString("action"), NodeDigest: integration.DigestString("node"),
		Type: integration.DecisionHold, ReasonCodes: []string{"AF-PROTECTION-NOT-VERIFIED"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	t.Run("accepts a correctly signed decision", func(t *testing.T) {
		consumer, key := factory(t)
		decision, err := integration.SignDecision(unsigned, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := consumer.Consume(context.Background(), decision); err != nil {
			t.Fatalf("Consume() = %v", err)
		}
	})
	t.Run("rejects unsigned, altered, and foreign-key decisions", func(t *testing.T) {
		consumer, key := factory(t)
		signed, _ := integration.SignDecision(unsigned, key)
		altered := signed
		altered.Type = integration.DecisionAllow
		_, foreign, _ := ed25519.GenerateKey(rand.Reader)
		foreignSigned, _ := integration.SignDecision(unsigned, foreign)
		for name, decision := range map[string]integration.Decision{"unsigned": unsigned, "altered": altered, "foreign": foreignSigned} {
			err := consumer.Consume(context.Background(), decision)
			if err == nil {
				t.Errorf("%s: decision consumed", name)
				continue
			}
			if !errors.Is(err, integration.ErrInvalidSignature) && !errors.Is(err, integration.ErrInvalidInput) {
				t.Errorf("%s: error %v must wrap ErrInvalidSignature or ErrInvalidInput", name, err)
			}
		}
	})
	t.Run("honours a cancelled context", func(t *testing.T) {
		consumer, key := factory(t)
		signed, _ := integration.SignDecision(unsigned, key)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := consumer.Consume(ctx, signed); err == nil {
			t.Fatal("Consume() succeeded with a cancelled context")
		}
	})
}

// RecoveryFixture names a node digest the verifier under test can observe as
// reachable.
type RecoveryFixture struct {
	ReachableNodeDigest string
}

// RecoveryFactory builds a fresh verifier and its fixture.
type RecoveryFactory func(t *testing.T) (integration.RecoveryVerifier, RecoveryFixture)

func validClaim(nodeDigest string) integration.RecoveryClaim {
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	return integration.RecoveryClaim{
		DeploymentDigest: integration.DigestString("deployment"), NodeDigest: nodeDigest,
		RecoveryPathDigest: integration.DigestString("recovery-path"), Operation: integration.RecoveryAfterApply,
		ClaimedAt: time.Now().UTC(), Nonce: hex.EncodeToString(nonce),
	}
}

// RunRecoveryVerifier checks a RecoveryVerifier implementation.
func RunRecoveryVerifier(t *testing.T, factory RecoveryFactory) {
	t.Helper()
	t.Run("returns a nonce-bound evidence verdict", func(t *testing.T) {
		verifier, fixture := factory(t)
		claim := validClaim(fixture.ReachableNodeDigest)
		verdict, err := verifier.VerifyRecovery(context.Background(), claim)
		if err != nil {
			t.Fatalf("VerifyRecovery() = %v", err)
		}
		if err := verdict.Validate(claim); err != nil {
			t.Fatalf("verdict invalid: %v", err)
		}
		if !verdict.Reachable {
			t.Fatal("fixture node reported unreachable")
		}
		replay := validClaim(fixture.ReachableNodeDigest)
		if err := verdict.Validate(replay); !errors.Is(err, integration.ErrInvalidInput) {
			t.Fatalf("verdict validates against a different claim nonce: %v", err)
		}
	})
	t.Run("unknown nodes are never observed reachable", func(t *testing.T) {
		verifier, _ := factory(t)
		claim := validClaim(integration.DigestString("unknown-node"))
		verdict, err := verifier.VerifyRecovery(context.Background(), claim)
		if err != nil {
			if !errors.Is(err, integration.ErrUnavailable) && !errors.Is(err, integration.ErrNotFound) {
				t.Fatalf("unknown node error %v must wrap ErrUnavailable or ErrNotFound", err)
			}
			return
		}
		if verdict.Reachable && verdict.Class == integration.VerdictObserved {
			t.Fatal("verifier claims to have observed an unknown node as reachable")
		}
	})
	t.Run("rejects invalid claims", func(t *testing.T) {
		verifier, fixture := factory(t)
		raw := validClaim(fixture.ReachableNodeDigest)
		raw.NodeDigest = "node-1"
		for name, claim := range map[string]integration.RecoveryClaim{"zero": {}, "raw node id": raw} {
			if _, err := verifier.VerifyRecovery(context.Background(), claim); !errors.Is(err, integration.ErrInvalidInput) {
				t.Errorf("%s: VerifyRecovery() = %v, want ErrInvalidInput", name, err)
			}
		}
	})
	t.Run("honours a cancelled context", func(t *testing.T) {
		verifier, fixture := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := verifier.VerifyRecovery(ctx, validClaim(fixture.ReachableNodeDigest)); err == nil {
			t.Fatal("VerifyRecovery() succeeded with a cancelled context")
		}
	})
}
