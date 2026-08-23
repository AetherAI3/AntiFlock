package fake_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/integration"
	"github.com/DBarr3/AntiFlock/core/integration/conformance"
	"github.com/DBarr3/AntiFlock/core/integration/fake"
)

func TestFakeWitnessConformance(t *testing.T) {
	t.Parallel()
	conformance.RunExternalWitness(t, func(t *testing.T) (integration.ExternalWitness, ed25519.PublicKey) {
		witness, err := fake.NewWitness("fake-witness", nil)
		if err != nil {
			t.Fatal(err)
		}
		return witness, witness.PublicKey()
	})
}

func TestFakeWitnessRefusesRegressionAndOutage(t *testing.T) {
	t.Parallel()
	witness, err := fake.NewWitness("fake-witness", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := integration.Checkpoint{DeploymentDigest: integration.DigestString("d"), AuditHeadDigest: integration.DigestString("h"), Sequence: 5, IssuedAt: time.Now()}
	if _, err := witness.Submit(context.Background(), checkpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Submit(context.Background(), checkpoint); !errors.Is(err, integration.ErrSequenceRegression) {
		t.Fatalf("replayed sequence = %v, want ErrSequenceRegression", err)
	}
	witness.Fail = true
	checkpoint.Sequence = 6
	if _, err := witness.Submit(context.Background(), checkpoint); !integration.IsRetryable(err) {
		t.Fatalf("outage = %v, want retryable ErrUnavailable", err)
	}
	if got := witness.Records(); len(got) != 1 {
		t.Fatalf("records = %d, want 1", len(got))
	}
}

func TestFakeIdentityProviderConformance(t *testing.T) {
	t.Parallel()
	conformance.RunIdentityProvider(t, func(t *testing.T) (integration.IdentityProvider, conformance.IdentityFixture) {
		provider := fake.NewIdentityProvider(nil)
		fixture := conformance.IdentityFixture{
			Credential: integration.Credential{Kind: integration.CredentialCertificateFingerprint, Value: integration.DigestString("leaf-cert")},
			Expected:   integration.Principal{SubjectDigest: integration.DigestString("subject"), Scopes: []string{"findings:read", "policy:read"}, ExpiresAt: time.Now().Add(time.Hour)},
		}
		if err := provider.Add(fixture.Credential, fixture.Expected); err != nil {
			t.Fatal(err)
		}
		return provider, fixture
	})
}

func TestFakePolicySourceConformance(t *testing.T) {
	t.Parallel()
	conformance.RunPolicySource(t, func(t *testing.T) (integration.PolicySource, conformance.PolicyFixture) {
		source := fake.NewPolicySource()
		known := integration.PolicyRef{ID: "guard-default", Revision: 3}
		if err := source.Put(integration.SignedPolicy{Ref: known, Payload: []byte(`{"apiVersion":"antiflock.policy/v1"}`), Signature: []byte("opaque"), KeyID: "policy:test"}); err != nil {
			t.Fatal(err)
		}
		return source, conformance.PolicyFixture{Known: known, Publish: func(t *testing.T, policy integration.SignedPolicy) {
			if err := source.Put(policy); err != nil {
				t.Fatal(err)
			}
		}}
	})
}

func TestFakeEventSinkConformance(t *testing.T) {
	t.Parallel()
	conformance.RunEventSink(t, func(*testing.T) integration.EventSink { return fake.NewEventSink() })
}

func TestFakeFindingSinkConformance(t *testing.T) {
	t.Parallel()
	conformance.RunFindingSink(t, func(*testing.T) integration.FindingSink { return fake.NewFindingSink() })
}

func TestFakeDecisionConsumerConformance(t *testing.T) {
	t.Parallel()
	conformance.RunDecisionConsumer(t, func(t *testing.T) (integration.DecisionConsumer, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		consumer, err := fake.NewDecisionConsumer(public)
		if err != nil {
			t.Fatal(err)
		}
		return consumer, private
	})
}

func TestFakeRecoveryVerifierConformance(t *testing.T) {
	t.Parallel()
	conformance.RunRecoveryVerifier(t, func(t *testing.T) (integration.RecoveryVerifier, conformance.RecoveryFixture) {
		verifier, err := fake.NewRecoveryVerifier("fake-verifier", nil)
		if err != nil {
			t.Fatal(err)
		}
		node := integration.DigestString("node-reachable")
		verifier.SetReachable(node, true)
		return verifier, conformance.RecoveryFixture{ReachableNodeDigest: node}
	})
}

func TestFakesWireThroughRegistry(t *testing.T) {
	t.Parallel()
	registry := integration.NewRegistry()
	if err := registry.Register("fake", integration.KindExternalWitness, func(_ context.Context, options integration.Options) (any, error) {
		return fake.NewWitness(options["id"], nil)
	}); err != nil {
		t.Fatal(err)
	}
	witness, err := registry.NewExternalWitness(context.Background(), "fake", integration.Options{"id": "wired"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Submit(context.Background(), integration.Checkpoint{DeploymentDigest: integration.DigestString("d"), AuditHeadDigest: integration.DigestString("h"), Sequence: 1, IssuedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}
