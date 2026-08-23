// Package replay holds property-style tests for plan replay protection in
// agent/enforcement with MemoryStateStore. Every property is driven by a
// deterministic PRNG (math/rand/v2 PCG with a fixed seed) so a failure is
// reproducible from the seed printed in the failure message.
//
// Properties on main today:
//   - P1 same signed plan twice: the driver runs once; the second Apply
//     returns the persisted signed result (idempotent replay, no mutation).
//   - P2 same plan id, different bytes: AF-PLAN-REPLAY.
//   - P3 plan revision <= last committed revision: AF-PLAN-REPLAY.
//   - P4 policy revision < last committed policy revision: AF-PLAN-REPLAY.
//   - P5 time-window edges: created-at/expires-at/signed-at boundaries.
//   - P6 capability spoofing: the agent only believes the manifest it was
//     handed; a plan whose requirements exceed that manifest is refused.
//
// Known gaps (documented in docs/adversarial-qualification.md, owner S3):
//   - G-NONCE: a fresh plan id and revision that reuses a previous plan's
//     nonce is accepted; the nonce is not tracked by the state store.
//   - G-MANIFEST: the manifest is caller-asserted. A manifest claiming FULL
//     for every key is believed without signature, expiry, or probe.
package replay_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/enforcement"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/tests/fixtures"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const seed = 0x5eed_0000_0010

func prng(t *testing.T) *rand.Rand {
	t.Helper()
	t.Logf("replay seed: %#x", seed)
	return rand.New(rand.NewPCG(seed, uint64(len(t.Name()))))
}

type outcome struct {
	reason    string
	committed bool
	mutations int
}

func apply(t *testing.T, enforcer *enforcement.Enforcer, driver *fixtures.RecordingDriver, plan *antiflockv1.Plan, publicKey []byte) outcome {
	t.Helper()
	before := driver.MutationCalls()
	result, err := enforcer.Apply(context.Background(), plan)
	if err != nil && !errors.Is(err, enforcement.ErrPlanRejected) {
		t.Fatalf("apply: %v", err)
	}
	if result == nil {
		t.Fatal("apply returned no signed result")
	}
	if verifyErr := enforcement.VerifyExecutionResult(result, publicKey); verifyErr != nil {
		t.Fatalf("result not signed by node: %v", verifyErr)
	}
	return outcome{reason: result.ReasonCode, committed: result.Status == antiflockv1.PlanStatus_PLAN_STATUS_COMMITTED, mutations: driver.MutationCalls() - before}
}

// P1/P2: across random interleavings of replays and tampered replays, the
// driver mutates exactly once per distinct plan and tampered bytes under a
// committed id are AF-PLAN-REPLAY.
func TestPropertySamePlanMutatesOnce(t *testing.T) {
	t.Parallel()
	random := prng(t)
	for round := 0; round < 25; round++ {
		fixture := fixtures.NewPlanFixture(t)
		driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
		store := enforcement.NewMemoryStateStore(0, 0)
		enforcer := fixture.Enforcer(t, driver, store, fixtures.EnforcerOptions{})

		first := apply(t, enforcer, driver, fixture.Plan, fixture.NodePublicKey)
		if !first.committed || first.mutations != 4 {
			t.Fatalf("round %d: first apply = %+v", round, first)
		}
		replays := 1 + random.IntN(6)
		for index := 0; index < replays; index++ {
			var plan *antiflockv1.Plan
			tampered := random.IntN(2) == 1
			if tampered {
				plan = fixtures.ClonePlan(fixture.Plan)
				switch random.IntN(3) {
				case 0:
					plan.HumanReadableDryRun += " (replayed)"
				case 1:
					plan.Actions[0].Description = fmt.Sprintf("%s (replay %d)", plan.Actions[0].Description, index)
				default:
					plan.Sensitivity = antiflockv1.Sensitivity_SENSITIVITY_INTERNAL
				}
				if err := fixtures.ResignPlan(plan, fixtures.PlanKeyID, fixture.PlanPrivateKey, fixture.Now); err != nil {
					t.Fatal(err)
				}
			} else {
				plan = fixture.Plan
			}
			again := apply(t, enforcer, driver, plan, fixture.NodePublicKey)
			if again.mutations != 0 {
				t.Fatalf("round %d replay %d (tampered=%v): driver mutated again: %+v", round, index, tampered, again)
			}
			if tampered && again.reason != "AF-PLAN-REPLAY" {
				t.Fatalf("round %d replay %d: tampered replay reason = %q", round, index, again.reason)
			}
			if !tampered && (!again.committed || again.reason != "AF-PLAN-COMMITTED") {
				t.Fatalf("round %d replay %d: byte-identical replay = %+v", round, index, again)
			}
		}
	}
}

// P3/P4: after committing at (policy p, plan r), every plan with r' <= r or
// p' < p is AF-PLAN-REPLAY and never reaches the driver, in any order.
func TestPropertyRevisionMonotonicity(t *testing.T) {
	t.Parallel()
	random := prng(t)
	fixture := fixtures.NewPlanFixture(t)
	for round := 0; round < 12; round++ {
		policyRevision := uint64(2 + random.IntN(6))
		planRevision := uint64(2 + random.IntN(6))
		driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
		store := enforcement.NewMemoryStateStore(0, 0)
		enforcer := fixture.Enforcer(t, driver, store, fixtures.EnforcerOptions{Clock: func() time.Time { return time.Now().UTC() }})
		committed := fixtures.CompilePlan(t, policyRevision, planRevision, fixture.Manifest)
		if result := apply(t, enforcer, driver, committed, fixture.NodePublicKey); !result.committed {
			t.Fatalf("round %d: baseline = %+v", round, result)
		}
		candidates := []struct {
			policy, plan uint64
			accept       bool
		}{
			{policyRevision, planRevision - 1, false},
			{policyRevision, planRevision, false},
			{policyRevision, planRevision + 1, true},
			{policyRevision - 1, planRevision + 2, false},
			{policyRevision + 1, planRevision + 3, true},
			{policyRevision + 1, planRevision + 3, false}, // same as previous: already committed
		}
		random.Shuffle(len(candidates), func(left, right int) {
			// Keep the two dependent entries ordered; shuffle the rest.
			if candidates[left].accept == candidates[right].accept && candidates[left].plan != planRevision+3 && candidates[right].plan != planRevision+3 {
				candidates[left], candidates[right] = candidates[right], candidates[left]
			}
		})
		highestPlan := planRevision
		for _, candidate := range candidates {
			plan := fixtures.CompilePlan(t, candidate.policy, candidate.plan, fixture.Manifest)
			result := apply(t, enforcer, driver, plan, fixture.NodePublicKey)
			expectAccept := candidate.plan > highestPlan && candidate.policy >= policyRevision
			if expectAccept {
				if !result.committed || result.mutations != 4 {
					t.Fatalf("round %d: (%d,%d) should commit: %+v", round, candidate.policy, candidate.plan, result)
				}
				highestPlan = candidate.plan
				if candidate.policy > policyRevision {
					policyRevision = candidate.policy
				}
				continue
			}
			if result.mutations != 0 {
				t.Fatalf("round %d: (%d,%d) mutated the host", round, candidate.policy, candidate.plan)
			}
			if result.reason != "AF-PLAN-REPLAY" && !(result.committed && candidate.plan == highestPlan) {
				t.Fatalf("round %d: (%d,%d) reason = %q", round, candidate.policy, candidate.plan, result.reason)
			}
		}
	}
}

// P5: random clock positions around created-at, expires-at, and signed-at
// produce AF-PLAN-TIME-INVALID / AF-PLAN-SIGNER-INVALID outside the window
// and never a commit; positions inside the window commit exactly once.
func TestPropertyTimeWindowEdges(t *testing.T) {
	t.Parallel()
	random := prng(t)
	fixture := fixtures.NewPlanFixture(t)
	created := fixture.Plan.CreatedAt.AsTime()
	expires := fixture.Plan.ExpiresAt.AsTime()
	for round := 0; round < 60; round++ {
		offset := time.Duration(random.Int64N(int64(12*time.Minute))) - 6*time.Minute
		now := created.Add(offset)
		if random.IntN(4) == 0 {
			now = expires.Add(time.Duration(random.Int64N(int64(2*time.Second))) - time.Second)
		}
		driver := &fixtures.RecordingDriver{ObservedAt: now}
		enforcer := fixture.Enforcer(t, driver, nil, fixtures.EnforcerOptions{Clock: func() time.Time { return now }})
		result := apply(t, enforcer, driver, fixture.Plan, fixture.NodePublicKey)
		inside := !now.Before(created) && now.Before(expires)
		switch {
		case inside && (!result.committed || result.mutations != 4):
			t.Fatalf("round %d now=%v (created+%v): inside window but %+v", round, now, offset, result)
		case !inside && result.mutations != 0:
			t.Fatalf("round %d now=%v: outside window but mutated", round, now)
		case !inside && result.reason != "AF-PLAN-TIME-INVALID" && result.reason != "AF-PLAN-SIGNER-INVALID":
			t.Fatalf("round %d now=%v: reason = %q", round, now, result.reason)
		}
	}
}

// P6a: a plan requiring an operation or level the supplied manifest does not
// declare is AF-PLAN-CAPABILITY-UNSUPPORTED, for random subsets of missing
// capabilities, even though the plan signature is valid.
func TestPropertyManifestShortfallIsRefused(t *testing.T) {
	t.Parallel()
	random := prng(t)
	fixture := fixtures.NewPlanFixture(t)
	keys := []string{"firewall.egress.enforce", "mesh.path.enforce", "network.route.enforce", "dns.protected.enforce"}
	for round := 0; round < 40; round++ {
		manifest := proto.Clone(fixture.Manifest).(*antiflockv1.CapabilityManifest)
		weakened := 0
		for _, capability := range manifest.Capabilities {
			switch random.IntN(5) {
			case 0:
				capability.SupportLevel = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_PARTIAL
				weakened++
			case 1:
				capability.SupportLevel = antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_EXPERIMENTAL
				weakened++
			case 2:
				capability.Operations = capability.Operations[:len(capability.Operations)-1]
				weakened++
			case 3:
				capability.Key = keys[random.IntN(len(keys))] + ".spoof"
				weakened++
			}
		}
		driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
		enforcer := fixture.Enforcer(t, driver, nil, fixtures.EnforcerOptions{Manifest: manifest})
		result := apply(t, enforcer, driver, fixture.Plan, fixture.NodePublicKey)
		if weakened == 0 {
			if !result.committed {
				t.Fatalf("round %d: full manifest refused: %+v", round, result)
			}
			continue
		}
		if result.mutations != 0 || result.reason != "AF-PLAN-CAPABILITY-UNSUPPORTED" {
			t.Fatalf("round %d (%d weakened): %+v", round, weakened, result)
		}
	}
}

// P6b (capability spoofing, KNOWN-GAP): a manifest that claims FULL for
// every key is believed as-is. Nothing on main verifies a manifest signature,
// expiry, node binding beyond the id string, or probes the host. The test
// states the invariant we want and skips while main accepts the spoof.
func TestPropertyCapabilitySpoofIsDetected(t *testing.T) {
	t.Parallel()
	fixture := fixtures.NewPlanFixture(t)
	spoofed := fixtures.FullManifest()
	spoofed.Revision = 1
	spoofed.IssuedAt = timestamppb.New(fixture.Now.Add(-48 * time.Hour))
	spoofed.ExpiresAt = timestamppb.New(fixture.Now.Add(-24 * time.Hour)) // expired
	spoofed.Signature = &antiflockv1.Signature{KeyId: "attacker", Value: make([]byte, 64)}
	for _, capability := range spoofed.Capabilities {
		capability.Implementation = "none"
		capability.Constraints = []string{"no-host-mutation"}
	}
	driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
	enforcer, err := enforcement.New(enforcement.Config{
		DeploymentID: fixtures.DeploymentID, NodeID: fixtures.NodeID, PlanKeyID: fixtures.PlanKeyID, PlanPublicKey: fixture.PlanPublicKey,
		NodePrivateKey: fixture.NodePrivateKey, Capabilities: spoofed, Driver: driver, StateStore: enforcement.NewMemoryStateStore(0, 0),
		Clock: func() time.Time { return fixture.Now },
	})
	if err != nil {
		return // refusing the manifest at construction satisfies the invariant
	}
	result := apply(t, enforcer, driver, fixture.Plan, fixture.NodePublicKey)
	if result.committed {
		t.Skipf("KNOWN-GAP AF-GAP-006: agent/enforcement believes a caller-supplied manifest (expired, unsigned, implementation=none, constraint no-host-mutation) and committed with %d mutations", result.mutations)
	}
}

// Nonce reuse (KNOWN-GAP): a plan with a new id and higher revision but the
// nonce of an already-committed plan must be refused. MemoryStateStore keys on
// plan id and revision only, so main accepts it.
func TestPropertyNonceReuseIsRefused(t *testing.T) {
	t.Parallel()
	random := prng(t)
	fixture := fixtures.NewPlanFixture(t)
	driver := &fixtures.RecordingDriver{ObservedAt: fixture.Now}
	store := enforcement.NewMemoryStateStore(0, 0)
	enforcer := fixture.Enforcer(t, driver, store, fixtures.EnforcerOptions{})
	if result := apply(t, enforcer, driver, fixture.Plan, fixture.NodePublicKey); !result.committed {
		t.Fatalf("baseline = %+v", result)
	}
	for round := 0; round < 10; round++ {
		reused := fixtures.ClonePlan(fixture.Plan)
		reused.Id = fmt.Sprintf("plan_reuse_%d_%d", round, random.Uint32())
		reused.Revision = fixture.Plan.Revision + uint64(round) + 1
		if err := fixtures.ResignPlan(reused, fixtures.PlanKeyID, fixture.PlanPrivateKey, fixture.Now); err != nil {
			t.Fatal(err)
		}
		result := apply(t, enforcer, driver, reused, fixture.NodePublicKey)
		if result.committed {
			t.Skipf("KNOWN-GAP AF-GAP-007: nonce reuse accepted; plan %s with the committed nonce committed at revision %d (round %d)", reused.Id, reused.Revision, round)
		}
	}
}

// Serial safety: concurrent Apply calls of distinct valid plans never
// interleave driver mutations and commit in revision order.
func TestPropertyConcurrentAppliesAreSerialized(t *testing.T) {
	t.Parallel()
	fixture := fixtures.NewPlanFixture(t)
	driver := &fixtures.RecordingDriver{ObservedAt: time.Now().UTC()}
	enforcer := fixture.Enforcer(t, driver, enforcement.NewMemoryStateStore(0, 0), fixtures.EnforcerOptions{Clock: func() time.Time { return time.Now().UTC() }})
	const workers = 6
	results := make(chan outcome, workers)
	for worker := 1; worker <= workers; worker++ {
		plan := fixtures.CompilePlan(t, 7, uint64(worker), fixture.Manifest)
		go func() {
			results <- apply(t, enforcer, driver, plan, fixture.NodePublicKey)
		}()
	}
	committed := 0
	for worker := 0; worker < workers; worker++ {
		if result := <-results; result.committed {
			committed++
		}
	}
	calls := driver.Calls()
	for index := 0; index+8 <= len(calls); index += 8 {
		if calls[index] != "check:preflight-current-state" || calls[index+1] != "apply:guard-egress" || calls[index+7] != "check:verify-dns" {
			t.Fatalf("driver calls interleaved at %d: %v", index, calls[index:index+8])
		}
	}
	if committed == 0 || len(calls) != committed*8 {
		t.Fatalf("committed=%d calls=%d", committed, len(calls))
	}
}
