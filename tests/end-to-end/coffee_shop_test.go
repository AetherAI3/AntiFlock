package endtoend_test

import (
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/sim"
)

func TestCoffeeShopFailureHoldRecoveryAndRelease(t *testing.T) {
	t.Parallel()
	result, err := sim.RunCoffeeShop(time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(result.Timeline) != 5 || result.Timeline[2].Kind != "action.held" || result.Timeline[2].ActionDecision != "HOLD" {
		t.Fatalf("missing held action: %#v", result.Timeline)
	}
	if result.Timeline[4].Kind != "action.allowed" || result.Timeline[4].ActionDecision != "ALLOW" || result.FinalProtectionState != "PROTECTED" {
		t.Fatalf("missing verified recovery release: %#v", result)
	}
	for _, step := range result.Timeline {
		if step.EvidenceClass != "DETECTED" {
			t.Fatalf("simulation evidence was upgraded: %#v", step)
		}
	}
}
