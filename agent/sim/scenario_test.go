package sim

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCoffeeShopScenarioIsDeterministicFailClosedAndEvidenceHonest(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	first, err := RunCoffeeShop(start)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunCoffeeShop(start)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("fixed simulation input did not produce fixed output")
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"evidenceClass":"VERIFIED"`) {
		t.Fatal("simulation fabricated VERIFIED evidence")
	}
	if first.Timeline[1].ProtectionState != "EXPOSED" || first.Timeline[1].EnforcementState != "HOLDING" || first.Timeline[2].ActionDecision != "HOLD" {
		t.Fatalf("unsafe phase = %#v", first.Timeline[:3])
	}
	if first.FinalProtectionState != "PROTECTED" || first.FinalActionDecision != "ALLOW" {
		t.Fatalf("final state = %s/%s", first.FinalProtectionState, first.FinalActionDecision)
	}
}

func TestCoffeeShopAuditChainDetectsTampering(t *testing.T) {
	t.Parallel()
	result, err := RunCoffeeShop(time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result.Timeline[1].SafeDescription = "tampered"
	if err := result.Validate(); err == nil {
		t.Fatal("tampered simulation audit chain was accepted")
	}
}
