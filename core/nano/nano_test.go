package nano_test

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/nano"
)

const probeWatch = `strategy ProbeWatch {
  agent Watchdog
  every 1s {
    if REASON_404_PROBING == 1
    and CONFIDENCE > 0.8 {
      execute()
    }
  }
}`

func TestProbeWatchCompilesToCanonicalNanoIR(t *testing.T) {
	t.Parallel()
	program, err := nano.Compile(probeWatch, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if err := nano.AdmitWatchdog(program); err != nil {
		t.Fatal(err)
	}
	canonical, err := program.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"Strategy","nanoIrVersion":"0.1.0","name":"ProbeWatch","effects":["intent.emit","log.append"],"nodes":[{"type":"Schedule","interval":"1s"},{"type":"Condition","signal":"REASON_404_PROBING","operator":"==","value":1},{"type":"Condition","signal":"CONFIDENCE","operator":">","value":0.8},{"type":"Intent","action":"EXECUTE"},{"type":"Agent","name":"Watchdog"}]}`
	if string(canonical) != want {
		t.Fatalf("canonical IR\n got: %s\nwant: %s", canonical, want)
	}
	first, _ := program.Digest()
	second, _ := program.Digest()
	if first == "" || first != second || nano.UpstreamCommit != "40f697ba9020a4d4fee985406779c0d90ea2d6f4" {
		t.Fatalf("unstable program provenance: %q %q %q", first, second, nano.UpstreamCommit)
	}
}

func TestFindingEvaluationPersistsScheduleCursor(t *testing.T) {
	t.Parallel()
	program, err := nano.Compile(probeWatch, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	frame, inputDigest, err := nano.FrameForFinding(nano.FindingContext{
		FindingID: "finding-404", NodeID: "node-test", ReasonCode: "404 probing",
		Confidence: 0.91, ObservedUnix: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, cursor, err := nano.Evaluate(program, frame, nano.Cursor{}, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Intents) != 1 || result.Intents[0].Action != "EXECUTE" || cursor.NextDueUnix != 101 {
		t.Fatalf("first result=%#v cursor=%#v", result, cursor)
	}
	result, cursor, err = nano.Evaluate(program, frame, cursor, nano.DefaultLimits)
	if err != nil || len(result.Intents) != 0 || cursor.NextDueUnix != 101 {
		t.Fatalf("same tick refired: result=%#v cursor=%#v err=%v", result, cursor, err)
	}
	programDigest, _ := program.Digest()
	proposals, err := nano.BuildProposals(
		nano.EvaluationResult{Intents: []nano.EmittedIntent{{Action: "EXECUTE", Timestamp: 100}}},
		nano.BindingScramblerSimulation, programDigest, inputDigest, "node-test",
		time.Unix(160, 0).UTC().Format(time.RFC3339Nano),
	)
	if err != nil || len(proposals) != 1 {
		t.Fatalf("proposal=%#v err=%v", proposals, err)
	}
	proposal := proposals[0]
	if proposal.ApplicationID != "antiflock-nano" || proposal.ActionType != "scrambler.simulate" ||
		proposal.DataClass != "network-control" || proposal.Sensitivity != "SENSITIVITY_OPERATOR_PRIVATE" ||
		len(proposal.Destinations) != 1 || proposal.Destinations[0] != "local://scrambler/simulation" {
		t.Fatalf("proposal escaped admitted binding: %#v", proposal)
	}
	encoded, _ := json.Marshal(proposal)
	if string(encoded) == "" {
		t.Fatal("proposal was not serializable")
	}
}

func TestWatchdogAdmissionAndFramesFailClosed(t *testing.T) {
	t.Parallel()
	trading, err := nano.Compile(`strategy Trading { every 1s { if RSI < 30 { buy(BTC, 0.9) } } }`, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if err := nano.AdmitWatchdog(trading); !errors.Is(err, nano.ErrAdmissionDenied) {
		t.Fatalf("trading intent admission error = %v", err)
	}
	program, _ := nano.Compile(probeWatch, nano.DefaultLimits)
	for name, frame := range map[string]nano.Frame{
		"missing signal": {Timestamps: []int64{100}, Signals: map[string][]float64{"CONFIDENCE": {0.9}}},
		"nan": {Timestamps: []int64{100}, Signals: map[string][]float64{
			"REASON_404_PROBING": {1}, "CONFIDENCE": {math.NaN()},
		}},
		"regressed time": {Timestamps: []int64{100, 99}, Signals: map[string][]float64{
			"REASON_404_PROBING": {1, 1}, "CONFIDENCE": {0.9, 0.9},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, evaluateErr := nano.Evaluate(program, frame, nano.Cursor{}, nano.DefaultLimits); !errors.Is(evaluateErr, nano.ErrInvalidFrame) {
				t.Fatalf("error = %v", evaluateErr)
			}
		})
	}
}

func TestSyntaxAndResourceBudgets(t *testing.T) {
	t.Parallel()
	if _, err := nano.Compile("strategy Empty { }", nano.DefaultLimits); err == nil {
		t.Fatal("empty Nano IR compiled")
	}
	if _, err := nano.Compile("strategy Broken { every 0s { } }", nano.DefaultLimits); err == nil {
		t.Fatal("zero interval compiled")
	}
	if _, err := nano.Compile("strategy Broken { every 1s { if X = 1 { execute() } } }", nano.DefaultLimits); err == nil {
		t.Fatal("unknown operator compiled")
	}
	limits := nano.DefaultLimits
	limits.MaxConditions = 1
	if _, err := nano.Compile(probeWatch, limits); !errors.Is(err, nano.ErrLimitExceeded) {
		t.Fatalf("condition budget error = %v", err)
	}
	program, _ := nano.Compile(probeWatch, nano.DefaultLimits)
	limits = nano.DefaultLimits
	limits.MaxInstructions = 1
	frame, _, _ := nano.FrameForFinding(nano.FindingContext{
		FindingID: "finding", NodeID: "node", ReasonCode: "404 probing", Confidence: 0.9, ObservedUnix: 1,
	})
	if _, _, err := nano.Evaluate(program, frame, nano.Cursor{}, limits); !errors.Is(err, nano.ErrInstructionLimit) {
		t.Fatalf("instruction budget error = %v", err)
	}
}

func TestNoMatchAndObserveNeverCreateMutationProposal(t *testing.T) {
	t.Parallel()
	program, err := nano.Compile(`strategy ObserveOnly { every 1s { if CONFIDENCE > 0.8 { observe() } } }`, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := nano.Evaluate(program, nano.Frame{
		Timestamps: []int64{10}, Signals: map[string][]float64{"CONFIDENCE": {0.9}},
	}, nano.Cursor{}, nano.DefaultLimits)
	if err != nil || len(result.Intents) != 1 {
		t.Fatalf("observe result=%#v err=%v", result, err)
	}
	digest, _ := program.Digest()
	proposals, err := nano.BuildProposals(result, nano.BindingCountermeasurePlan, digest, digest, "node", time.Unix(20, 0).UTC().Format(time.RFC3339Nano))
	if err != nil || len(proposals) != 0 {
		t.Fatalf("observe produced proposal=%#v err=%v", proposals, err)
	}
}
