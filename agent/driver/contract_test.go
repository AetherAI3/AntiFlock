package driver_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

func TestValidateTargetRejectsShellMetacharacters(t *testing.T) {
	t.Parallel()
	hostile := []string{
		"", "a b", "a\tb", "a;b", "a|b", "a&b", "$x", "`x`", "a<b", "a>b", "(a)", "{a}", "[a]", "a*", "a?", "a!", "~a",
		"a'", "a\"", "a\\b", "a#b", "a\n", "a\x00", "\x1b[0m", "café", "a\u200bb", strings.Repeat("a", driver.MaxTargetLength+1),
	}
	for _, target := range hostile {
		if err := driver.ValidateTarget(target); !errors.Is(err, driver.ErrUnsafeTarget) {
			t.Fatalf("target %q accepted (err = %v)", target, err)
		}
	}
	for _, safe := range []string{"eth0", "protected-egress", "10.0.0.0/8", "fd00::1", "table.inet_guard", "a,b", "x=y", "v1.2.3", "dns:53", "name@host", "50%"} {
		if err := driver.ValidateTarget(safe); err != nil {
			t.Fatalf("target %q rejected: %v", safe, err)
		}
	}
}

func TestSnapshotDigestIgnoresCaptureTimeAndRequiresOrder(t *testing.T) {
	t.Parallel()
	base := driver.Snapshot{
		SchemaVersion: driver.ContractVersion, DriverName: "memory",
		Scope:      driver.Scope{OperationType: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_FIREWALL},
		Entries:    []driver.SnapshotEntry{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}},
		CapturedAt: time.Unix(1, 0),
	}
	first, err := base.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	later := base
	later.CapturedAt = time.Unix(2, 0)
	second, err := later.Digest()
	if err != nil || first != second {
		t.Fatalf("digest changed with capture time: %s != %s (%v)", first, second, err)
	}
	unsorted := base
	unsorted.Entries = []driver.SnapshotEntry{{Key: "b", Value: "2"}, {Key: "a", Value: "1"}}
	if _, err := unsorted.Digest(); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("unsorted entries: err = %v, want ErrInvalidRequest", err)
	}
	changed := base
	changed.Entries = []driver.SnapshotEntry{{Key: "a", Value: "1"}, {Key: "b", Value: "3"}}
	third, _ := changed.Digest()
	if third == first {
		t.Fatal("digest did not change with content")
	}
	hostile := base
	hostile.Entries = []driver.SnapshotEntry{{Key: "a", Value: "raw\x1b[31moutput"}}
	if _, err := hostile.Digest(); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("control characters in value: err = %v, want ErrInvalidRequest", err)
	}
}

func TestApplyRequestBindsTargetAndReservation(t *testing.T) {
	t.Parallel()
	key := driver.ReservationKey{PlanID: "plan", PolicyRevision: 1, PlanRevision: 2, Nonce: "01", Fingerprint: "fp"}
	digest, _ := key.Digest()
	token := driver.ReservationToken{Key: key, Token: digest, IssuedAt: time.Unix(1, 0)}
	newOperation := func() *antiflockv1.PlanOperation {
		return &antiflockv1.PlanOperation{Id: "op", Type: antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_ROUTE, Target: "t"}
	}
	valid := driver.ApplyRequest{
		PlanID: "plan", PlanRevision: 2, OperationID: "op", Target: "t", Operation: newOperation(), Reservation: token, Timeout: time.Second,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	cases := map[string]struct {
		mutate func(*driver.ApplyRequest)
		want   error
	}{
		"target mismatch":     {func(r *driver.ApplyRequest) { r.Target = "other" }, driver.ErrTargetMismatch},
		"hostile target":      {func(r *driver.ApplyRequest) { r.Target = "t;x"; r.Operation.Target = "t;x" }, driver.ErrUnsafeTarget},
		"foreign token":       {func(r *driver.ApplyRequest) { r.Reservation.Token = strings.Repeat("0", 64) }, driver.ErrReservationInvalid},
		"reservation plan":    {func(r *driver.ApplyRequest) { r.PlanID = "other" }, driver.ErrReservationInvalid},
		"reservation rev":     {func(r *driver.ApplyRequest) { r.PlanRevision = 3 }, driver.ErrReservationInvalid},
		"operation id":        {func(r *driver.ApplyRequest) { r.OperationID = "other" }, driver.ErrInvalidRequest},
		"nil operation":       {func(r *driver.ApplyRequest) { r.Operation = nil }, driver.ErrInvalidRequest},
		"unspecified type":    {func(r *driver.ApplyRequest) { r.Operation.Type = 0 }, driver.ErrInvalidRequest},
		"zero timeout":        {func(r *driver.ApplyRequest) { r.Timeout = 0 }, driver.ErrInvalidRequest},
		"oversized timeout":   {func(r *driver.ApplyRequest) { r.Timeout = driver.MaxOperationTimeout + 1 }, driver.ErrInvalidRequest},
		"zero revision":       {func(r *driver.ApplyRequest) { r.PlanRevision = 0 }, driver.ErrInvalidRequest},
		"zero issued-at":      {func(r *driver.ApplyRequest) { r.Reservation.IssuedAt = time.Time{} }, driver.ErrReservationInvalid},
		"control char planid": {func(r *driver.ApplyRequest) { r.PlanID = "plan\n" }, driver.ErrInvalidRequest},
	}
	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := valid
			request.Operation = newOperation()
			testCase.mutate(&request)
			if err := request.Validate(); !errors.Is(err, testCase.want) {
				t.Fatalf("err = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestReceiptDigestIsStableAndContentBound(t *testing.T) {
	t.Parallel()
	receipt := driver.Receipt{
		SchemaVersion: driver.ContractVersion, Kind: driver.ReceiptKindApply, PlanID: "plan", PlanRevision: 1, OperationID: "op",
		Target: "t", OwnershipToken: strings.Repeat("a", 64), Digest: strings.Repeat("b", 64), ReasonCode: driver.ReasonApplied,
		At: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	}
	first, err := receipt.ContentDigest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, _ := receipt.ContentDigest()
	if first != second {
		t.Fatal("digest not stable")
	}
	// pinnedReceiptDigest is the digest of the receipt above at ContractVersion
	// 1; a layout change must fail here rather than silently re-identify
	// every stored receipt.
	const pinnedReceiptDigest = "2371a87b3e5d4834850af03ffe814c5994eb75632d206d6e2a873c58672b1502"
	if first != pinnedReceiptDigest {
		t.Fatalf("receipt digest layout changed: %s", first)
	}
	for name, mutate := range map[string]func(*driver.Receipt){
		"kind":   func(r *driver.Receipt) { r.Kind = driver.ReceiptKindRollback },
		"plan":   func(r *driver.Receipt) { r.PlanID = "other" },
		"rev":    func(r *driver.Receipt) { r.PlanRevision = 2 },
		"target": func(r *driver.Receipt) { r.Target = "u" },
		"token":  func(r *driver.Receipt) { r.OwnershipToken = strings.Repeat("c", 64) },
		"digest": func(r *driver.Receipt) { r.Digest = strings.Repeat("d", 64) },
		"reason": func(r *driver.Receipt) { r.ReasonCode = driver.ReasonRolledBack },
		"at":     func(r *driver.Receipt) { r.At = r.At.Add(time.Nanosecond) },
	} {
		mutated := receipt
		mutate(&mutated)
		digest, err := mutated.ContentDigest()
		if err != nil || digest == first {
			t.Fatalf("%s: digest unchanged or invalid (%v)", name, err)
		}
	}
	store := driver.NewMemoryReceiptStore()
	if err := store.Append(t.Context(), receipt); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := store.Append(t.Context(), receipt); !errors.Is(err, driver.ErrReceiptDuplicate) {
		t.Fatalf("duplicate append: err = %v, want ErrReceiptDuplicate", err)
	}
	listed, err := store.List(t.Context(), "plan")
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %d (%v), want 1", len(listed), err)
	}
}

func TestPrivilegeBoundaryMustBeShellFree(t *testing.T) {
	t.Parallel()
	boundary := driver.PrivilegeBoundary{Binary: "/usr/sbin/nft", ArgumentPattern: []string{"-f", "-"}, Privilege: "CAP_NET_ADMIN", ShellFree: true}
	if err := boundary.Validate(); err != nil {
		t.Fatalf("valid boundary rejected: %v", err)
	}
	boundary.ShellFree = false
	if err := boundary.Validate(); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("shell boundary accepted: %v", err)
	}
	plan := driver.CommandPlan{Executable: "/usr/sbin/nft", Arguments: []string{"-f", "-"}, Input: "add table inet guard\n"}
	if err := plan.Validate(); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	plan.Arguments = []string{"-c", "nft; rm -rf /"}
	if err := plan.Validate(); !errors.Is(err, driver.ErrUnsafeTarget) {
		t.Fatalf("shell argument accepted: %v", err)
	}
	plan.Arguments = nil
	plan.Input = "add table\x00"
	if err := plan.Validate(); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("control byte in input accepted: %v", err)
	}
}

func TestVerificationCannotPassWithDifferentDigests(t *testing.T) {
	t.Parallel()
	result := driver.VerificationResult{
		OwnershipToken: strings.Repeat("a", 64), ExpectedDigest: strings.Repeat("b", 64), ObservedDigest: strings.Repeat("c", 64),
		Verified: true, ReasonCodes: []string{driver.ReasonVerified}, At: time.Unix(1, 0),
	}
	if err := result.Validate(); !errors.Is(err, driver.ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestApprovalDigestBindsEveryField(t *testing.T) {
	t.Parallel()
	base, err := driver.ApprovalDigest("plan", 1, "op", "t", "operator")
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for name, other := range map[string][5]any{
		"plan":     {"plan2", uint64(1), "op", "t", "operator"},
		"revision": {"plan", uint64(2), "op", "t", "operator"},
		"op":       {"plan", uint64(1), "op2", "t", "operator"},
		"target":   {"plan", uint64(1), "op", "t2", "operator"},
		"approver": {"plan", uint64(1), "op", "t", "policy-core"},
	} {
		digest, err := driver.ApprovalDigest(other[0].(string), other[1].(uint64), other[2].(string), other[3].(string), other[4].(string))
		if err != nil || digest == base {
			t.Fatalf("%s: digest unchanged or invalid (%v)", name, err)
		}
	}
	if _, err := driver.ApprovalDigest("plan", 1, "op", "t;x", "operator"); !errors.Is(err, driver.ErrUnsafeTarget) {
		t.Fatalf("hostile target: err = %v, want ErrUnsafeTarget", err)
	}
}
