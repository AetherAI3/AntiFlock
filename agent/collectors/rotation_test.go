package collectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
)

const singleRotationRoute = "Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0\t00000000 010200C0 0003 0 0 100 00000000 0 0 0\n"

type captureSequence struct{ last uint64 }

func (sequence *captureSequence) NextSequence(context.Context) (uint64, error) {
	sequence.last++
	return sequence.last, nil
}

func rotationTestIntent(t *testing.T, now time.Time) ([]byte, RotationEnrollment) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	intent := rotationIntent{
		IssuedAtMS: now.Add(-3 * time.Second).UnixMilli(), ObserveAfterMS: now.Add(-time.Second).UnixMilli(),
		ValidUntilMS: now.Add(time.Second).UnixMilli(), Sequence: 4, OwnerID: "pilot-owner",
		WorkloadID: "pilot-app", PreviousProfile: strings.Repeat("1", 64), NextProfile: strings.Repeat("2", 64),
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rotationEnvelope{
		Payload: intent, Schema: rotationIntentSchema,
		Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(rotationIntentSchema+"\x00"), payload...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, RotationEnrollment{intent.OwnerID, intent.WorkloadID, key.Public().(ed25519.PublicKey)}
}

func rotationTestBuilder(t *testing.T, clock func() time.Time) (*TelemetryBuilder, ed25519.PublicKey, *captureSequence) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	sequences := &captureSequence{}
	builder, err := NewTelemetryBuilder("pilot", "route-observer", "boot", sequences,
		EventSignerFunc(func(event *model.EventEnvelope) error {
			return events.SignAt(event, event.NodeID, key, clock())
		}), clock)
	if err != nil {
		t.Fatal(err)
	}
	return builder, key.Public().(ed25519.PublicKey), sequences
}

func TestRotationCaptureCorrelatesMeasuredRouteBeforeSigning(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	raw, enrollment := rotationTestIntent(t, now)
	builder, routeKey, sequences := rotationTestBuilder(t, func() time.Time { return now })
	wire, err := builder.captureRotationRoute(t.Context(), raw, enrollment, func() ([]byte, error) {
		return []byte(singleRotationRoute), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Digest checked independently against the Python Predator v1 receipt.
	const expectedID = "rotation-0b3084b6cb9dec12e32294f1f5967040f749cda3d1790463694a7c58838e9b09"
	if wire.GetCorrelationId() != expectedID || wire.GetSequence() != 1 || sequences.last != 1 {
		t.Fatalf("unexpected binding %s sequence %d", wire.GetCorrelationId(), wire.GetSequence())
	}
	var route antiflockv1.RouteObservation
	if err := proto.Unmarshal(wire.GetPayload().GetValue(), &route); err != nil || !route.GetDefaultRoute() ||
		route.GetDestination() != "0.0.0.0/0" || route.GetGateway() != "192.0.2.1" {
		t.Fatal("capture did not retain the actual route observation")
	}
	source, err := model.EventFromProto(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := events.VerifySource(source, routeKey); err != nil {
		t.Fatal(err)
	}
	source.CorrelationID += "x"
	if events.VerifySource(source, routeKey) == nil {
		t.Fatal("correlation was not immutable")
	}
}

func TestRotationCaptureRefusesUnknownIntentBeforeReadingRoute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	raw, enrollment := rotationTestIntent(t, now)
	builder, _, sequences := rotationTestBuilder(t, func() time.Time { return now })
	read := func() ([]byte, error) {
		t.Fatal("read route table before owner intent was admitted")
		return nil, nil
	}
	for _, value := range [][]byte{append(bytes.Clone(raw), '\n'),
		bytes.Replace(raw, []byte(`"sequence":4`), []byte(`"sequence":3,"sequence":4`), 1),
		bytes.Replace(raw, []byte("pilot-owner"), []byte("evil-owner!"), 1)} {
		if _, err := builder.captureRotationRoute(t.Context(), value, enrollment, read); err == nil {
			t.Fatal("accepted invalid owner intent")
		}
	}
	enrollment.IntentPublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := builder.captureRotationRoute(t.Context(), raw, enrollment, read); err == nil || sequences.last != 0 {
		t.Fatal("accepted unknown owner key")
	}
}

func TestRotationCaptureRefusesAmbiguityAndExpiredWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	raw, enrollment := rotationTestIntent(t, now)
	builder, _, sequences := rotationTestBuilder(t, func() time.Time { return now })
	duplicate := singleRotationRoute + strings.SplitN(singleRotationRoute, "\n", 2)[1]
	for _, table := range []string{"Iface Destination\n", duplicate, "malformed"} {
		if _, err := builder.captureRotationRoute(t.Context(), raw, enrollment, func() ([]byte, error) {
			return []byte(table), nil
		}); err == nil || sequences.last != 0 {
			t.Fatal("accepted an incomplete or ambiguous default route")
		}
	}
	if _, err := builder.captureRotationRoute(t.Context(), raw, enrollment, func() ([]byte, error) {
		now = now.Add(time.Second)
		return []byte(singleRotationRoute), nil
	}); err == nil || sequences.last != 0 {
		t.Fatal("accepted observation at exclusive intent expiry")
	}
}
