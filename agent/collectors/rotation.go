package collectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
)

const (
	rotationIntentSchema    = "predator.gen4.rotation-intent.v1"
	MaxRotationIntentBytes  = 2048
	maximumRotationWindowMS = 60_000
)

var (
	rotationScope     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	rotationProfile   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rotationSignature = regexp.MustCompile(`^[0-9a-f]{128}$`)
	errRotationIntent = errors.New("owner rotation intent refused")
)

// RotationEnrollment pins the only allowed plan signer, owner, and workload.
type RotationEnrollment struct {
	OwnerID         string
	WorkloadID      string
	IntentPublicKey ed25519.PublicKey
}

// Field order is part of Predator's sorted, compact JSON signing profile.
type rotationIntent struct {
	IssuedAtMS      int64  `json:"issued_at_ms"`
	NextProfile     string `json:"next_profile"`
	ObserveAfterMS  int64  `json:"observe_after_ms"`
	OwnerID         string `json:"owner_id"`
	PreviousProfile string `json:"previous_profile"`
	Sequence        int64  `json:"sequence"`
	ValidUntilMS    int64  `json:"valid_until_ms"`
	WorkloadID      string `json:"workload_id"`
}

type rotationEnvelope struct {
	Payload   rotationIntent `json:"payload"`
	Schema    string         `json:"schema"`
	Signature string         `json:"signature"`
}

func verifyRotationIntent(raw []byte, enrollment RotationEnrollment) (rotationIntent, string, error) {
	var envelope rotationEnvelope
	if len(raw) == 0 || len(raw) > MaxRotationIntentBytes || len(enrollment.IntentPublicKey) != ed25519.PublicKeySize ||
		json.Unmarshal(raw, &envelope) != nil || envelope.Schema != rotationIntentSchema ||
		!rotationSignature.MatchString(envelope.Signature) {
		return rotationIntent{}, "", errRotationIntent
	}
	// Exact canonical comparison rejects unknown, duplicate and missing fields,
	// as well as representations accepted only by one JSON implementation.
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return rotationIntent{}, "", errRotationIntent
	}
	intent := envelope.Payload
	if !rotationScope.MatchString(intent.OwnerID) || !rotationScope.MatchString(intent.WorkloadID) ||
		intent.OwnerID != enrollment.OwnerID || intent.WorkloadID != enrollment.WorkloadID || intent.Sequence < 1 ||
		!rotationProfile.MatchString(intent.PreviousProfile) || !rotationProfile.MatchString(intent.NextProfile) ||
		intent.IssuedAtMS < 0 || intent.IssuedAtMS > intent.ObserveAfterMS ||
		intent.ObserveAfterMS >= intent.ValidUntilMS || intent.ValidUntilMS-intent.IssuedAtMS > maximumRotationWindowMS {
		return rotationIntent{}, "", errRotationIntent
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return rotationIntent{}, "", errRotationIntent
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(enrollment.IntentPublicKey, append([]byte(rotationIntentSchema+"\x00"), payload...), signature) {
		return rotationIntent{}, "", errRotationIntent
	}
	digest := sha256.Sum256(append(payload, '\n'))
	return intent, "rotation-" + hex.EncodeToString(digest[:]), nil
}

func (intent rotationIntent) canObserve(at time.Time) bool {
	millis := at.UnixMilli()
	return intent.ObserveAfterMS <= millis && millis < intent.ValidUntilMS
}

// CaptureRotationRoute emits a fresh signed observation of the single active
// default IPv4 route in the Linux main table. It does not change any route.
func (builder *TelemetryBuilder) CaptureRotationRoute(ctx context.Context, raw []byte, enrollment RotationEnrollment) (*antiflockv1.EventEnvelope, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("rotation route capture requires Linux")
	}
	return builder.captureRotationRoute(ctx, raw, enrollment, readRotationRouteTable)
}

func readRotationRouteTable() ([]byte, error) {
	file, err := os.Open(defaultRouteTable)
	if err != nil {
		return nil, errors.New("read Linux route table")
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maximumSourceSize+1))
}

func (builder *TelemetryBuilder) captureRotationRoute(ctx context.Context, raw []byte, enrollment RotationEnrollment, readRoutes func() ([]byte, error)) (*antiflockv1.EventEnvelope, error) {
	if builder == nil {
		return nil, errors.New("telemetry builder is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	intent, correlationID, err := verifyRotationIntent(raw, enrollment)
	if err != nil {
		return nil, err
	}
	startedAt := builder.clock().UTC()
	if !intent.canObserve(startedAt) {
		return nil, errors.New("outside owner rotation observation window")
	}
	content, err := readRoutes()
	observedAt := builder.clock().UTC()
	if err != nil || len(content) == 0 || len(content) > maximumSourceSize {
		return nil, errors.New("read bounded Linux route table")
	}
	if observedAt.Before(startedAt) || !intent.canObserve(observedAt) {
		return nil, errors.New("outside owner rotation observation window")
	}
	routes, err := parseRoutes(content, observedAt, false)
	if err != nil || len(routes) != 1 {
		return nil, errors.New("one active Linux default IPv4 route is required")
	}
	wire, _, err := builder.build(ctx, Observation{
		Kind: "network.route_changed", ObservedAt: observedAt, Payload: routes[0],
		Classification: model.EvidenceDetected, Confidence: 1, Sensitivity: model.SensitivityOperatorPrivate,
	}, correlationID)
	if err != nil {
		return nil, errors.New("sign rotation route observation")
	}
	signedAt := wire.GetSourceSignature().GetSignedAt().AsTime()
	finishedAt := builder.clock().UTC()
	if signedAt.Before(observedAt) || finishedAt.Before(signedAt) || !intent.canObserve(finishedAt) {
		return nil, errors.New("outside owner rotation observation window")
	}
	return wire, nil
}
