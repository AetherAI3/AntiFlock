package model_test

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEventFromProtoRejectsUnknownWireData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*antiflockv1.EventEnvelope)
	}{
		{
			name: "top-level unknown enum",
			mutate: func(event *antiflockv1.EventEnvelope) {
				event.Classification = antiflockv1.EvidenceClass(999)
			},
		},
		{
			name: "nested unknown enum",
			mutate: func(event *antiflockv1.EventEnvelope) {
				event.Evidence = []*antiflockv1.EvidenceReference{{Role: antiflockv1.EvidenceRole(999)}}
			},
		},
		{
			name: "top-level unknown field",
			mutate: func(event *antiflockv1.EventEnvelope) {
				event.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 100, protowire.VarintType), 1))
			},
		},
		{
			name: "nested unknown field",
			mutate: func(event *antiflockv1.EventEnvelope) {
				event.Payload.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 100, protowire.VarintType), 1))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire, err := model.EventToProto(validEvent())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(wire)
			if _, err := model.EventFromProto(wire); err == nil {
				t.Fatal("event with unknown protobuf data was accepted")
			}
		})
	}
}

func TestEventFromProtoRejectsInvalidOptionalTimestamps(t *testing.T) {
	t.Parallel()
	invalid := &timestamppb.Timestamp{Seconds: 253402300800}
	tests := []struct {
		name   string
		mutate func(*antiflockv1.EventEnvelope)
	}{
		{"received_at", func(event *antiflockv1.EventEnvelope) { event.ReceivedAt = invalid }},
		{"evidence received_at", func(event *antiflockv1.EventEnvelope) {
			event.Evidence = []*antiflockv1.EvidenceReference{{
				Id: "evidence_one", Role: antiflockv1.EvidenceRole_EVIDENCE_ROLE_SUPPORTING,
				Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED,
				SourceType:     antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_LOCAL_SENSOR,
				SourceName:     "sensor", ObservedAt: timestamppb.Now(), ReceivedAt: invalid,
				Confidence: 1, Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_INTERNAL, Summary: "observation",
			}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire, err := model.EventToProto(validEvent())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(wire)
			if _, err := model.EventFromProto(wire); err == nil {
				t.Fatal("event with invalid optional timestamp was accepted")
			}
		})
	}
}

func TestKnownPayloadContractRejectsTypeMismatchAndNoncanonicalEncoding(t *testing.T) {
	t.Parallel()
	t.Run("type mismatch", func(t *testing.T) {
		event := validEvent()
		event.PayloadTypeURL = "type.googleapis.com/antiflock.v1.WifiObservation"
		if err := event.ValidateSourceContent(); err == nil {
			t.Fatal("event kind with unrelated payload type was accepted")
		}
	})
	t.Run("noncanonical protobuf", func(t *testing.T) {
		event := validEvent()
		// Both encodings are valid protobuf, but deterministic encoding emits
		// route_id (field 1) before destination (field 2).
		payload := protowire.AppendString(protowire.AppendTag(nil, 2, protowire.BytesType), "0.0.0.0/0")
		payload = protowire.AppendString(protowire.AppendTag(payload, 1, protowire.BytesType), "route_one")
		event.Payload = payload
		digest := sha256.Sum256(payload)
		event.PayloadDigest.Digest = digest[:]
		if err := event.ValidateSourceContent(); err == nil {
			t.Fatal("noncanonical protobuf payload was accepted")
		}
	})
	t.Run("known payload unknown field", func(t *testing.T) {
		event := validEvent()
		payload := append([]byte(nil), event.Payload...)
		payload = protowire.AppendVarint(protowire.AppendTag(payload, 100, protowire.VarintType), 1)
		event.Payload = payload
		digest := sha256.Sum256(payload)
		event.PayloadDigest.Digest = digest[:]
		if err := event.ValidateSourceContent(); err == nil {
			t.Fatal("known payload with unknown field was accepted")
		}
	})
}

func TestKnownPayloadRejectsInvalidNestedTimestampAndSensitivityDowngrade(t *testing.T) {
	t.Parallel()
	t.Run("invalid payload timestamp", func(t *testing.T) {
		event := validEvent()
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.RouteObservation{
			RouteId: "route_one", ObservedAt: &timestamppb.Timestamp{Seconds: 253402300800},
		})
		if err != nil {
			t.Fatal(err)
		}
		event.Payload = payload
		digest := sha256.Sum256(payload)
		event.PayloadDigest.Digest = digest[:]
		if err := event.ValidateSourceContent(); err == nil {
			t.Fatal("payload with invalid timestamp was accepted")
		}
	})
	t.Run("nested sensitivity downgrade", func(t *testing.T) {
		event := validEvent()
		event.Kind = "network.dns_changed"
		event.PayloadTypeURL = "type.googleapis.com/antiflock.v1.DnsObservation"
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.DnsObservation{
			ResolverAddresses: []string{"192.0.2.53"},
			Evidence:          []*antiflockv1.EvidenceReference{{Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_SECRET}},
		})
		if err != nil {
			t.Fatal(err)
		}
		event.Payload = payload
		digest := sha256.Sum256(payload)
		event.PayloadDigest.Digest = digest[:]
		if err := event.ValidateSourceContent(); err == nil {
			t.Fatal("envelope sensitivity lower than nested payload sensitivity was accepted")
		}
	})
}

func TestKnownPayloadRejectsDeepUnknownEnumAndField(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*antiflockv1.EvidenceReference)
	}{
		{"unknown enum", func(evidence *antiflockv1.EvidenceReference) { evidence.Role = antiflockv1.EvidenceRole(999) }},
		{"unknown field", func(evidence *antiflockv1.EvidenceReference) {
			evidence.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 100, protowire.VarintType), 1))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := validEvent()
			event.Kind = "network.dns_changed"
			event.PayloadTypeURL = "type.googleapis.com/antiflock.v1.DnsObservation"
			evidence := &antiflockv1.EvidenceReference{
				Id: "nested", Role: antiflockv1.EvidenceRole_EVIDENCE_ROLE_CONTEXT,
				Classification: antiflockv1.EvidenceClass_EVIDENCE_CLASS_DETECTED,
				SourceType:     antiflockv1.EvidenceSourceType_EVIDENCE_SOURCE_TYPE_LOCAL_SENSOR,
				SourceName:     "sensor", ObservedAt: timestamppb.Now(), Confidence: 1,
				Sensitivity: antiflockv1.Sensitivity_SENSITIVITY_INTERNAL, Summary: "context",
				Attributes: map[string]string{"scalar-map": "must not panic recursive validation"},
			}
			test.mutate(evidence)
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.DnsObservation{Evidence: []*antiflockv1.EvidenceReference{evidence}})
			if err != nil {
				t.Fatal(err)
			}
			event.Payload = payload
			digest := sha256.Sum256(payload)
			event.PayloadDigest.Digest = digest[:]
			if err := event.ValidateSourceContent(); err == nil {
				t.Fatal("deep unknown protobuf data was accepted")
			}
		})
	}
}

func TestVerifiedEventRequiresFreshIntegrityProtectedSupportingEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	event := validEvent()
	event.Classification = model.EvidenceVerified
	if err := model.ValidateEvidenceAt(event, now); err == nil {
		t.Fatal("VERIFIED event without evidence was accepted")
	}
	verifiedAt := now.Add(-time.Minute)
	expiresAt := now.Add(time.Hour)
	event.Evidence = []model.EvidenceReference{{
		ID: "evidence_one", Role: "SUPPORTING", Classification: model.EvidenceVerified,
		SourceType: "LOCAL_SENSOR", Source: "route sensor", ObservedAt: now.Add(-2 * time.Minute),
		LastVerifiedAt: &verifiedAt, ExpiresAt: &expiresAt, Confidence: 1,
		Sensitivity: model.SensitivityInternal, Explanation: "independent route check",
		Integrity: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{3}, sha256.Size)},
	}}
	if err := event.ValidateSourceContent(); err != nil {
		t.Fatal(err)
	}
	if err := model.ValidateEvidenceAt(event, now); err != nil {
		t.Fatalf("fresh supporting evidence was rejected: %v", err)
	}

	checks := []struct {
		name   string
		mutate func(*model.EvidenceReference)
	}{
		{"wrong role", func(evidence *model.EvidenceReference) { evidence.Role = "CONTRADICTING" }},
		{"unverified", func(evidence *model.EvidenceReference) { evidence.Classification = model.EvidenceDetected }},
		{"future verification", func(evidence *model.EvidenceReference) {
			value := now.Add(6 * time.Minute)
			evidence.LastVerifiedAt = &value
		}},
		{"expired", func(evidence *model.EvidenceReference) {
			value := now
			evidence.ExpiresAt = &value
		}},
		{"missing integrity", func(evidence *model.EvidenceReference) { evidence.Integrity = model.IntegrityDigest{} }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := event
			candidate.Evidence = append([]model.EvidenceReference(nil), event.Evidence...)
			check.mutate(&candidate.Evidence[0])
			if err := model.ValidateEvidenceAt(candidate, now); err == nil {
				t.Fatal("invalid VERIFIED evidence was accepted")
			}
		})
	}
}

func TestEventFromProtoRejectsOversizedWireEnvelope(t *testing.T) {
	t.Parallel()
	wire, err := model.EventToProto(validEvent())
	if err != nil {
		t.Fatal(err)
	}
	wire.CorrelationId = strings.Repeat("x", model.MaximumEventWireBytes+1)
	if _, err := model.EventFromProto(wire); err == nil {
		t.Fatal("oversized event wire envelope was accepted")
	}
}
