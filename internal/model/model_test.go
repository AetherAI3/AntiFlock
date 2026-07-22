package model_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validEvent() model.EventEnvelope {
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.RouteObservation{
		RouteId: "route_one", Destination: "0.0.0.0/0", InterfaceId: "mesh0", DefaultRoute: true,
		ObservedAt: timestamppb.New(time.Now().UTC()),
	})
	digest := sha256.Sum256(payload)
	now := time.Now().UTC()
	return model.EventEnvelope{
		ID: "event_one", SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment_one", NodeID: "node_one",
		Kind: "network.route_changed", ObservedAt: now, Sequence: 1, BootID: "boot_one",
		Classification: model.EvidenceDetected, Confidence: 1,
		Sensitivity: model.SensitivityInternal, PayloadTypeURL: "type.googleapis.com/antiflock.v1.RouteObservation", Payload: payload,
		PayloadDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: digest[:]},
		SourceSignature: model.Signature{
			KeyID: "node_one", Algorithm: "ED25519", Value: bytes.Repeat([]byte{1}, 64), SignedAt: now,
			Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: "antiflock.event.v1",
			SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: bytes.Repeat([]byte{2}, 32)},
		},
	}
}

func TestEvidenceClassesAndEventValidation(t *testing.T) {
	t.Parallel()
	for _, class := range []model.EvidenceClass{
		model.EvidenceDetected, model.EvidenceVerified, model.EvidenceReported,
		model.EvidenceInferred, model.EvidenceSuspected, model.EvidenceUnknown,
	} {
		if !class.Valid() {
			t.Fatalf("class %q is invalid", class)
		}
	}
	if model.EvidenceClass("CERTAIN").Valid() {
		t.Fatal("unsupported certainty class was accepted")
	}
	if err := validEvent().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEventValidationRejectsUnverifiableData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*model.EventEnvelope)
	}{
		{"missing id", func(event *model.EventEnvelope) { event.ID = "" }},
		{"missing schema", func(event *model.EventEnvelope) { event.SchemaVersion = "" }},
		{"missing deployment", func(event *model.EventEnvelope) { event.DeploymentID = "" }},
		{"missing node", func(event *model.EventEnvelope) { event.NodeID = "" }},
		{"unnamespaced kind", func(event *model.EventEnvelope) { event.Kind = "route" }},
		{"missing observed time", func(event *model.EventEnvelope) { event.ObservedAt = time.Time{} }},
		{"missing boot", func(event *model.EventEnvelope) { event.BootID = "" }},
		{"unknown class", func(event *model.EventEnvelope) { event.Classification = "CERTAIN" }},
		{"bad confidence", func(event *model.EventEnvelope) { event.Confidence = 1.1 }},
		{"bad sensitivity", func(event *model.EventEnvelope) { event.Sensitivity = "EVERYTHING" }},
		{"invalid payload", func(event *model.EventEnvelope) { event.Payload = json.RawMessage(`{`) }},
		{"payload digest mismatch", func(event *model.EventEnvelope) { event.PayloadDigest.Digest[0] ^= 1 }},
		{"missing source signature", func(event *model.EventEnvelope) { event.SourceSignature = model.Signature{} }},
		{"bad evidence", func(event *model.EventEnvelope) {
			event.Evidence = []model.EvidenceReference{{Classification: "CERTAIN", Confidence: 2}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := validEvent()
			test.mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatal("invalid event was accepted")
			}
		})
	}
}
