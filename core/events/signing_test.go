package events

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDeterministicEventSignatureProfile(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signedAt := time.Date(2026, time.July, 21, 19, 4, 5, 123456789, time.UTC)
	payloadBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&antiflockv1.RouteObservation{
		RouteId: "route_vector", Destination: "0.0.0.0/0", Gateway: "192.0.2.1", InterfaceId: "wifi", DefaultRoute: true,
		ObservedAt: timestamppb.New(signedAt.Add(-time.Second)),
	})
	if err != nil {
		t.Fatal(err)
	}
	event := model.EventEnvelope{
		ID: "event_vector", SchemaVersion: "antiflock.event/v1", DeploymentID: "deployment_vector",
		NodeID: "node_vector", Kind: "network.route_changed", ObservedAt: signedAt.Add(-time.Second),
		Sequence: 7, BootID: "boot_vector", Classification: model.EvidenceDetected, Confidence: 0.75,
		Sensitivity: model.SensitivityInternal, PayloadTypeURL: "type.googleapis.com/antiflock.v1.RouteObservation",
		Payload:       payloadBytes,
		CorrelationID: "correlation_vector", CausationID: "causation_vector",
	}
	if err := SignAt(&event, event.NodeID, privateKey, signedAt); err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(event.SourceSignature.SignedContentDigest.Digest), "5379a5dc61df6b8b81a69a9227dd5a4ed747def3ca2cdb9d49e0ad60ab4b53fb"; got != want {
		t.Fatalf("signed-content digest = %s, want %s", got, want)
	}
	preimage, err := signatureInput(event.SourceSignature)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(preimage), "00000016416e7469466c6f636b2d5369676e61747572652d763100000012616e7469666c6f636b2e6576656e742e7631000000040000000100000006736861323536000000205379a5dc61df6b8b81a69a9227dd5a4ed747def3ca2cdb9d49e0ad60ab4b53fb00000008000000006a5fc2a500000004075bcd15"; got != want {
		t.Fatalf("signature preimage = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(event.SourceSignature.Value), "5e3e0d84b8f4cab09dbba9ecde69bdf27fdc4312c9d1c105963302b6b2371e075349bb5c311f4c5a89d155cb2d69d8314cb3ce44e8df936972cfe5a18191c102"; got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
	if err := VerifySource(event, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	withCoreReceipt := event
	withCoreReceipt.ReceivedAt = signedAt.Add(10 * time.Second)
	if err := VerifySource(withCoreReceipt, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("Core received_at changed the source signature: %v", err)
	}
	tampered := event
	tampered.CorrelationID = "different"
	if err := VerifySource(tampered, privateKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("correlation id tampering was accepted")
	}
}
