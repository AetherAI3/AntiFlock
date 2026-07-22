package model

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MaximumEventWireBytes = 1024 * 1024
	MaximumPayloadBytes   = 256 * 1024
)

type payloadContract struct {
	typeURL string
	new     func() proto.Message
}

var payloadContracts = map[string]payloadContract{
	"node.enrolled":               payload("antiflock.v1.Node", func() proto.Message { return &antiflockv1.Node{} }),
	"node.suspended":              payload("antiflock.v1.Node", func() proto.Message { return &antiflockv1.Node{} }),
	"node.revoked":                payload("antiflock.v1.Node", func() proto.Message { return &antiflockv1.Node{} }),
	"node.heartbeat":              payload("antiflock.v1.NodeHeartbeat", func() proto.Message { return &antiflockv1.NodeHeartbeat{} }),
	"node.capabilities_changed":   payload("antiflock.v1.CapabilityManifest", func() proto.Message { return &antiflockv1.CapabilityManifest{} }),
	"network.interface_changed":   payload("antiflock.v1.NetworkInterfaceObservation", func() proto.Message { return &antiflockv1.NetworkInterfaceObservation{} }),
	"network.gateway_changed":     payload("antiflock.v1.GatewayObservation", func() proto.Message { return &antiflockv1.GatewayObservation{} }),
	"network.wifi_changed":        payload("antiflock.v1.WifiObservation", func() proto.Message { return &antiflockv1.WifiObservation{} }),
	"network.route_changed":       payload("antiflock.v1.RouteObservation", func() proto.Message { return &antiflockv1.RouteObservation{} }),
	"network.dns_changed":         payload("antiflock.v1.DnsObservation", func() proto.Message { return &antiflockv1.DnsObservation{} }),
	"flow.started":                payload("antiflock.v1.FlowObservation", func() proto.Message { return &antiflockv1.FlowObservation{} }),
	"flow.updated":                payload("antiflock.v1.FlowObservation", func() proto.Message { return &antiflockv1.FlowObservation{} }),
	"flow.ended":                  payload("antiflock.v1.FlowObservation", func() proto.Message { return &antiflockv1.FlowObservation{} }),
	"service.listening":           payload("antiflock.v1.ListeningServiceObservation", func() proto.Message { return &antiflockv1.ListeningServiceObservation{} }),
	"mesh.peer_changed":           payload("antiflock.v1.MeshPeerObservation", func() proto.Message { return &antiflockv1.MeshPeerObservation{} }),
	"mesh.path_changed":           payload("antiflock.v1.MeshPathObservation", func() proto.Message { return &antiflockv1.MeshPathObservation{} }),
	"mesh.exit_changed":           payload("antiflock.v1.MeshPathObservation", func() proto.Message { return &antiflockv1.MeshPathObservation{} }),
	"mesh.connection_lost":        payload("antiflock.v1.MeshPathObservation", func() proto.Message { return &antiflockv1.MeshPathObservation{} }),
	"posture.changed":             payload("antiflock.v1.ProtectionSnapshot", func() proto.Message { return &antiflockv1.ProtectionSnapshot{} }),
	"policy.compiled":             payload("antiflock.v1.Plan", func() proto.Message { return &antiflockv1.Plan{} }),
	"policy.applied":              payload("antiflock.v1.PlanExecutionResult", func() proto.Message { return &antiflockv1.PlanExecutionResult{} }),
	"policy.failed":               payload("antiflock.v1.PlanExecutionResult", func() proto.Message { return &antiflockv1.PlanExecutionResult{} }),
	"policy.rolled_back":          payload("antiflock.v1.PlanExecutionResult", func() proto.Message { return &antiflockv1.PlanExecutionResult{} }),
	"finding.opened":              payload("antiflock.v1.Finding", func() proto.Message { return &antiflockv1.Finding{} }),
	"finding.updated":             payload("antiflock.v1.Finding", func() proto.Message { return &antiflockv1.Finding{} }),
	"finding.resolved":            payload("antiflock.v1.Finding", func() proto.Message { return &antiflockv1.Finding{} }),
	"action.held":                 payload("antiflock.v1.SecureActionDecision", func() proto.Message { return &antiflockv1.SecureActionDecision{} }),
	"action.allowed":              payload("antiflock.v1.SecureActionDecision", func() proto.Message { return &antiflockv1.SecureActionDecision{} }),
	"action.blocked":              payload("antiflock.v1.SecureActionDecision", func() proto.Message { return &antiflockv1.SecureActionDecision{} }),
	"action.bypassed":             payload("antiflock.v1.SecureActionDecision", func() proto.Message { return &antiflockv1.SecureActionDecision{} }),
	"field.report_imported":       payload("antiflock.v1.FieldReport", func() proto.Message { return &antiflockv1.FieldReport{} }),
	"field.report_submitted":      payload("antiflock.v1.FieldReport", func() proto.Message { return &antiflockv1.FieldReport{} }),
	"field.report_verified":       payload("antiflock.v1.FieldReport", func() proto.Message { return &antiflockv1.FieldReport{} }),
	"field.report_expired":        payload("antiflock.v1.FieldReport", func() proto.Message { return &antiflockv1.FieldReport{} }),
	"field.report_disputed":       payload("antiflock.v1.FieldReport", func() proto.Message { return &antiflockv1.FieldReport{} }),
	"field.report_removed":        payload("antiflock.v1.FieldReport", func() proto.Message { return &antiflockv1.FieldReport{} }),
	"scrambler.state_proposed":    payload("antiflock.v1.ScramblerTransition", func() proto.Message { return &antiflockv1.ScramblerTransition{} }),
	"scrambler.state_applied":     payload("antiflock.v1.ScramblerTransition", func() proto.Message { return &antiflockv1.ScramblerTransition{} }),
	"scrambler.state_failed":      payload("antiflock.v1.ScramblerTransition", func() proto.Message { return &antiflockv1.ScramblerTransition{} }),
	"scrambler.state_rolled_back": payload("antiflock.v1.ScramblerTransition", func() proto.Message { return &antiflockv1.ScramblerTransition{} }),
}

func payload(messageName string, constructor func() proto.Message) payloadContract {
	return payloadContract{typeURL: "type.googleapis.com/" + messageName, new: constructor}
}

func validateEventPayload(kind, typeURL string, value []byte, envelopeSensitivity Sensitivity) error {
	if len(value) == 0 {
		return errors.New("event protobuf payload is required")
	}
	if len(value) > MaximumPayloadBytes {
		return fmt.Errorf("event payload exceeds %d bytes", MaximumPayloadBytes)
	}
	if len(typeURL) < len("type.googleapis.com/") || typeURL[:len("type.googleapis.com/")] != "type.googleapis.com/" {
		return errors.New("event payload type URL must use type.googleapis.com")
	}
	contract, known := payloadContracts[kind]
	if !known {
		return validateOpaqueProtobuf(value)
	}
	if typeURL != contract.typeURL {
		return fmt.Errorf("event kind %q requires payload type %q", kind, contract.typeURL)
	}
	message := contract.new()
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(value, message); err != nil {
		return fmt.Errorf("decode event payload %s: %w", typeURL, err)
	}
	if err := RejectUnknownFields(message); err != nil {
		return fmt.Errorf("event payload: %w", err)
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return fmt.Errorf("canonicalize event payload: %w", err)
	}
	if !bytes.Equal(canonical, value) {
		return errors.New("event payload is not deterministic protobuf encoding")
	}
	if err := validateEmbeddedPayload(message.ProtoReflect(), envelopeSensitivity); err != nil {
		return err
	}
	return nil
}

func validateOpaqueProtobuf(value []byte) error {
	remaining := value
	for len(remaining) > 0 {
		_, _, consumed := protowire.ConsumeField(remaining)
		if consumed < 0 {
			return fmt.Errorf("event payload is not valid protobuf: %v", protowire.ParseError(consumed))
		}
		remaining = remaining[consumed:]
	}
	return nil
}

func ValidateEvidenceAt(event EventEnvelope, now time.Time) error {
	if event.Classification != EvidenceVerified {
		return nil
	}
	for _, evidence := range event.Evidence {
		if evidence.Role != "SUPPORTING" || evidence.Classification != EvidenceVerified || evidence.LastVerifiedAt == nil {
			continue
		}
		if evidence.LastVerifiedAt.After(now.Add(5*time.Minute)) || (evidence.ExpiresAt != nil && !now.Before(*evidence.ExpiresAt)) {
			continue
		}
		if evidence.Integrity.Algorithm != "sha256" || len(evidence.Integrity.Digest) != sha256.Size {
			continue
		}
		return nil
	}
	return errors.New("VERIFIED events require fresh supporting VERIFIED evidence with verification time and integrity")
}

func RejectUnknownFields(message proto.Message) error {
	if message == nil {
		return errors.New("protobuf message is required")
	}
	return rejectUnknownMessage(message.ProtoReflect())
}

func rejectUnknownMessage(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return errors.New("protobuf message contains unknown fields")
	}
	var nestedErr error
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.IsList() && descriptor.Kind() == protoreflect.EnumKind {
			for index, list := 0, value.List(); index < list.Len(); index++ {
				if descriptor.Enum().Values().ByNumber(list.Get(index).Enum()) == nil {
					nestedErr = fmt.Errorf("protobuf field %s contains unknown enum value %d", descriptor.FullName(), list.Get(index).Enum())
					return false
				}
			}
		} else if descriptor.Kind() == protoreflect.EnumKind && descriptor.Enum().Values().ByNumber(value.Enum()) == nil {
			nestedErr = fmt.Errorf("protobuf field %s contains unknown enum value %d", descriptor.FullName(), value.Enum())
			return false
		}
		if descriptor.IsMap() {
			if descriptor.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
					nestedErr = rejectUnknownMessage(item.Message())
					return nestedErr == nil
				})
			}
		} else if descriptor.IsList() && descriptor.Kind() == protoreflect.MessageKind {
			for index, list := 0, value.List(); index < list.Len() && nestedErr == nil; index++ {
				nestedErr = rejectUnknownMessage(list.Get(index).Message())
			}
		} else if descriptor.Kind() == protoreflect.MessageKind {
			nestedErr = rejectUnknownMessage(value.Message())
		}
		return nestedErr == nil
	})
	return nestedErr
}

func validateProtoTime(value time.Time, field string) error {
	if err := timestamppb.New(value.UTC()).CheckValid(); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func validateEmbeddedPayload(message protoreflect.Message, envelope Sensitivity) error {
	if message.Descriptor().FullName() == "google.protobuf.Timestamp" {
		timestamp, ok := message.Interface().(*timestamppb.Timestamp)
		if !ok {
			return errors.New("event payload timestamp has an unexpected protobuf type")
		}
		if err := timestamp.CheckValid(); err != nil {
			return fmt.Errorf("event payload contains an invalid timestamp: %w", err)
		}
		return nil
	}
	var result error
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.Enum() != nil && descriptor.Enum().FullName() == "antiflock.v1.Sensitivity" {
			name := descriptor.Enum().Values().ByNumber(value.Enum()).Name()
			payloadSensitivity := Sensitivity(bytes.TrimPrefix([]byte(name), []byte("SENSITIVITY_")))
			if payloadSensitivity.Valid() && sensitivityRank(envelope) < sensitivityRank(payloadSensitivity) {
				result = errors.New("event envelope sensitivity is lower than its payload sensitivity")
				return false
			}
		}
		if descriptor.IsMap() {
			if descriptor.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
					result = validateEmbeddedPayload(item.Message(), envelope)
					return result == nil
				})
			}
		} else if descriptor.IsList() && descriptor.Kind() == protoreflect.MessageKind {
			for index, list := 0, value.List(); index < list.Len() && result == nil; index++ {
				result = validateEmbeddedPayload(list.Get(index).Message(), envelope)
			}
		} else if descriptor.Kind() == protoreflect.MessageKind {
			result = validateEmbeddedPayload(value.Message(), envelope)
		}
		return result == nil
	})
	return result
}
