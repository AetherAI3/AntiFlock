package model

import (
	"errors"
	"fmt"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventToProto is the single mapping between the Core model and the locked
// antiflock.v1 wire contract. Signing and durable storage both use this path.
func EventToProto(event EventEnvelope) (*antiflockv1.EventEnvelope, error) {
	observedAt, err := requiredTimestamp(event.ObservedAt, "observed_at")
	if err != nil {
		return nil, err
	}
	var receivedAt *timestamppb.Timestamp
	if !event.ReceivedAt.IsZero() {
		receivedAt, err = requiredTimestamp(event.ReceivedAt, "received_at")
		if err != nil {
			return nil, err
		}
	}
	evidence := make([]*antiflockv1.EvidenceReference, 0, len(event.Evidence))
	for index, reference := range event.Evidence {
		converted, convertErr := evidenceToProto(reference)
		if convertErr != nil {
			return nil, fmt.Errorf("evidence %d: %w", index, convertErr)
		}
		evidence = append(evidence, converted)
	}
	result := &antiflockv1.EventEnvelope{
		Id: event.ID, SchemaVersion: event.SchemaVersion, DeploymentId: event.DeploymentID,
		NodeId: event.NodeID, Kind: event.Kind, ObservedAt: observedAt, ReceivedAt: receivedAt,
		Sequence: event.Sequence, BootId: event.BootID, Classification: evidenceClassToProto(event.Classification),
		Confidence: event.Confidence, Sensitivity: sensitivityToProto(event.Sensitivity),
		Payload:  &anypb.Any{TypeUrl: event.PayloadTypeURL, Value: append([]byte(nil), event.Payload...)},
		Evidence: evidence, CorrelationId: event.CorrelationID, CausationId: event.CausationID,
		PayloadDigest: digestToProto(event.PayloadDigest),
	}
	if event.SourceSignature.KeyID != "" || len(event.SourceSignature.Value) > 0 {
		result.SourceSignature, err = signatureToProto(event.SourceSignature)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func EventFromProto(event *antiflockv1.EventEnvelope) (EventEnvelope, error) {
	if event == nil {
		return EventEnvelope{}, errors.New("event protobuf is required")
	}
	if proto.Size(event) > MaximumEventWireBytes {
		return EventEnvelope{}, fmt.Errorf("event envelope exceeds %d bytes", MaximumEventWireBytes)
	}
	if err := RejectUnknownFields(event); err != nil {
		return EventEnvelope{}, err
	}
	observedAt, err := timestampToTime(event.ObservedAt, true, "observed_at")
	if err != nil {
		return EventEnvelope{}, err
	}
	receivedAt, err := timestampToTime(event.ReceivedAt, false, "received_at")
	if err != nil {
		return EventEnvelope{}, err
	}
	if event.Payload == nil {
		return EventEnvelope{}, errors.New("event payload is required")
	}
	evidence := make([]EvidenceReference, 0, len(event.Evidence))
	for index, reference := range event.Evidence {
		converted, convertErr := evidenceFromProto(reference)
		if convertErr != nil {
			return EventEnvelope{}, fmt.Errorf("evidence %d: %w", index, convertErr)
		}
		evidence = append(evidence, converted)
	}
	result := EventEnvelope{
		ID: event.Id, SchemaVersion: event.SchemaVersion, DeploymentID: event.DeploymentId,
		NodeID: event.NodeId, Kind: event.Kind, ObservedAt: observedAt, ReceivedAt: receivedAt,
		Sequence: event.Sequence, BootID: event.BootId, Classification: evidenceClassFromProto(event.Classification),
		Confidence: event.Confidence, Sensitivity: sensitivityFromProto(event.Sensitivity),
		PayloadTypeURL: event.Payload.TypeUrl, Payload: append([]byte(nil), event.Payload.Value...),
		Evidence: evidence, CorrelationID: event.CorrelationId, CausationID: event.CausationId,
		PayloadDigest: digestFromProto(event.PayloadDigest),
	}
	if event.SourceSignature != nil {
		result.SourceSignature, err = signatureFromProto(event.SourceSignature)
		if err != nil {
			return EventEnvelope{}, err
		}
	}
	return result, nil
}

func evidenceToProto(reference EvidenceReference) (*antiflockv1.EvidenceReference, error) {
	observedAt, err := requiredTimestamp(reference.ObservedAt, "observed_at")
	if err != nil {
		return nil, err
	}
	receivedAt, err := optionalTimestamp(reference.ReceivedAt, "received_at")
	if err != nil {
		return nil, err
	}
	lastVerifiedAt, err := optionalTimestamp(reference.LastVerifiedAt, "last_verified_at")
	if err != nil {
		return nil, err
	}
	expiresAt, err := optionalTimestamp(reference.ExpiresAt, "expires_at")
	if err != nil {
		return nil, err
	}
	return &antiflockv1.EvidenceReference{
		Id: reference.ID, Role: evidenceRoleToProto(reference.Role),
		Classification: evidenceClassToProto(reference.Classification), SourceType: evidenceSourceToProto(reference.SourceType),
		SourceName: reference.Source, SourceUri: reference.SourceURI, ObservedAt: observedAt,
		ReceivedAt: receivedAt, LastVerifiedAt: lastVerifiedAt,
		ExpiresAt: expiresAt, Confidence: reference.Confidence,
		Sensitivity: sensitivityToProto(reference.Sensitivity), LocationPrecision: locationPrecisionToProto(reference.LocationPrecision),
		Summary: reference.Explanation, Integrity: digestToProto(reference.Integrity),
		SourceLicense: reference.SourceLicense, Attributes: reference.Attributes,
	}, nil
}

func evidenceFromProto(reference *antiflockv1.EvidenceReference) (EvidenceReference, error) {
	if reference == nil {
		return EvidenceReference{}, errors.New("evidence reference is required")
	}
	observedAt, err := timestampToTime(reference.ObservedAt, true, "observed_at")
	if err != nil {
		return EvidenceReference{}, err
	}
	receivedAt, err := timestampToPointer(reference.ReceivedAt, "received_at")
	if err != nil {
		return EvidenceReference{}, err
	}
	lastVerifiedAt, err := timestampToPointer(reference.LastVerifiedAt, "last_verified_at")
	if err != nil {
		return EvidenceReference{}, err
	}
	expiresAt, err := timestampToPointer(reference.ExpiresAt, "expires_at")
	if err != nil {
		return EvidenceReference{}, err
	}
	return EvidenceReference{
		ID: reference.Id, Role: trimEnum(reference.Role.String(), "EVIDENCE_ROLE_"),
		Classification: evidenceClassFromProto(reference.Classification),
		SourceType:     trimEnum(reference.SourceType.String(), "EVIDENCE_SOURCE_TYPE_"),
		Source:         reference.SourceName, SourceURI: reference.SourceUri, ObservedAt: observedAt,
		ReceivedAt: receivedAt, LastVerifiedAt: lastVerifiedAt, ExpiresAt: expiresAt,
		Confidence: reference.Confidence, Sensitivity: sensitivityFromProto(reference.Sensitivity),
		LocationPrecision: locationPrecisionFromProto(reference.LocationPrecision),
		Explanation:       reference.Summary, Integrity: digestFromProto(reference.Integrity),
		SourceLicense: reference.SourceLicense, Attributes: reference.Attributes,
	}, nil
}

func signatureToProto(signature Signature) (*antiflockv1.Signature, error) {
	signedAt, err := requiredTimestamp(signature.SignedAt, "signature.signed_at")
	if err != nil {
		return nil, err
	}
	return &antiflockv1.Signature{
		KeyId: signature.KeyID, Algorithm: signatureAlgorithmToProto(signature.Algorithm),
		Value: append([]byte(nil), signature.Value...), SignedAt: signedAt,
		Encoding:            signatureEncodingToProto(signature.Encoding),
		SignedContentDigest: digestToProto(signature.SignedContentDigest), Domain: signature.Domain,
	}, nil
}

func signatureFromProto(signature *antiflockv1.Signature) (Signature, error) {
	signedAt, err := timestampToTime(signature.SignedAt, true, "signature.signed_at")
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		KeyID: signature.KeyId, Algorithm: trimEnum(signature.Algorithm.String(), "SIGNATURE_ALGORITHM_"),
		Value: append([]byte(nil), signature.Value...), SignedAt: signedAt,
		Encoding:            trimEnum(signature.Encoding.String(), "SIGNATURE_ENCODING_"),
		SignedContentDigest: digestFromProto(signature.SignedContentDigest), Domain: signature.Domain,
	}, nil
}

func digestToProto(digest IntegrityDigest) *antiflockv1.IntegrityDigest {
	if digest.Algorithm == "" && len(digest.Digest) == 0 {
		return nil
	}
	return &antiflockv1.IntegrityDigest{Algorithm: digest.Algorithm, Digest: append([]byte(nil), digest.Digest...)}
}

func digestFromProto(digest *antiflockv1.IntegrityDigest) IntegrityDigest {
	if digest == nil {
		return IntegrityDigest{}
	}
	return IntegrityDigest{Algorithm: digest.Algorithm, Digest: append([]byte(nil), digest.Digest...)}
}

func requiredTimestamp(value time.Time, field string) (*timestamppb.Timestamp, error) {
	if value.IsZero() {
		return nil, fmt.Errorf("%s is required", field)
	}
	result := timestamppb.New(value.UTC())
	if err := result.CheckValid(); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return result, nil
}

func optionalTimestamp(value *time.Time, field string) (*timestamppb.Timestamp, error) {
	if value == nil || value.IsZero() {
		return nil, nil
	}
	result := timestamppb.New(value.UTC())
	if err := result.CheckValid(); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return result, nil
}

func timestampToTime(value *timestamppb.Timestamp, required bool, field string) (time.Time, error) {
	if value == nil {
		if required {
			return time.Time{}, fmt.Errorf("%s is required", field)
		}
		return time.Time{}, nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", field, err)
	}
	return value.AsTime().UTC(), nil
}

func timestampToPointer(value *timestamppb.Timestamp, field string) (*time.Time, error) {
	converted, err := timestampToTime(value, false, field)
	if err != nil || converted.IsZero() {
		return nil, err
	}
	return &converted, nil
}

func evidenceClassToProto(value EvidenceClass) antiflockv1.EvidenceClass {
	return antiflockv1.EvidenceClass(antiflockv1.EvidenceClass_value["EVIDENCE_CLASS_"+string(value)])
}

func evidenceClassFromProto(value antiflockv1.EvidenceClass) EvidenceClass {
	return EvidenceClass(trimEnum(value.String(), "EVIDENCE_CLASS_"))
}

func sensitivityToProto(value Sensitivity) antiflockv1.Sensitivity {
	return antiflockv1.Sensitivity(antiflockv1.Sensitivity_value["SENSITIVITY_"+string(value)])
}

func sensitivityFromProto(value antiflockv1.Sensitivity) Sensitivity {
	return Sensitivity(trimEnum(value.String(), "SENSITIVITY_"))
}

func evidenceRoleToProto(value string) antiflockv1.EvidenceRole {
	return antiflockv1.EvidenceRole(antiflockv1.EvidenceRole_value["EVIDENCE_ROLE_"+value])
}

func evidenceSourceToProto(value string) antiflockv1.EvidenceSourceType {
	return antiflockv1.EvidenceSourceType(antiflockv1.EvidenceSourceType_value["EVIDENCE_SOURCE_TYPE_"+value])
}

func locationPrecisionToProto(value string) antiflockv1.LocationPrecision {
	return antiflockv1.LocationPrecision(antiflockv1.LocationPrecision_value["LOCATION_PRECISION_"+value])
}

func locationPrecisionFromProto(value antiflockv1.LocationPrecision) string {
	if value == antiflockv1.LocationPrecision_LOCATION_PRECISION_UNSPECIFIED {
		return ""
	}
	return trimEnum(value.String(), "LOCATION_PRECISION_")
}

func signatureAlgorithmToProto(value string) antiflockv1.SignatureAlgorithm {
	return antiflockv1.SignatureAlgorithm(antiflockv1.SignatureAlgorithm_value["SIGNATURE_ALGORITHM_"+value])
}

func signatureEncodingToProto(value string) antiflockv1.SignatureEncoding {
	return antiflockv1.SignatureEncoding(antiflockv1.SignatureEncoding_value["SIGNATURE_ENCODING_"+value])
}

func trimEnum(value, prefix string) string {
	return strings.TrimPrefix(value, prefix)
}
