package events

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	signatureProtocol = "AntiFlock-Signature-v1"
	eventDomain       = "antiflock.event.v1"
)

func Sign(event *model.EventEnvelope, privateKey ed25519.PrivateKey) error {
	if event == nil {
		return errors.New("event is required")
	}
	return SignAt(event, event.NodeID, privateKey, time.Now().UTC())
}

// SignAt exists so agents can produce reproducible vectors without weakening
// the production API's timestamping behavior.
func SignAt(event *model.EventEnvelope, keyID string, privateKey ed25519.PrivateKey, signedAt time.Time) error {
	if event == nil {
		return errors.New("event is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("event signing key must be Ed25519")
	}
	if keyID == "" {
		return errors.New("event signing key id is required")
	}
	if signedAt.IsZero() {
		return errors.New("event signed time is required")
	}
	payloadDigest := sha256.Sum256(event.Payload)
	event.PayloadDigest = model.IntegrityDigest{Algorithm: "sha256", Digest: payloadDigest[:]}
	if err := event.ValidateSourceContent(); err != nil {
		return err
	}
	digest, err := signingDigest(*event)
	if err != nil {
		return err
	}
	signature := model.Signature{
		KeyID: keyID, Algorithm: "ED25519", SignedAt: signedAt.UTC(),
		Encoding: "PROTOBUF_DETERMINISTIC_V1", Domain: eventDomain,
		SignedContentDigest: model.IntegrityDigest{Algorithm: "sha256", Digest: digest},
	}
	signedBytes, err := signatureInput(signature)
	if err != nil {
		return err
	}
	signature.Value = ed25519.Sign(privateKey, signedBytes)
	event.SourceSignature = signature
	return event.Validate()
}

func VerifySource(event model.EventEnvelope, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("enrolled event key is not Ed25519")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.SourceSignature.KeyID != event.NodeID {
		return errors.New("event signature key id does not match node id")
	}
	digest, err := signingDigest(event)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, event.SourceSignature.SignedContentDigest.Digest) != 1 {
		return errors.New("event signed-content digest mismatch")
	}
	signedBytes, err := signatureInput(event.SourceSignature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, signedBytes, event.SourceSignature.Value) {
		return errors.New("event source signature verification failed")
	}
	return nil
}

// CanonicalSourceEnvelope returns the deterministic source-submitted envelope.
// Core-assigned received_at is cleared while the source signature is retained.
func CanonicalSourceEnvelope(event model.EventEnvelope) ([]byte, error) {
	wire, err := model.EventToProto(event)
	if err != nil {
		return nil, err
	}
	wire.ReceivedAt = nil
	if err := rejectUnknown(wire.ProtoReflect()); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(wire)
}

func signingDigest(event model.EventEnvelope) ([]byte, error) {
	wire, err := model.EventToProto(event)
	if err != nil {
		return nil, err
	}
	wire.ReceivedAt = nil
	wire.SourceSignature = nil
	if err := rejectUnknown(wire.ProtoReflect()); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("deterministically encode signable event: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func signatureInput(signature model.Signature) ([]byte, error) {
	if signature.Algorithm != "ED25519" || signature.Encoding != "PROTOBUF_DETERMINISTIC_V1" || signature.Domain != eventDomain {
		return nil, errors.New("unsupported event signature profile")
	}
	if signature.SignedContentDigest.Algorithm != "sha256" || len(signature.SignedContentDigest.Digest) != sha256.Size {
		return nil, errors.New("unsupported event signature digest")
	}
	if signature.SignedAt.IsZero() {
		return nil, errors.New("event signature time is required")
	}
	algorithm := make([]byte, 4)
	binary.BigEndian.PutUint32(algorithm, uint32(antiflockv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519))
	seconds := make([]byte, 8)
	binary.BigEndian.PutUint64(seconds, uint64(signature.SignedAt.UTC().Unix()))
	nanoseconds := make([]byte, 4)
	binary.BigEndian.PutUint32(nanoseconds, uint32(signature.SignedAt.UTC().Nanosecond()))
	fields := [][]byte{
		[]byte(signatureProtocol), []byte(signature.Domain), algorithm,
		[]byte(signature.SignedContentDigest.Algorithm), signature.SignedContentDigest.Digest,
		seconds, nanoseconds,
	}
	result := make([]byte, 0, 128)
	for _, field := range fields {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		result = append(result, length...)
		result = append(result, field...)
	}
	return result, nil
}

func rejectUnknown(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return errors.New("signed event contains unknown protobuf fields")
	}
	var nestedErr error
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.IsMap() {
			if descriptor.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
					nestedErr = rejectUnknown(item.Message())
					return nestedErr == nil
				})
			}
		} else if descriptor.IsList() && descriptor.Kind() == protoreflect.MessageKind {
			list := value.List()
			for index := 0; index < list.Len() && nestedErr == nil; index++ {
				nestedErr = rejectUnknown(list.Get(index).Message())
			}
		} else if descriptor.Kind() == protoreflect.MessageKind {
			nestedErr = rejectUnknown(value.Message())
		}
		return nestedErr == nil
	})
	return nestedErr
}
