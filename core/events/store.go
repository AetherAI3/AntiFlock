package events

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/proto"
)

// APIProjection is the durable retention gate for events accepted by the
// canonical Core ingestion/API store. It advances only after the committed
// event can be read back from SQLite.
const APIProjection = "event-api"

type Store struct {
	database       *storage.DB
	deploymentID   string
	caCertificate  *x509.Certificate
	clock          func() time.Time
	mu             sync.RWMutex
	nextSubscriber int
	subscribers    map[int]chan model.EventEnvelope
}

func New(database *storage.DB, authority *identity.Authority) (*Store, error) {
	if database == nil || authority == nil || authority.CACert == nil || authority.Deployment.DeploymentID == "" {
		return nil, errors.New("event store database and deployment authority are required")
	}
	return &Store{
		database: database, deploymentID: authority.Deployment.DeploymentID, caCertificate: authority.CACert,
		clock: func() time.Time { return time.Now().UTC() }, subscribers: make(map[int]chan model.EventEnvelope),
	}, nil
}

func (store *Store) Append(ctx context.Context, event model.EventEnvelope) (bool, error) {
	now := store.clock()
	if err := event.Validate(); err != nil {
		return false, err
	}
	wire, err := model.EventToProto(event)
	if err != nil {
		return false, err
	}
	if proto.Size(wire) > model.MaximumEventWireBytes {
		return false, fmt.Errorf("event envelope exceeds %d bytes", model.MaximumEventWireBytes)
	}
	if event.DeploymentID != store.deploymentID {
		return false, errors.New("event deployment does not match this Core")
	}
	node, err := store.database.GetNode(ctx, event.NodeID)
	if err != nil {
		return false, err
	}
	if node.Status != model.NodeActive {
		return false, fmt.Errorf("event node is not active: %s", node.Status)
	}
	if err := validateCredential(event, node, store.deploymentID, store.caCertificate, now); err != nil {
		return false, err
	}
	if err := VerifySource(event, ed25519.PublicKey(node.PublicKey)); err != nil {
		return false, err
	}
	if err := model.ValidateEvidenceAt(event, now); err != nil {
		return false, err
	}
	existing, err := store.database.GetEvent(ctx, event.ID)
	if err == nil {
		event.ReceivedAt = existing.ReceivedAt
	} else if errors.Is(err, storage.ErrEventNotFound) {
		event.ReceivedAt = now
	} else {
		return false, err
	}
	if err := event.Validate(); err != nil {
		return false, err
	}
	inserted, err := store.database.AppendEvent(ctx, event)
	if err != nil {
		return false, err
	}
	stored, err := store.database.GetEvent(ctx, event.ID)
	if err != nil {
		return inserted, fmt.Errorf("read back committed event: %w", err)
	}
	if err := store.advanceAPICursor(ctx, stored, now); err != nil {
		return inserted, err
	}
	if inserted {
		store.publish(stored)
	}
	return inserted, nil
}

func (store *Store) advanceAPICursor(ctx context.Context, event model.EventEnvelope, now time.Time) error {
	current, err := store.database.GetProjectionCursor(ctx, APIProjection)
	if err != nil {
		return fmt.Errorf("read event API projection cursor: %w", err)
	}
	if current.LastIngestOrdinal >= event.IngestOrdinal {
		return nil
	}
	updatedAt := now
	if updatedAt.Before(current.UpdatedAt) {
		updatedAt = current.UpdatedAt
	}
	err = store.database.SetProjectionCursor(ctx, storage.ProjectionCursor{
		Projection: APIProjection, LastIngestOrdinal: event.IngestOrdinal,
		LastReceivedAt: event.ReceivedAt, LastEventID: event.ID, UpdatedAt: updatedAt,
	})
	if err == nil {
		return nil
	}
	// Concurrent ingestion may have safely advanced past this event between the
	// read and write. Treat that monotonic race as success, never as permission
	// to move the cursor backward.
	latest, latestErr := store.database.GetProjectionCursor(ctx, APIProjection)
	if latestErr == nil && latest.LastIngestOrdinal >= event.IngestOrdinal {
		return nil
	}
	return fmt.Errorf("advance event API projection cursor: %w", err)
}

func validateCredential(event model.EventEnvelope, node model.Node, deploymentID string, caCertificate *x509.Certificate, now time.Time) error {
	if caCertificate == nil || now.Before(caCertificate.NotBefore) || !now.Before(caCertificate.NotAfter) {
		return errors.New("deployment authority is outside its validity window")
	}
	block, _ := pem.Decode([]byte(node.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("enrolled node certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrolled node certificate: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicKey.Equal(ed25519.PublicKey(node.PublicKey)) {
		return errors.New("enrolled node certificate does not match the event verification key")
	}
	if certificate.Subject.CommonName != node.ID || !slices.Contains(certificate.Subject.Organization, deploymentID) {
		return errors.New("enrolled node certificate subject is outside this deployment")
	}
	if !slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return errors.New("enrolled node certificate is not valid for client authentication")
	}
	if certificate.CheckSignatureFrom(caCertificate) != nil {
		return errors.New("enrolled node certificate is not signed by this deployment authority")
	}
	signedAt := event.SourceSignature.SignedAt
	if signedAt.Before(certificate.NotBefore) || signedAt.After(certificate.NotAfter) {
		return errors.New("event was signed outside the node credential validity window")
	}
	if signedAt.After(now.Add(5*time.Minute)) || event.ObservedAt.After(now.Add(5*time.Minute)) {
		return errors.New("event timestamp exceeds the allowed clock skew")
	}
	if delta := signedAt.Sub(event.ObservedAt); delta < -5*time.Minute || delta > 5*time.Minute {
		return errors.New("event signature time is not bound to its observation time")
	}
	return nil
}

func (store *Store) Replay(ctx context.Context, after time.Time, limit int) ([]model.EventEnvelope, error) {
	return store.database.ListEvents(ctx, after, limit)
}

func (store *Store) ReplayFrom(ctx context.Context, cursor storage.ProjectionCursor, limit int) ([]model.EventEnvelope, error) {
	if cursor.LastIngestOrdinal != 0 {
		return store.database.ListEventsFromOrdinal(ctx, cursor.LastIngestOrdinal, limit)
	}
	return store.database.ListEventsPage(ctx, cursor.LastReceivedAt, cursor.LastEventID, limit)
}

func (store *Store) Subscribe(buffer int) (<-chan model.EventEnvelope, func()) {
	if buffer < 1 {
		buffer = 32
	}
	store.mu.Lock()
	id := store.nextSubscriber
	store.nextSubscriber++
	channel := make(chan model.EventEnvelope, buffer)
	store.subscribers[id] = channel
	store.mu.Unlock()
	var once sync.Once
	return channel, func() {
		once.Do(func() {
			store.mu.Lock()
			if _, exists := store.subscribers[id]; exists {
				delete(store.subscribers, id)
				close(channel)
			}
			store.mu.Unlock()
		})
	}
}

func (store *Store) publish(event model.EventEnvelope) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, channel := range store.subscribers {
		select {
		case channel <- event:
		default:
			// Eviction makes the gap explicit: stream handlers observe closure and
			// must reconnect using their last durable (received_at, event_id) cursor.
			delete(store.subscribers, id)
			close(channel)
		}
	}
}
