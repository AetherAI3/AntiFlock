package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumEventBatchBytes = int64(8 << 20)
	maximumBatchEvents     = 256
	streamReplayPageSize   = 200
	streamHeartbeat        = 15 * time.Second
)

var streamTopics = []string{
	"posture.changed", "finding.opened", "finding.resolved", "node.changed",
	"path.changed", "action.held", "scrambler.changed",
}

func (server *Server) handleEventBatch(response http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(response, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content type must be application/json.", "", false)
		return
	}
	if encoding := request.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		writeAPIError(response, http.StatusUnsupportedMediaType, "CONTENT_ENCODING_UNSUPPORTED", "Compressed request bodies are not accepted.", "", false)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumEventBatchBytes)
	content, err := io.ReadAll(request.Body)
	if err != nil {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "BATCH_TOO_LARGE", "Event batch exceeds the allowed size.", "", false)
		return
	}
	var submission antiflockv1.SubmitEventBatchRequest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, &submission); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_EVENT_BATCH", "Event batch is not valid protobuf JSON.", "", false)
		return
	}
	batch := submission.GetBatch()
	if batch == nil || !bounded(batch.GetBatchId(), 128) || !bounded(batch.GetNodeId(), 128) || len(batch.GetEvents()) == 0 || len(batch.GetEvents()) > maximumBatchEvents {
		writeAPIError(response, http.StatusBadRequest, "INVALID_EVENT_BATCH", "Event batch id, node id, and between one and 256 events are required.", "", false)
		return
	}
	caller := principalFromContext(request.Context())
	if caller.NodeID == "" || caller.NodeID != batch.GetNodeId() {
		writeAPIError(response, http.StatusForbidden, "NODE_SCOPE_MISMATCH", "Agent credential does not match the event batch node.", "", false)
		return
	}
	receivedAt := server.clock().UTC()
	rejected := make([]*antiflockv1.RejectedEvent, 0)
	batchBootID := ""
	for _, wire := range batch.GetEvents() {
		eventID := ""
		if wire != nil {
			eventID = wire.GetId()
		}
		if wire == nil || wire.GetNodeId() != batch.GetNodeId() || proto.Size(wire) > 1<<20 {
			rejected = append(rejected, rejectedEvent(eventID, "EVENT_ENVELOPE_INVALID", "Event does not match the authenticated batch scope."))
			continue
		}
		if batchBootID == "" {
			batchBootID = wire.GetBootId()
		} else if wire.GetBootId() != batchBootID {
			rejected = append(rejected, rejectedEvent(eventID, "EVENT_BOOT_MISMATCH", "Every event in a batch must use the same boot id."))
			continue
		}
		event, convertErr := model.EventFromProto(wire)
		if convertErr != nil {
			rejected = append(rejected, rejectedEvent(eventID, "EVENT_SCHEMA_INVALID", "Event failed schema validation."))
			continue
		}
		_, appendErr := server.events.Append(request.Context(), event)
		if appendErr != nil {
			reason := "EVENT_REJECTED"
			if errors.Is(appendErr, storage.ErrEventSequenceConflict) {
				reason = "EVENT_SEQUENCE_CONFLICT"
			} else if errors.Is(appendErr, storage.ErrEventSequenceGap) {
				reason = "EVENT_SEQUENCE_GAP"
			} else if errors.Is(appendErr, storage.ErrEventBootRegression) {
				reason = "EVENT_BOOT_REGRESSION"
			}
			rejected = append(rejected, rejectedEvent(eventID, reason, "Event was rejected by Core validation."))
			continue
		}
	}
	highestContiguous := uint64(0)
	state, stateErr := server.database.GetNodeEventState(request.Context(), batch.GetNodeId())
	if stateErr != nil {
		server.writeDomainError(response, http.StatusInternalServerError, stateErr, "")
		return
	}
	if state.CurrentBootID == batchBootID {
		highestContiguous = state.HighestContiguousSequence
	}
	ack := &antiflockv1.EventBatchAck{
		BatchId: batch.GetBatchId(), HighestContiguousSequence: highestContiguous,
		Rejected: rejected, ReceivedAt: timestamppb.New(receivedAt),
	}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: true}).Marshal(&antiflockv1.SubmitEventBatchResponse{Ack: ack})
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(append(encoded, '\n'))
}

func rejectedEvent(id, reason, message string) *antiflockv1.RejectedEvent {
	return &antiflockv1.RejectedEvent{EventId: id, ReasonCode: reason, SafeMessage: message}
}

func (server *Server) handleEvents(response http.ResponseWriter, request *http.Request) {
	limit, err := eventLimit(request)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_LIMIT", "Event limit must be between 1 and 500.", "", false)
		return
	}
	cursor, err := server.requestCursor(request)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_CURSOR", "Event cursor is invalid.", "", false)
		return
	}
	events, err := server.events.ReplayFrom(request.Context(), storage.ProjectionCursor{
		LastIngestOrdinal: cursor.IngestOrdinal, LastEventID: cursor.EventID,
	}, limit)
	if err != nil {
		server.writeDomainError(response, http.StatusInternalServerError, err, "")
		return
	}
	next := ""
	if len(events) != 0 {
		last := events[len(events)-1]
		next = encodeCursor(replayCursor{Version: 1, IngestOrdinal: last.IngestOrdinal, EventID: last.ID})
	}
	if events == nil {
		events = []model.EventEnvelope{}
	}
	writeJSON(response, http.StatusOK, map[string]any{"events": events, "nextCursor": next})
}

func (server *Server) handleStream(response http.ResponseWriter, request *http.Request) {
	requestedTopics, err := parseTopics(request.URL.Query().Get("topics"))
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_TOPICS", err.Error(), "", false)
		return
	}
	cursor, err := server.requestCursor(request)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_CURSOR", "Stream cursor is invalid.", "", false)
		return
	}
	if cursor.EventID != "" {
		stored, getErr := server.database.GetEvent(request.Context(), cursor.EventID)
		if errors.Is(getErr, storage.ErrEventNotFound) {
			writeAPIError(response, http.StatusGone, "CURSOR_EXPIRED", "Stream cursor is no longer retained; reload current projections.", "", false)
			return
		}
		if getErr != nil || stored.IngestOrdinal != cursor.IngestOrdinal {
			writeAPIError(response, http.StatusBadRequest, "INVALID_CURSOR", "Stream cursor does not match durable event state.", "", false)
			return
		}
	}

	wake, unsubscribe := server.events.Subscribe(64)
	defer unsubscribe()
	response.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	response.Header().Set("Connection", "keep-alive")
	response.Header().Set("X-Accel-Buffering", "no")
	response.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(response)
	if err := controller.Flush(); err != nil {
		return
	}

	current := cursor
	drain := func(ctx context.Context) error {
		for {
			page, replayErr := server.events.ReplayFrom(ctx, storage.ProjectionCursor{
				LastIngestOrdinal: current.IngestOrdinal, LastEventID: current.EventID,
			}, streamReplayPageSize)
			if replayErr != nil {
				return replayErr
			}
			if len(page) == 0 {
				return nil
			}
			for _, event := range page {
				current = replayCursor{Version: 1, IngestOrdinal: event.IngestOrdinal, EventID: event.ID}
				topic := topicForEvent(event.Kind)
				if topic == "" || !requestedTopics[topic] {
					continue
				}
				if err := writeSSE(controller, response, topic, current, event); err != nil {
					return err
				}
			}
			if len(page) < streamReplayPageSize {
				return nil
			}
		}
	}
	if err := drain(request.Context()); err != nil {
		return
	}
	heartbeat := time.NewTicker(streamHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case _, open := <-wake:
			if !open {
				return
			}
			if err := drain(request.Context()); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return
			}
			if _, err := io.WriteString(response, ": keepalive\n\n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
	}
}

func writeSSE(controller *http.ResponseController, response http.ResponseWriter, topic string, cursor replayCursor, event model.EventEnvelope) error {
	encodedCursor := encodeCursor(cursor)
	data, err := json.Marshal(map[string]any{
		"cursor": encodedCursor,
		"event": map[string]any{
			"id": event.ID, "kind": topic, "sourceKind": event.Kind,
			"observedAt": event.ObservedAt, "receivedAt": event.ReceivedAt,
			"nodeId": event.NodeID, "classification": event.Classification,
		},
	})
	if err != nil {
		return err
	}
	if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(response, "id: %s\nevent: %s\ndata: %s\n\n", encodedCursor, topic, data); err != nil {
		return err
	}
	return controller.Flush()
}

func parseTopics(value string) (map[string]bool, error) {
	if value == "" {
		value = strings.Join(streamTopics, ",")
	}
	parts := strings.Split(value, ",")
	if len(parts) > len(streamTopics) {
		return nil, errors.New("at most seven stream topics may be requested")
	}
	result := make(map[string]bool, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 64 || !slices.Contains(streamTopics, part) {
			return nil, errors.New("stream contains an unsupported topic")
		}
		result[part] = true
	}
	return result, nil
}

func topicForEvent(kind string) string {
	switch {
	case kind == "posture.changed", kind == "finding.opened", kind == "finding.resolved", kind == "action.held":
		return kind
	case strings.HasPrefix(kind, "node."):
		return "node.changed"
	case strings.HasPrefix(kind, "mesh.path"), strings.HasPrefix(kind, "mesh.exit"), kind == "mesh.connection_lost":
		return "path.changed"
	case strings.HasPrefix(kind, "scrambler."):
		return "scrambler.changed"
	default:
		return ""
	}
}

func (server *Server) requestCursor(request *http.Request) (replayCursor, error) {
	query := request.URL.Query().Get("cursor")
	header := request.Header.Get("Last-Event-ID")
	if query != "" && header != "" && query != header {
		return replayCursor{}, errors.New("cursor and Last-Event-ID conflict")
	}
	value := query
	if value == "" {
		value = header
	}
	if value == "" {
		return replayCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > 512 {
		return replayCursor{}, errors.New("invalid cursor encoding")
	}
	var cursor replayCursor
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.Version != 1 || cursor.IngestOrdinal == 0 || !bounded(cursor.EventID, 128) {
		return replayCursor{}, errors.New("invalid cursor fields")
	}
	return cursor, nil
}

func encodeCursor(cursor replayCursor) string {
	encoded, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func parseUint(value string) (uint64, error) {
	return strconv.ParseUint(value, 10, 64)
}
