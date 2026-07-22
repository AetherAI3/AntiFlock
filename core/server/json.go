package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

type apiErrorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	ReasonCode      string           `json:"reasonCode"`
	SafeMessage     string           `json:"safeMessage"`
	OperationID     string           `json:"operationId,omitempty"`
	Retryable       bool             `json:"retryable"`
	FieldViolations []fieldViolation `json:"fieldViolations,omitempty"`
}

type fieldViolation struct {
	Field       string `json:"field"`
	ReasonCode  string `json:"reasonCode"`
	Description string `json:"description"`
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any, maximum int64) error {
	contentType := request.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximum)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeAPIError(response http.ResponseWriter, status int, reason, message, operationID string, retryable bool) {
	writeJSON(response, status, apiErrorEnvelope{Error: apiError{
		ReasonCode: reason, SafeMessage: message, OperationID: operationID, Retryable: retryable,
	}})
}

func safeDecodeMessage(err error) string {
	if err == nil {
		return "invalid request"
	}
	message := err.Error()
	if strings.Contains(message, "request body too large") || strings.Contains(message, "http: request body too large") {
		return "request body exceeds the allowed size"
	}
	if strings.Contains(message, "unknown field") {
		return "request contains an unknown field"
	}
	return "request body is not valid JSON for this endpoint"
}
