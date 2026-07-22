package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/config"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/findings"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/core/posture"
	"github.com/DBarr3/AntiFlock/core/scrambler"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

type Options struct {
	Config           config.Config
	Database         *storage.DB
	Events           *events.Store
	Audit            *audit.Service
	Enrollment       *enrollment.Service
	PolicyCompiler   *policy.Compiler
	PostureEngine    *posture.Engine
	Findings         *findings.Service
	Scrambler        *scrambler.Planner
	DeploymentID     string
	Credentials      []Credential
	AuthorizationKey []byte
	NodeClientCAs    *x509.CertPool
	Version          string
	Clock            func() time.Time
}

// Server exposes the authenticated REST and live-projection surface. It owns
// no database or key material and can therefore be shut down before the
// composition root closes those dependencies.
type Server struct {
	config        config.Config
	database      database
	events        eventBus
	audit         *audit.Service
	enrollment    *enrollment.Service
	policy        *policy.Compiler
	posture       *posture.Engine
	findings      *findings.Service
	scrambler     *scrambler.Planner
	authenticator *tokenAuthenticator
	actions       *actionGate
	deploymentID  string
	version       string
	clock         func() time.Time
	handler       http.Handler
	requestSlots  chan struct{}
	ready         atomic.Bool
	nodeClientCAs *x509.CertPool
	simulation    bool
}

func New(options Options) (*Server, error) {
	if options.Database == nil || options.Events == nil || options.Audit == nil || options.Enrollment == nil ||
		options.PolicyCompiler == nil || options.PostureEngine == nil || options.Findings == nil || options.Scrambler == nil || options.DeploymentID == "" {
		return nil, errors.New("core server requires database, events, audit, enrollment, policy, posture, findings, Scrambler, and deployment identity")
	}
	if err := options.Config.Validate(); err != nil {
		return nil, fmt.Errorf("validate Core server config: %w", err)
	}
	clock := options.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	authenticator, err := newTokenAuthenticator(options.Credentials, clock)
	if err != nil {
		return nil, err
	}
	if len(options.AuthorizationKey) < 32 {
		return nil, errors.New("one-time authorization key must contain at least 32 bytes")
	}
	simulation := strings.EqualFold(os.Getenv("ANTIFLOCK_DEMO_MODE"), "true")
	authorizationKey := sha256.Sum256(append([]byte("AntiFlock-One-Time-Authorization-v1\x00"), options.AuthorizationKey...))
	actions, err := newActionGate(
		options.Database, options.Audit, options.DeploymentID, options.Config.Protection,
		authorizationKey[:], options.PostureEngine, options.Findings, simulation, clock,
	)
	if err != nil {
		return nil, err
	}
	server := &Server{
		config: options.Config, database: options.Database, events: options.Events,
		audit: options.Audit, enrollment: options.Enrollment, policy: options.PolicyCompiler,
		posture: options.PostureEngine, findings: options.Findings, scrambler: options.Scrambler,
		authenticator: authenticator, actions: actions,
		deploymentID: options.DeploymentID, version: options.Version, clock: clock,
		requestSlots: make(chan struct{}, defaultRequestLimit), nodeClientCAs: options.NodeClientCAs,
		simulation: simulation,
	}
	if server.version == "" {
		server.version = "development"
	}
	server.handler = server.routes()
	server.ready.Store(true)
	return server, nil
}

func (server *Server) Handler() http.Handler {
	return server.handler
}

// Serve listens according to the already-validated config and drains active
// requests on cancellation. Long-lived SSE and action-wait handlers inherit a
// base context that is cancelled before Shutdown begins.
func (server *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("core server context is required")
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	httpServer := &http.Server{
		Addr: server.config.Server.Listen, Handler: server.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 0, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return serveCtx },
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: server.nodeClientCAs,
		},
	}
	listener, err := net.Listen("tcp", server.config.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen for Core API: %w", err)
	}
	defer listener.Close()
	errCh := make(chan error, 1)
	go func() {
		if server.config.Server.TLSCertFile != "" || server.config.Server.TLSKeyFile != "" {
			if server.config.Server.TLSCertFile == "" || server.config.Server.TLSKeyFile == "" {
				errCh <- errors.New("both TLS certificate and key files are required")
				return
			}
			errCh <- httpServer.ServeTLS(listener, server.config.Server.TLSCertFile, server.config.Server.TLSKeyFile)
			return
		}
		errCh <- httpServer.Serve(listener)
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		server.ready.Store(false)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		shutdownErr := httpServer.Shutdown(shutdownCtx)
		serveErr := <-errCh
		if !errors.Is(serveErr, http.ErrServerClosed) {
			shutdownErr = errors.Join(shutdownErr, serveErr)
		}
		return shutdownErr
	}
}

func (server *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.handleHealth)
	mux.HandleFunc("GET /readyz", server.handleReady)
	mux.HandleFunc("GET /v1/overview", server.handleOverview)
	mux.HandleFunc("GET /v1/nodes", server.handleNodes)
	mux.HandleFunc("GET /v1/topology", server.handleTopology)
	mux.HandleFunc("GET /v1/paths", server.handlePaths)
	mux.HandleFunc("GET /v1/events", server.handleEvents)
	mux.HandleFunc("POST /v1/events/batch", server.handleEventBatch)
	mux.HandleFunc("POST /v1/telemetry/events:submit", server.handleEventBatch)
	mux.HandleFunc("GET /v1/findings", server.handleFindings)
	mux.HandleFunc("GET /v1/posture", server.handlePosture)
	mux.HandleFunc("POST /v1/posture/report", server.handlePostureReport)
	mux.HandleFunc("GET /v1/field/reports", server.handleEmptyList("reports"))
	mux.HandleFunc("GET /v1/footprint", server.handleFootprint)
	mux.HandleFunc("GET /v1/scrambler/state", server.handleScrambler)
	mux.HandleFunc("POST /v1/scrambler/simulate", server.handleSimulateScrambler)
	mux.HandleFunc("POST /v1/scrambler/activate", server.handleActivateScrambler)
	mux.HandleFunc("POST /v1/policies/validate", server.handleValidatePolicy)
	mux.HandleFunc("POST /v1/policies/compile", server.handleCompilePolicy)
	mux.HandleFunc("GET /v1/stream", server.handleStream)
	mux.HandleFunc("GET /v1/actions", server.handleListActions)
	mux.HandleFunc("POST /v1/actions/evaluate", server.handleEvaluateAction)
	mux.HandleFunc("POST /v1/actions/{id}/wait", server.handleWaitAction)
	mux.HandleFunc("POST /v1/actions/{id}/authorize", server.handleAuthorizeAction)
	mux.HandleFunc("POST /v1/actions/{id}/audit", server.handleActionAudit)
	mux.HandleFunc("POST /v1/enrollment/tokens", server.handleCreateEnrollmentToken)
	mux.HandleFunc("POST /v1/enrollment/nodes", server.handleEnrollNode)
	mux.HandleFunc("POST /v1/enrollment/{id}/approve", server.handleApproveEnrollment)
	mux.HandleFunc("POST /v1/enrollment/{id}/deny", server.handleDenyEnrollment)
	mux.HandleFunc("PATCH /v1/nodes/{id}", server.handleUpdateNodeMetadata)
	mux.HandleFunc("POST /v1/nodes/{id}/suspend", server.handleNodeStatus(model.NodeSuspended))
	mux.HandleFunc("POST /v1/nodes/{id}/reactivate", server.handleNodeStatus(model.NodeActive))
	mux.HandleFunc("POST /v1/nodes/{id}/revoke", server.handleNodeStatus(model.NodeRevoked))

	for _, pattern := range []string{
		"POST /v1/plans/{id}/apply", "POST /v1/plans/{id}/rollback", "POST /v1/field/reports",
		"POST /v1/footprint/assets",
	} {
		mux.HandleFunc(pattern, server.handleUnavailable)
	}

	return server.recoverPanics(server.securityHeaders(server.authenticate(server.limitConcurrency(mux))))
}

func (server *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" || request.URL.Path == "/readyz" ||
			(request.Method == http.MethodPost && request.URL.Path == "/v1/enrollment/nodes") {
			next.ServeHTTP(response, request)
			return
		}
		value, ok := server.authenticator.authenticate(request)
		if !ok {
			response.Header().Set("WWW-Authenticate", `Bearer realm="antiflock-core"`)
			writeAPIError(response, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication is required.", "", false)
			return
		}
		required := requiredScope(request)
		if required == "" || !value.hasScope(required) {
			writeAPIError(response, http.StatusForbidden, "FORBIDDEN", "This credential is not authorized for the requested operation.", "", false)
			return
		}
		if !value.validatePeerCertificate(request, server.deploymentID) {
			writeAPIError(response, http.StatusForbidden, "NODE_CREDENTIAL_REQUIRED", "A verified node client certificate is required.", "", false)
			return
		}
		if required == ScopeAgentIngest {
			node, err := server.database.GetNode(request.Context(), value.NodeID)
			if err != nil || node.Status != model.NodeActive {
				writeAPIError(response, http.StatusForbidden, "NODE_INACTIVE", "The node credential is not active.", "", false)
				return
			}
		}
		next.ServeHTTP(response, withPrincipal(request, value))
	})
}

func requiredScope(request *http.Request) string {
	path := request.URL.Path
	switch {
	case request.Method == http.MethodPost && strings.HasPrefix(path, "/v1/actions/") && strings.HasSuffix(path, "/authorize"):
		return ScopeActionsAuthorize
	case strings.HasPrefix(path, "/v1/actions/"):
		return ScopeActionsExecute
	case path == "/v1/events/batch", path == "/v1/telemetry/events:submit", path == "/v1/posture/report":
		return ScopeAgentIngest
	case path == "/v1/enrollment/tokens", strings.HasSuffix(path, "/approve"), strings.HasSuffix(path, "/deny"):
		return ScopeEnrollmentAdmin
	case request.Method == http.MethodGet:
		return ScopeDashboardRead
	case request.Method == http.MethodPost, request.Method == http.MethodPatch:
		return ScopeOperatorMutate
	default:
		return ""
	}
}

func (server *Server) limitConcurrency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case server.requestSlots <- struct{}{}:
			defer func() { <-server.requestSlots }()
			next.ServeHTTP(response, request)
		default:
			response.Header().Set("Retry-After", "1")
			writeAPIError(response, http.StatusTooManyRequests, "RATE_LIMITED", "Core is handling its current request limit.", "", true)
		}
	})
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}

func (server *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		defer func() {
			if recover() != nil {
				writeAPIError(response, http.StatusInternalServerError, "INTERNAL", "Core could not complete the request.", "", true)
			}
		}()
		next.ServeHTTP(response, request)
	})
}

func (server *Server) handleHealth(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "alive"})
}

func (server *Server) handleReady(response http.ResponseWriter, request *http.Request) {
	if !server.ready.Load() {
		writeAPIError(response, http.StatusServiceUnavailable, "NOT_READY", "Core is not ready.", "", true)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := server.database.Health(ctx); err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "NOT_READY", "Core is not ready.", "", true)
		return
	}
	if err := server.audit.Verify(ctx); err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "NOT_READY", "Core is not ready.", "", false)
		return
	}
	if err := server.database.VerifyEventRetentionTombstones(ctx); err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "NOT_READY", "Core is not ready.", "", false)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

func (server *Server) handleEvaluateAction(response http.ResponseWriter, request *http.Request) {
	var body evaluateRequest
	if err := decodeJSON(response, request, &body, 64<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false)
		return
	}
	decision, status, err := server.actions.evaluate(request.Context(), body.Action)
	if err != nil {
		server.writeDomainError(response, status, err, body.Action.OperationID)
		return
	}
	writeJSON(response, status, decision)
}

func (server *Server) handleWaitAction(response http.ResponseWriter, request *http.Request) {
	var body waitRequest
	if err := decodeJSON(response, request, &body, 16<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false)
		return
	}
	posture, restored, status, err := server.actions.wait(request.Context(), request.PathValue("id"), body)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		server.writeDomainError(response, status, err, "")
		return
	}
	writeJSON(response, status, map[string]any{"restored": restored, "snapshot": posture})
}

func (server *Server) handleAuthorizeAction(response http.ResponseWriter, request *http.Request) {
	var body authorizeRequest
	if err := decodeJSON(response, request, &body, 32<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false)
		return
	}
	decision, status, err := server.actions.authorize(request.Context(), request.PathValue("id"), body)
	if err != nil {
		server.writeDomainError(response, status, err, body.OperationID)
		return
	}
	writeJSON(response, status, decision)
}

func (server *Server) handleActionAudit(response http.ResponseWriter, request *http.Request) {
	var body auditEventRequest
	if err := decodeJSON(response, request, &body, 64<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false)
		return
	}
	status, err := server.actions.appendLifecycleAudit(request.Context(), request.PathValue("id"), body)
	if err != nil {
		server.writeDomainError(response, status, err, "")
		return
	}
	response.WriteHeader(status)
}

func (server *Server) handlePostureReport(response http.ResponseWriter, request *http.Request) {
	var body postureReport
	if err := decodeJSON(response, request, &body, 32<<10); err != nil {
		writeAPIError(response, http.StatusBadRequest, "INVALID_JSON", safeDecodeMessage(err), "", false)
		return
	}
	caller := principalFromContext(request.Context())
	if caller.NodeID == "" || caller.NodeID != body.NodeID {
		writeAPIError(response, http.StatusForbidden, "NODE_SCOPE_MISMATCH", "Agent credential does not match the posture node.", "", false)
		return
	}
	if err := server.actions.reportPosture(request.Context(), body); err != nil {
		server.writeDomainError(response, http.StatusBadRequest, err, "")
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (server *Server) handleUnavailable(response http.ResponseWriter, _ *http.Request) {
	writeAPIError(response, http.StatusNotImplemented, "CAPABILITY_UNAVAILABLE", "This capability is not available in the current Core build.", "", false)
}

func (server *Server) writeDomainError(response http.ResponseWriter, status int, err error, operationID string) {
	if status == 0 {
		status = http.StatusInternalServerError
	}
	reason := "FAILED_PRECONDITION"
	message := "The request could not be completed."
	retryable := false
	switch status {
	case http.StatusBadRequest:
		reason, message = "INVALID_ARGUMENT", err.Error()
	case http.StatusNotFound:
		reason, message = "NOT_FOUND", "The requested resource was not found."
	case http.StatusConflict:
		reason, message = "CONFLICT", "The request conflicts with committed state."
	case http.StatusForbidden:
		reason, message = "FORBIDDEN", "Policy does not authorize this operation."
	case http.StatusInternalServerError:
		reason, message, retryable = "INTERNAL", "Core could not complete the request.", true
	}
	writeAPIError(response, status, reason, message, operationID, retryable)
}
