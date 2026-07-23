package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	ScopeDashboardRead    = "dashboard:read"
	ScopeOperatorMutate   = "operator:mutate"
	ScopeEnrollmentAdmin  = "enrollment:admin"
	ScopeActionsExecute   = "actions:execute"
	ScopeActionsAuthorize = "actions:authorize"
	ScopeAgentIngest      = "agent:ingest"
)

var knownScopes = []string{
	ScopeDashboardRead, ScopeOperatorMutate, ScopeEnrollmentAdmin, ScopeActionsExecute, ScopeActionsAuthorize, ScopeAgentIngest,
}

// Credential configures one independently revocable calling identity. Tokens
// are hashed during server construction and are never retained in plaintext.
type Credential struct {
	Token         string
	PrincipalID   string
	Scopes        []string
	NodeID        string
	ApplicationID string
	ExpiresAt     time.Time
	RequireMTLS   bool
}

type principalContextKey struct{}

type principal struct {
	ID            string
	Scopes        map[string]bool
	NodeID        string
	ApplicationID string
	ExpiresAt     time.Time
	RequireMTLS   bool
}

func (value principal) hasScope(scope string) bool {
	return value.Scopes[scope]
}

func (value principal) allowsAction(request secureActionRequest) bool {
	return (value.ApplicationID == "" || value.ApplicationID == request.ApplicationID) &&
		(value.NodeID == "" || value.NodeID == request.NodeID)
}

type credentialDigest struct {
	digest    [sha256.Size]byte
	principal principal
}

type tokenAuthenticator struct {
	credentials []credentialDigest
	clock       func() time.Time
}

func newTokenAuthenticator(credentials []Credential, clock func() time.Time) (*tokenAuthenticator, error) {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if len(credentials) == 0 {
		return &tokenAuthenticator{clock: clock}, nil
	}
	result := &tokenAuthenticator{credentials: make([]credentialDigest, 0, len(credentials)), clock: clock}
	seenTokens := make(map[[sha256.Size]byte]struct{}, len(credentials))
	seenPrincipals := make(map[string]struct{}, len(credentials))
	for _, credential := range credentials {
		if len(credential.Token) < 32 {
			return nil, errors.New("API bearer tokens must contain at least 32 bytes")
		}
		if !bounded(credential.PrincipalID, 128) {
			return nil, errors.New("API credential principal id is invalid")
		}
		if _, duplicate := seenPrincipals[credential.PrincipalID]; duplicate {
			return nil, errors.New("API credential principal ids must be unique")
		}
		seenPrincipals[credential.PrincipalID] = struct{}{}
		if len(credential.Scopes) == 0 {
			return nil, errors.New("API credential requires an explicit scope")
		}
		scopes := make(map[string]bool, len(credential.Scopes))
		for _, scope := range credential.Scopes {
			if !slices.Contains(knownScopes, scope) || scopes[scope] {
				return nil, errors.New("API credential contains an invalid or duplicate scope")
			}
			scopes[scope] = true
		}
		if credential.RequireMTLS && credential.NodeID == "" {
			return nil, errors.New("mTLS credentials must be bound to a node id")
		}
		digest := sha256.Sum256([]byte(credential.Token))
		if _, duplicate := seenTokens[digest]; duplicate {
			return nil, errors.New("API bearer tokens must be unique")
		}
		seenTokens[digest] = struct{}{}
		result.credentials = append(result.credentials, credentialDigest{
			digest: digest,
			principal: principal{
				ID: credential.PrincipalID, Scopes: scopes, NodeID: credential.NodeID,
				ApplicationID: credential.ApplicationID, ExpiresAt: credential.ExpiresAt,
				RequireMTLS: credential.RequireMTLS,
			},
		})
	}
	return result, nil
}

func (authenticator *tokenAuthenticator) authenticate(request *http.Request) (principal, bool) {
	candidate := ""
	headerValues := request.Header.Values("Authorization")
	if len(headerValues) == 1 && strings.HasPrefix(headerValues[0], "Bearer ") && strings.Count(headerValues[0], " ") == 1 {
		candidate = strings.TrimPrefix(headerValues[0], "Bearer ")
	}
	actual := sha256.Sum256([]byte(candidate))
	matched := -1
	for index := range authenticator.credentials {
		if subtle.ConstantTimeCompare(actual[:], authenticator.credentials[index].digest[:]) == 1 {
			matched = index
		}
	}
	if candidate == "" || matched < 0 {
		return principal{}, false
	}
	value := authenticator.credentials[matched].principal
	if !value.ExpiresAt.IsZero() && !authenticator.clock().Before(value.ExpiresAt) {
		return principal{}, false
	}
	return value, true
}

func (value principal) validatePeerCertificate(request *http.Request, deploymentID string) bool {
	if !value.RequireMTLS {
		return true
	}
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if leaf.Subject.CommonName != value.NodeID || !slices.Contains(leaf.Subject.Organization, deploymentID) {
		return false
	}
	return slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func principalFromContext(ctx context.Context) principal {
	value, _ := ctx.Value(principalContextKey{}).(principal)
	if value.ID == "" {
		value.ID = "unknown-principal"
	}
	return value
}

func withPrincipal(request *http.Request, value principal) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), principalContextKey{}, value))
}
