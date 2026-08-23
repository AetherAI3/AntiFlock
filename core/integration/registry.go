package integration

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Kind names the seam an integration implements.
type Kind string

// Kinds a Registry accepts.
const (
	KindExternalWitness  Kind = "external-witness"
	KindIdentityProvider Kind = "identity-provider"
	KindPolicySource     Kind = "policy-source"
	KindEventSink        Kind = "event-sink"
	KindFindingSink      Kind = "finding-sink"
	KindDecisionConsumer Kind = "decision-consumer"
	KindRecoveryVerifier Kind = "recovery-verifier"
)

// ValidKind reports whether kind is one of the defined seams.
func ValidKind(kind Kind) bool {
	switch kind {
	case KindExternalWitness, KindIdentityProvider, KindPolicySource, KindEventSink,
		KindFindingSink, KindDecisionConsumer, KindRecoveryVerifier:
		return true
	}
	return false
}

// MaxOptions bounds the option map handed to a factory.
const MaxOptions = 64

// Options is the bounded, string-only configuration a factory receives.
// Secrets may appear as option values; a factory must not log them.
type Options map[string]string

// Factory constructs one integration. The returned value must implement the
// interface for the registered Kind; typed resolvers check this and fail
// closed otherwise.
type Factory func(ctx context.Context, options Options) (any, error)

// Registration describes one integration offered to a Registry.
type Registration struct {
	// Name is the operator-facing selector (for example "file" or "https").
	Name string
	Kind Kind
	// Version must equal InterfaceVersion.
	Version int
	Factory Factory
}

// Registry is an explicit, non-global table of named integration factories.
// There is no init-time registration and no package-level default: the
// composition root creates a Registry, registers what it ships, and resolves
// by name. Unknown names, kind mismatches, duplicate names, and version
// mismatches all fail closed.
//
// InterfaceVersion = 1.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Registration
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]Registration)}
}

// Register adds one registration. It rejects invalid names, unknown kinds,
// a Version other than InterfaceVersion, a nil factory, and duplicate names
// (regardless of kind).
func (registry *Registry) Register(name string, kind Kind, factory Factory) error {
	return registry.RegisterVersioned(Registration{Name: name, Kind: kind, Version: InterfaceVersion, Factory: factory})
}

// RegisterVersioned is Register with an explicit declared version. An
// adapter compiled against a different contract declares its own version
// and is rejected here instead of misbehaving later.
func (registry *Registry) RegisterVersioned(registration Registration) error {
	if registry == nil {
		return fmt.Errorf("%w: registry is nil", ErrInvalidInput)
	}
	if !validRegistrationName(registration.Name) {
		return fmt.Errorf("%w: registration name must be 1-64 lowercase letters, digits, '.', '_' or '-'", ErrInvalidInput)
	}
	if !ValidKind(registration.Kind) {
		return fmt.Errorf("%w: registration kind %q is not recognised", ErrInvalidInput, string(registration.Kind))
	}
	if registration.Version != InterfaceVersion {
		return fmt.Errorf("%w: %q declares version %d, registry requires %d", ErrVersionMismatch, registration.Name, registration.Version, InterfaceVersion)
	}
	if registration.Factory == nil {
		return fmt.Errorf("%w: registration factory is nil", ErrInvalidInput)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.entries[registration.Name]; exists {
		return fmt.Errorf("%w: %q", ErrDuplicateIntegration, registration.Name)
	}
	registry.entries[registration.Name] = registration
	return nil
}

// Resolve returns the registration for name if it exists and is of kind.
func (registry *Registry) Resolve(name string, kind Kind) (Registration, error) {
	if registry == nil {
		return Registration{}, fmt.Errorf("%w: registry is nil", ErrInvalidInput)
	}
	if !validRegistrationName(name) {
		return Registration{}, fmt.Errorf("%w: %q is not a valid registration name", ErrUnknownIntegration, name)
	}
	if !ValidKind(kind) {
		return Registration{}, fmt.Errorf("%w: kind %q is not recognised", ErrKindMismatch, string(kind))
	}
	registry.mu.RLock()
	registration, exists := registry.entries[name]
	registry.mu.RUnlock()
	if !exists {
		return Registration{}, fmt.Errorf("%w: %q", ErrUnknownIntegration, name)
	}
	if registration.Kind != kind {
		return Registration{}, fmt.Errorf("%w: %q is registered as %s, not %s", ErrKindMismatch, name, registration.Kind, kind)
	}
	if registration.Version != InterfaceVersion {
		return Registration{}, fmt.Errorf("%w: %q", ErrVersionMismatch, name)
	}
	return registration, nil
}

// Names lists registered names for kind, sorted.
func (registry *Registry) Names(kind Kind) []string {
	if registry == nil {
		return nil
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	names := make([]string, 0, len(registry.entries))
	for name, registration := range registry.entries {
		if registration.Kind == kind {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (registry *Registry) build(ctx context.Context, name string, kind Kind, options Options) (any, error) {
	registration, err := registry.Resolve(name, kind)
	if err != nil {
		return nil, err
	}
	if len(options) > MaxOptions {
		return nil, fmt.Errorf("%w: more than %d options", ErrInvalidInput, MaxOptions)
	}
	copied := make(Options, len(options))
	for key, value := range options {
		if !ValidIdentifier(key) {
			return nil, fmt.Errorf("%w: option key is not a canonical identifier", ErrInvalidInput)
		}
		copied[key] = value
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	value, err := registration.Factory(ctx, copied)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("%w: factory %q returned nil", ErrKindMismatch, name)
	}
	return value, nil
}

// NewExternalWitness resolves and constructs a witness, failing closed if the
// factory returns any other type.
func (registry *Registry) NewExternalWitness(ctx context.Context, name string, options Options) (ExternalWitness, error) {
	return resolveTyped[ExternalWitness](registry, ctx, name, KindExternalWitness, options)
}

// NewIdentityProvider resolves and constructs an identity provider.
func (registry *Registry) NewIdentityProvider(ctx context.Context, name string, options Options) (IdentityProvider, error) {
	return resolveTyped[IdentityProvider](registry, ctx, name, KindIdentityProvider, options)
}

// NewPolicySource resolves and constructs a policy source.
func (registry *Registry) NewPolicySource(ctx context.Context, name string, options Options) (PolicySource, error) {
	return resolveTyped[PolicySource](registry, ctx, name, KindPolicySource, options)
}

// NewEventSink resolves and constructs an event sink.
func (registry *Registry) NewEventSink(ctx context.Context, name string, options Options) (EventSink, error) {
	return resolveTyped[EventSink](registry, ctx, name, KindEventSink, options)
}

// NewFindingSink resolves and constructs a finding sink.
func (registry *Registry) NewFindingSink(ctx context.Context, name string, options Options) (FindingSink, error) {
	return resolveTyped[FindingSink](registry, ctx, name, KindFindingSink, options)
}

// NewDecisionConsumer resolves and constructs a decision consumer.
func (registry *Registry) NewDecisionConsumer(ctx context.Context, name string, options Options) (DecisionConsumer, error) {
	return resolveTyped[DecisionConsumer](registry, ctx, name, KindDecisionConsumer, options)
}

// NewRecoveryVerifier resolves and constructs a recovery verifier.
func (registry *Registry) NewRecoveryVerifier(ctx context.Context, name string, options Options) (RecoveryVerifier, error) {
	return resolveTyped[RecoveryVerifier](registry, ctx, name, KindRecoveryVerifier, options)
}

func resolveTyped[T any](registry *Registry, ctx context.Context, name string, kind Kind, options Options) (T, error) {
	var zero T
	value, err := registry.build(ctx, name, kind, options)
	if err != nil {
		return zero, err
	}
	typed, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("%w: factory %q did not produce a %s", ErrKindMismatch, name, kind)
	}
	return typed, nil
}

func validRegistrationName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for index, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case index > 0 && (r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}
