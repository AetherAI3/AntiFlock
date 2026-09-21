package capability

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
)

// Probe timeout bounds.
const (
	DefaultProbeTimeout = 5 * time.Second
	MaxProbeTimeout     = 60 * time.Second
)

// Options configures Discover. Registration is explicit: there is no global
// prober registry, so a manifest can only contain what the caller wired in.
type Options struct {
	// NodeID binds the manifest to this node. Required.
	NodeID string
	// Revision is the manifest revision; zero means 1.
	Revision uint64
	// PolicyKeyID records the policy public key the node trusts. Required.
	PolicyKeyID string
	// AttestationRef is an optional opaque attestation reference.
	AttestationRef string
	// Probers maps driver name to prober. Each prober's results must report
	// DriverName equal to its registration name.
	Probers map[string]driver.Prober
	// ProbeTimeout bounds every individual probe. Zero means
	// DefaultProbeTimeout; values above MaxProbeTimeout are rejected.
	ProbeTimeout time.Duration
	// Now supplies the issue time; nil means time.Now.
	Now func() time.Time
	// NodeKey, when set, signs the manifest before it is returned.
	NodeKey ed25519.PrivateKey
}

// DiscoveryError carries a stable reason code and the driver and key it
// concerns. Err never contains driver output.
type DiscoveryError struct {
	Code   string
	Driver string
	Key    string
	Err    error
}

func (err *DiscoveryError) Error() string {
	message := err.Code
	if err.Driver != "" {
		message += " driver=" + err.Driver
	}
	if err.Key != "" {
		message += " key=" + err.Key
	}
	if err.Err != nil {
		message += ": " + err.Err.Error()
	}
	return message
}

func (err *DiscoveryError) Unwrap() error { return err.Err }

// Discover runs every registered prober under its own bounded timeout,
// validates every result, rejects duplicate capability keys, and issues a
// node-bound manifest whose expiry is the earliest probe expiry. Any failure
// fails closed: no partial manifest is ever returned.
func Discover(ctx context.Context, opts Options) (*Manifest, error) {
	if ctx == nil {
		return nil, &DiscoveryError{Code: ReasonOptionsInvalid, Err: errors.New("context is required")}
	}
	if !validIdentifier(opts.NodeID, MaxNodeIDLength) || !validIdentifier(opts.PolicyKeyID, MaxNodeIDLength) {
		return nil, &DiscoveryError{Code: ReasonOptionsInvalid, Err: errors.New("node id and policy key id must be bounded printable identifiers")}
	}
	if opts.ProbeTimeout < 0 || opts.ProbeTimeout > MaxProbeTimeout {
		return nil, &DiscoveryError{Code: ReasonOptionsInvalid, Err: fmt.Errorf("probe timeout must be between 0 and %s", MaxProbeTimeout)}
	}
	if opts.NodeKey != nil && len(opts.NodeKey) != ed25519.PrivateKeySize {
		return nil, &DiscoveryError{Code: ReasonOptionsInvalid, Err: errors.New("node key must be an Ed25519 private key")}
	}
	if len(opts.Probers) == 0 {
		return nil, &DiscoveryError{Code: ReasonNoCapabilities, Err: errors.New("no probers are registered")}
	}
	timeout := opts.ProbeTimeout
	if timeout == 0 {
		timeout = DefaultProbeTimeout
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	revision := opts.Revision
	if revision == 0 {
		revision = 1
	}

	names := make([]string, 0, len(opts.Probers))
	for name := range opts.Probers {
		names = append(names, name)
	}
	slices.Sort(names)

	issuedAt := now().UTC()
	owners := make(map[string]string)
	entries := make([]Entry, 0)
	expiresAt := issuedAt.Add(MaxManifestValidity)
	for _, name := range names {
		prober := opts.Probers[name]
		if !validIdentifier(name, MaxNodeIDLength) || prober == nil {
			return nil, &DiscoveryError{Code: ReasonOptionsInvalid, Driver: name, Err: errors.New("prober registration name must be a bounded identifier and the prober non-nil")}
		}
		results, err := runProbe(ctx, name, prober, timeout)
		if err != nil {
			return nil, err
		}
		for _, result := range results {
			if err := result.Validate(); err != nil {
				return nil, &DiscoveryError{Code: ReasonProbeInvalid, Driver: name, Key: result.Key, Err: err}
			}
			if result.DriverName != name {
				return nil, &DiscoveryError{Code: ReasonDriverMismatch, Driver: name, Key: result.Key, Err: errors.New("probe result names a different driver")}
			}
			if owner, duplicate := owners[result.Key]; duplicate {
				return nil, &DiscoveryError{Code: ReasonDuplicateKey, Driver: name, Key: result.Key, Err: fmt.Errorf("key already reported by driver %q", owner)}
			}
			owners[result.Key] = name
			entry, err := EntryFromProbe(result)
			if err != nil {
				return nil, &DiscoveryError{Code: ReasonProbeInvalid, Driver: name, Key: result.Key, Err: err}
			}
			entries = append(entries, entry)
			if entry.ExpiresAt.Before(expiresAt) {
				expiresAt = entry.ExpiresAt
			}
		}
	}
	if len(entries) == 0 {
		return nil, &DiscoveryError{Code: ReasonNoCapabilities, Err: errors.New("probers reported no capabilities")}
	}
	if !expiresAt.After(issuedAt) {
		return nil, &DiscoveryError{Code: ReasonExpired, Err: errors.New("a probe result expired before the manifest could be issued")}
	}
	manifest := &Manifest{
		SchemaVersion:  SchemaVersion,
		NodeID:         opts.NodeID,
		Revision:       revision,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
		Capabilities:   entries,
		PolicyKeyID:    opts.PolicyKeyID,
		AttestationRef: opts.AttestationRef,
	}
	if err := manifest.Validate(); err != nil {
		return nil, &DiscoveryError{Code: ReasonSchema, Err: err}
	}
	if opts.NodeKey != nil {
		if err := manifest.Sign(opts.NodeKey); err != nil {
			return nil, &DiscoveryError{Code: ReasonSignatureInvalid, Err: err}
		}
	}
	return manifest, nil
}

type probeOutcome struct {
	results []driver.ProbeResult
	err     error
}

// runProbe runs one prober under a bounded timeout. A prober that ignores its
// context is abandoned, not waited for; its late results are discarded.
func runProbe(parent context.Context, name string, prober driver.Prober, timeout time.Duration) ([]driver.ProbeResult, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	outcomes := make(chan probeOutcome, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				outcomes <- probeOutcome{err: errors.New("prober panicked")}
			}
		}()
		results, err := prober.Probe(ctx)
		outcomes <- probeOutcome{results: results, err: err}
	}()
	select {
	case outcome := <-outcomes:
		if outcome.err != nil {
			if errors.Is(outcome.err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, &DiscoveryError{Code: ReasonProbeTimeout, Driver: name, Err: context.DeadlineExceeded}
			}
			// The prober's error text may contain raw command output; only its
			// existence is reported.
			return nil, &DiscoveryError{Code: ReasonProbeFailed, Driver: name, Err: errors.New("prober returned an error")}
		}
		if ctx.Err() != nil {
			return nil, &DiscoveryError{Code: ReasonProbeTimeout, Driver: name, Err: ctx.Err()}
		}
		return outcome.results, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &DiscoveryError{Code: ReasonProbeTimeout, Driver: name, Err: ctx.Err()}
		}
		return nil, &DiscoveryError{Code: ReasonProbeFailed, Driver: name, Err: ctx.Err()}
	}
}
