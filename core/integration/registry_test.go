package integration

import (
	"context"
	"errors"
	"testing"
)

type stubWitness struct{}

func (stubWitness) Submit(context.Context, Checkpoint) (WitnessReceipt, error) {
	return WitnessReceipt{}, errors.New("stub")
}

func stubFactory(value any) Factory {
	return func(context.Context, Options) (any, error) { return value, nil }
}

func TestRegistryFailsClosed(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	ctx := context.Background()
	if err := registry.Register("file", KindExternalWitness, stubFactory(stubWitness{})); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("file", KindEventSink, stubFactory(stubWitness{})); !errors.Is(err, ErrDuplicateIntegration) {
		t.Fatalf("duplicate name (other kind) = %v, want ErrDuplicateIntegration", err)
	}
	if err := registry.RegisterVersioned(Registration{Name: "v2", Kind: KindExternalWitness, Version: 2, Factory: stubFactory(stubWitness{})}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("version 2 = %v, want ErrVersionMismatch", err)
	}
	if err := registry.Register("Bad Name", KindExternalWitness, stubFactory(stubWitness{})); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad name = %v, want ErrInvalidInput", err)
	}
	if err := registry.Register("nilfactory", KindExternalWitness, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil factory = %v, want ErrInvalidInput", err)
	}
	if err := registry.Register("weird", Kind("telemetry-uploader"), stubFactory(stubWitness{})); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown kind = %v, want ErrInvalidInput", err)
	}
	if _, err := registry.Resolve("missing", KindExternalWitness); !errors.Is(err, ErrUnknownIntegration) {
		t.Fatalf("unknown name = %v, want ErrUnknownIntegration", err)
	}
	if _, err := registry.Resolve("file", KindEventSink); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("kind mismatch = %v, want ErrKindMismatch", err)
	}
	witness, err := registry.NewExternalWitness(ctx, "file", Options{"path": "/x"})
	if err != nil || witness == nil {
		t.Fatalf("typed resolve failed: %v", err)
	}
	if err := registry.Register("wrongtype", KindEventSink, stubFactory(stubWitness{})); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.NewEventSink(ctx, "wrongtype", nil); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("factory returning the wrong type = %v, want ErrKindMismatch", err)
	}
	if err := registry.Register("nilvalue", KindEventSink, stubFactory(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.NewEventSink(ctx, "nilvalue", nil); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("factory returning nil = %v, want ErrKindMismatch", err)
	}
	if got := registry.Names(KindExternalWitness); len(got) != 1 || got[0] != "file" {
		t.Fatalf("Names = %v", got)
	}
	var nilRegistry *Registry
	if _, err := nilRegistry.Resolve("file", KindExternalWitness); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil registry = %v", err)
	}
}

func TestRegistryCopiesOptionsBeforeFactory(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	var seen Options
	if err := registry.Register("capture", KindExternalWitness, func(_ context.Context, options Options) (any, error) {
		seen = options
		return stubWitness{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	original := Options{"url": "https://witness.example"}
	if _, err := registry.NewExternalWitness(context.Background(), "capture", original); err != nil {
		t.Fatal(err)
	}
	seen["url"] = "mutated"
	if original["url"] != "https://witness.example" {
		t.Fatal("factory shares the caller's option map")
	}
	if _, err := registry.NewExternalWitness(context.Background(), "capture", Options{"bad key": "x"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-canonical option key = %v", err)
	}
}
