package main

import (
	"bytes"
	"context"
	"testing"
)

func TestRunWritesDeterministicScenario(t *testing.T) {
	t.Parallel()
	var first, second bytes.Buffer
	if err := run(context.Background(), []string{"-compact"}, &first, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"offline", "-compact"}, &second, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || !bytes.Contains(first.Bytes(), []byte(`"finalActionDecision":"ALLOW"`)) {
		t.Fatalf("unexpected simulator output: %s", first.String())
	}
}

func TestRunRejectsAmbientOrAmbiguousInputs(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{{"positional"}, {"-start", "now"}} {
		if err := run(context.Background(), arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted arguments %v", arguments)
		}
	}
}
