package id_test

import (
	"strings"
	"testing"

	"github.com/DBarr3/AntiFlock/internal/id"
)

func TestNewUsesPrefixAndFreshEntropy(t *testing.T) {
	t.Parallel()
	first := id.New("node")
	second := id.New("node")
	if !strings.HasPrefix(first, "node_") || len(first) != len("node_")+32 {
		t.Fatalf("unexpected id format %q", first)
	}
	if first == second {
		t.Fatal("identifiers repeated")
	}
}
