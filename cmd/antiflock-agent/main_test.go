package main

import (
	"bytes"
	"context"
	"flag"
	"strings"
	"testing"
)

func TestAgentExecutableExposesReadOnlyCollectionOnly(t *testing.T) {
	t.Parallel()
	var help bytes.Buffer
	err := run(context.Background(), []string{"-help"}, &bytes.Buffer{}, &help)
	if err != flag.ErrHelp {
		t.Fatalf("help result = %v", err)
	}
	for _, forbidden := range []string{"nft", "apply", "enforce", "rollback", "mutate"} {
		if strings.Contains(strings.ToLower(help.String()), forbidden) {
			t.Fatalf("agent help exposed mutation surface %q: %s", forbidden, help.String())
		}
	}
	if err := run(context.Background(), []string{"-nft-apply"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("agent accepted an nftables mutation flag")
	}
}
