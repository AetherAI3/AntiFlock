package main

import (
	"testing"
)

func TestLoadOptionalTokenAllowsMTLSOnlyCore(t *testing.T) {
	t.Setenv("ANTIFLOCK_AGENT_TOKEN", "")
	t.Setenv("ANTIFLOCK_AGENT_TOKEN_FILE", "")
	token, err := loadOptionalToken("ANTIFLOCK_AGENT_TOKEN", "ANTIFLOCK_AGENT_TOKEN_FILE")
	if err != nil || token != "" { t.Fatalf("token=%q err=%v", token, err) }
}
