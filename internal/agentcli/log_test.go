package agentcli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactMasksKnownSecretShapes(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, mustNotContain, mustContain string }{
		{"Authorization: Bearer abc.def-ghi", "abc.def-ghi", "Authorization: [REDACTED]"},
		{"authorization=Basic dXNlcjpwdw==", "dXNlcjpwdw==", "authorization=[REDACTED]"},
		{"sent bearer 0123456789abcdefXYZ", "0123456789abcdefXYZ", "bearer [REDACTED]"},
		{`{"token": "sekrit-value"}`, "sekrit-value", `"token": "[REDACTED]`},
		{"api_key=AKIA1234", "AKIA1234", "api_key=[REDACTED]"},
		{"password: hunter2", "hunter2", "password: [REDACTED]"},
		{"seed=deadbeef", "deadbeef", "seed=[REDACTED]"},
		{"leak ghp_0123456789abcdefghijklmnop end", "ghp_0123456789abcdefghijklmnop", "leak [REDACTED] end"},
		{pemFixture("", "MC4CAQAwBQYDK2VwBCIEIAAA"), "MC4CAQAw", "[REDACTED]"},
		{pemFixture("ED25519 ", "abc"), "abc", "[REDACTED]"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if strings.Contains(out, c.mustNotContain) || !strings.Contains(out, c.mustContain) {
			t.Errorf("Redact(%q) = %q", c.in, out)
		}
	}
}

func TestRedactKeepsChecksumsPathsAndKeyNames(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`"runningSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`,
		`"keyPath": "/var/lib/antiflock/node.seed"`,
		`"enrollmentTokenFile": "/run/secrets/token"`,
		"AF-DOCTOR-KEY-PRIVATE: node key present",
		"antiflock-agent_0.2.0_linux_amd64",
	} {
		if out := Redact(in); out != in {
			t.Errorf("Redact changed benign text %q -> %q", in, out)
		}
	}
}

func TestRedactingWriterMasksAcrossSplitWritesAndFlush(t *testing.T) {
	t.Parallel()
	var sink bytes.Buffer
	writer := NewRedactingWriter(&sink)
	for _, chunk := range []string{"Authoriz", "ation: Bearer sp", "lit-token\nplain line\n", "trailing password=abc"} {
		if _, err := writer.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(sink.String(), "trailing") {
		t.Fatalf("partial line flushed early: %q", sink.String())
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	out := sink.String()
	if strings.Contains(out, "sp") && strings.Contains(out, "lit-token") || strings.Contains(out, "abc") {
		t.Fatalf("secret leaked: %q", out)
	}
	if !strings.Contains(out, "plain line\n") || !strings.Contains(out, "Authorization: [REDACTED]") || !strings.Contains(out, "password=[REDACTED]") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestRedactingWriterBuffersPEMUntilClosed(t *testing.T) {
	t.Parallel()
	var sink bytes.Buffer
	writer := NewRedactingWriter(&sink)
	_, _ = writer.Write([]byte(pemBegin + " " + pemKeyMarker + "\nline1\n"))
	if sink.Len() != 0 {
		t.Fatalf("open PEM block flushed early: %q", sink.String())
	}
	_, _ = writer.Write([]byte("line2\n" + pemEnd + " " + pemKeyMarker + "\n"))
	if strings.Contains(sink.String(), "line1") || strings.Contains(sink.String(), "line2") {
		t.Fatalf("PEM body leaked: %q", sink.String())
	}
	if NewRedactingWriter(nil) == nil {
		t.Fatal("nil target must be tolerated")
	}
}

// pemFixture assembles a private-key armor block at runtime; the literal
// form must never appear in the source tree.
func pemFixture(label, body string) string {
	return pemBegin + " " + label + pemKeyMarker + "\n" + body + "\n" + pemEnd + " " + label + pemKeyMarker
}
