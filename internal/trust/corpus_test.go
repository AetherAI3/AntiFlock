package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const corpusRoot = "testdata/hostile"

type manifest struct {
	Version     int             `json:"version"`
	Description string          `json:"description"`
	Entries     []manifestEntry `json:"entries"`
}

type manifestEntry struct {
	ID                 string         `json:"id"`
	File               string         `json:"file"`
	Origin             string         `json:"origin"`
	Authenticity       string         `json:"authenticity"`
	Render             []renderCheck  `json:"render"`
	Bounded            []boundedCheck `json:"bounded"`
	Receipt            *receiptCheck  `json:"receipt"`
	SafeLabel          *string        `json:"safe_label"`
	InstructionMatches *[]string      `json:"instruction_matches"`
}

type renderCheck struct {
	Policy          string   `json:"policy"`
	Field           string   `json:"field"`
	ExpectTaint     []string `json:"expect_taint"`
	ExpectFindings  []string `json:"expect_findings"`
	ExpectText      *string  `json:"expect_text"`
	ExpectTruncated bool     `json:"expect_truncated"`
}

type boundedCheck struct {
	Limits      *manifestLimits `json:"limits"`
	ExpectTaint []string        `json:"expect_taint"`
	ExpectError string          `json:"expect_error"`
}

type manifestLimits struct {
	MaxBytes       int `json:"max_bytes"`
	MaxDepth       int `json:"max_depth"`
	MaxTokens      int `json:"max_tokens"`
	MaxStringBytes int `json:"max_string_bytes"`
	MaxNumberBytes int `json:"max_number_bytes"`
}

type receiptCheck struct {
	Now    string     `json:"now"`
	Expect [][]string `json:"expect"`
}

type receiptFile struct {
	Receipts []struct {
		Digest    string `json:"digest"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	} `json:"receipts"`
}

var boundedErrors = map[string]error{
	"":          nil,
	"oversized": ErrJSONOversized,
	"depth":     ErrJSONDepth,
	"tokens":    ErrJSONTokens,
	"string":    ErrJSONStringLength,
	"number":    ErrJSONNumberLength,
	"duplicate": ErrJSONDuplicateKey,
	"trailing":  ErrJSONTrailing,
	"malformed": ErrJSONMalformed,
	"empty":     ErrJSONEmpty,
}

func loadManifest(t testing.TB) manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusRoot, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var parsed manifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if parsed.Version != 1 || len(parsed.Entries) == 0 {
		t.Fatalf("manifest version %d with %d entries", parsed.Version, len(parsed.Entries))
	}
	return parsed
}

func policyByName(t testing.TB, name string) RenderPolicy {
	t.Helper()
	switch name {
	case "utf8":
		return DefaultPolicy()
	case "ascii":
		return ASCIIPolicy()
	case "strip":
		return RenderPolicy{Mode: RenderStrip, MaxBytes: DefaultMaxBytes}
	}
	t.Fatalf("unknown policy %q", name)
	return RenderPolicy{}
}

func mustTaints(t testing.TB, names []string) Taint {
	t.Helper()
	set, err := ParseTaints(names)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func fieldOf(t testing.TB, raw []byte, field string) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode fixture for field %q: %v", field, err)
	}
	value, ok := document[field].(string)
	if !ok {
		t.Fatalf("fixture field %q is not a string", field)
	}
	return value
}

// assertSafeBytes is the output invariant every rendering must satisfy.
func assertSafeBytes(t testing.TB, text string, asciiOnly bool) {
	t.Helper()
	for index := 0; index < len(text); index++ {
		b := text[index]
		switch {
		case b < 0x20 && b != '\n':
			t.Fatalf("rendered text contains control byte 0x%02x at %d: %q", b, index, text)
		case b == 0x7f:
			t.Fatalf("rendered text contains DEL at %d: %q", index, text)
		case asciiOnly && b >= 0x80:
			t.Fatalf("ascii rendering contains byte 0x%02x at %d: %q", b, index, text)
		}
	}
}

func assertIdempotent(t testing.TB, text string, policy RenderPolicy) {
	t.Helper()
	again, err := Render(text, policy)
	if err != nil {
		t.Fatal(err)
	}
	if again.Text != text {
		t.Fatalf("Render is not idempotent:\n first=%q\nsecond=%q", text, again.Text)
	}
	if again.Taints != 0 {
		t.Fatalf("re-rendering safe text reported taint %s", again.Taints)
	}
}

func TestCorpusManifestCoversEveryFixture(t *testing.T) {
	t.Parallel()
	parsed := loadManifest(t)
	referenced := map[string]bool{}
	for _, entry := range parsed.Entries {
		referenced[filepath.ToSlash(entry.File)] = true
	}
	err := filepath.WalkDir(corpusRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(corpusRoot, path)
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" || rel == ".gitattributes" {
			return nil
		}
		if !referenced[rel] {
			t.Errorf("fixture %s is not referenced by manifest.json", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file := range referenced {
		if _, err := os.Stat(filepath.Join(corpusRoot, filepath.FromSlash(file))); err != nil {
			t.Errorf("manifest references missing fixture %s", file)
		}
	}
}

func TestCorpus(t *testing.T) {
	t.Parallel()
	parsed := loadManifest(t)
	seenIDs := map[string]bool{}
	for _, entry := range parsed.Entries {
		entry := entry
		if seenIDs[entry.ID] {
			t.Fatalf("duplicate manifest id %q", entry.ID)
		}
		seenIDs[entry.ID] = true
		t.Run(entry.ID, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(corpusRoot, filepath.FromSlash(entry.File)))
			if err != nil {
				t.Fatal(err)
			}
			origin, ok := ParseOrigin(entry.Origin)
			if !ok {
				t.Fatalf("unknown origin %q", entry.Origin)
			}
			authenticity, ok := ParseAuthenticity(entry.Authenticity)
			if !ok {
				t.Fatalf("unknown authenticity %q", entry.Authenticity)
			}
			for index, check := range entry.Render {
				runRenderCheck(t, index, raw, origin, authenticity, check)
			}
			for index, check := range entry.Bounded {
				runBoundedCheck(t, index, raw, check)
			}
			if entry.Receipt != nil {
				runReceiptCheck(t, raw, *entry.Receipt)
			}
			if entry.SafeLabel != nil {
				if got := SafeLabel(string(raw), 0); got != *entry.SafeLabel {
					t.Errorf("SafeLabel = %q, want %q", got, *entry.SafeLabel)
				}
				if !IsSafeLabel(SafeLabel(string(raw), 0)) {
					t.Errorf("SafeLabel output is not itself a safe label")
				}
			}
			if entry.InstructionMatches != nil {
				hit, matches := LooksInstructionLike(string(raw))
				want := *entry.InstructionMatches
				if hit != (len(want) != 0) {
					t.Errorf("LooksInstructionLike hit = %v, want %v", hit, len(want) != 0)
				}
				if len(matches) == 0 {
					matches = nil
				}
				if len(want) == 0 {
					want = nil
				}
				if !reflect.DeepEqual(matches, want) {
					t.Errorf("LooksInstructionLike matches = %q, want %q", matches, want)
				}
			}
		})
	}
}

func runRenderCheck(t *testing.T, index int, raw []byte, origin Origin, authenticity Authenticity, check renderCheck) {
	t.Helper()
	input := string(raw)
	if check.Field != "" {
		input = fieldOf(t, raw, check.Field)
	}
	policy := policyByName(t, check.Policy)
	env := Wrap(origin, authenticity, input, WrapOptions{Policy: &policy})
	want := mustTaints(t, check.ExpectTaint)
	if env.Taint != want {
		t.Errorf("render[%d] %s: taint = %s, want %s", index, check.Policy, env.Taint, want)
	}
	gotKinds := env.Payload.Rendered.FindingKinds()
	wantKinds := check.ExpectFindings
	if len(gotKinds) == 0 {
		gotKinds = nil
	}
	if len(wantKinds) == 0 {
		wantKinds = nil
	}
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Errorf("render[%d] %s: findings = %v, want %v", index, check.Policy, gotKinds, wantKinds)
	}
	if check.ExpectText != nil && env.Text() != *check.ExpectText {
		t.Errorf("render[%d] %s: text = %q, want %q", index, check.Policy, env.Text(), *check.ExpectText)
	}
	if check.ExpectTruncated {
		rendered := env.Payload.Rendered
		marker := "[truncated " + strconv.Itoa(rendered.DroppedBytes) + " bytes]"
		if !strings.HasSuffix(env.Text(), marker) {
			t.Errorf("render[%d] %s: truncated text lacks marker %q: %q", index, check.Policy, marker, tail(env.Text()))
		}
		if rendered.DroppedBytes <= 0 {
			t.Errorf("render[%d] %s: DroppedBytes = %d", index, check.Policy, rendered.DroppedBytes)
		}
		if len(env.Text()) > DefaultMaxBytes {
			t.Errorf("render[%d] %s: text is %d bytes, cap %d", index, check.Policy, len(env.Text()), DefaultMaxBytes)
		}
	} else if env.Payload.Rendered.DroppedBytes != 0 {
		t.Errorf("render[%d] %s: unexpected truncation of %d bytes", index, check.Policy, env.Payload.Rendered.DroppedBytes)
	}
	assertSafeBytes(t, env.Text(), policy.ASCIIOnly)
	assertIdempotent(t, env.Text(), policy)

	sum := sha256.Sum256([]byte(input))
	if env.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("render[%d]: digest mismatch %s", index, env.Digest)
	}
	if env.ControlClass != DataOnly || env.ControlClass.GrantsCapability() {
		t.Errorf("render[%d]: envelope claims control authority", index)
	}
	if !env.Taint.Has(TaintUntrusted) {
		t.Errorf("render[%d]: envelope is missing TaintUntrusted", index)
	}

	// A signature never launders taint.
	signed := env.WithAuthenticity(SignatureValid)
	if signed.Taint != env.Taint {
		t.Errorf("render[%d]: SIGNATURE_VALID changed taint from %s to %s", index, env.Taint, signed.Taint)
	}
	if signed.ControlClass.GrantsCapability() || signed.Authenticity != SignatureValid {
		t.Errorf("render[%d]: WithAuthenticity did not behave", index)
	}
	if signed.Text() != env.Text() || signed.Digest != env.Digest {
		t.Errorf("render[%d]: WithAuthenticity altered payload", index)
	}

	// Structured output carries the rendering, never the raw bytes.
	encoded, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var summary Summary
	if err := json.Unmarshal(encoded, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Text != env.Text() || summary.RawBytes != len(input) {
		t.Errorf("render[%d]: summary text/raw mismatch", index)
	}
	assertSafeBytes(t, summary.Text, policy.ASCIIOnly)
	if env.Payload.Rendered.Taints&(TaintContainsControlChars|TaintContainsBidi) != 0 && strings.Contains(string(encoded), input) {
		t.Errorf("render[%d]: JSON output contains the raw hostile input", index)
	}
}

func tail(text string) string {
	if len(text) > 80 {
		return "..." + text[len(text)-80:]
	}
	return text
}

func runBoundedCheck(t *testing.T, index int, raw []byte, check boundedCheck) {
	t.Helper()
	var limits Limits
	if check.Limits != nil {
		limits = Limits{
			MaxBytes:       check.Limits.MaxBytes,
			MaxDepth:       check.Limits.MaxDepth,
			MaxTokens:      check.Limits.MaxTokens,
			MaxStringBytes: check.Limits.MaxStringBytes,
			MaxNumberBytes: check.Limits.MaxNumberBytes,
		}
	}
	taint, err := BoundedJSON(raw, limits)
	want := mustTaints(t, check.ExpectTaint)
	if taint != want {
		t.Errorf("bounded[%d]: taint = %s, want %s (err=%v)", index, taint, want, err)
	}
	wantErr, known := boundedErrors[check.ExpectError]
	if !known {
		t.Fatalf("bounded[%d]: unknown expect_error %q", index, check.ExpectError)
	}
	switch {
	case wantErr == nil && err != nil:
		t.Errorf("bounded[%d]: unexpected error %v", index, err)
	case wantErr != nil && !errors.Is(err, wantErr):
		t.Errorf("bounded[%d]: error = %v, want %v", index, err, wantErr)
	}
	if err != nil {
		var typed *JSONError
		if !errors.As(err, &typed) {
			t.Errorf("bounded[%d]: error is not a *JSONError: %T", index, err)
		} else {
			assertSafeBytes(t, typed.Error(), true)
		}
	}
}

func runReceiptCheck(t *testing.T, raw []byte, check receiptCheck) {
	t.Helper()
	var file receiptFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, check.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Receipts) != len(check.Expect) {
		t.Fatalf("receipt: %d receipts but %d expectations", len(file.Receipts), len(check.Expect))
	}
	seen := NewSeenSet(16)
	for index, receipt := range file.Receipts {
		issued, err := time.Parse(time.RFC3339, receipt.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		got := CheckReceipt(receipt.Digest, issued, expires, now, seen)
		want := mustTaints(t, check.Expect[index])
		if got != want {
			t.Errorf("receipt[%d]: taint = %s, want %s", index, got, want)
		}
	}
}
