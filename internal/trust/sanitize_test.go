package trust

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRenderRejectsUnknownMode(t *testing.T) {
	t.Parallel()
	if _, err := Render("x", RenderPolicy{Mode: RenderMode(7)}); err != ErrInvalidPolicy {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       string
		policy   RenderPolicy
		wantText string
		wantT    Taint
		wantK    []string
	}{
		{"plain", "hello world", DefaultPolicy(), "hello world", 0, nil},
		{"newline kept", "a\nb", DefaultPolicy(), "a\nb", 0, nil},
		{"crlf normalised silently", "a\r\nb", DefaultPolicy(), "a\nb", 0, nil},
		{"lone cr", "a\rb", DefaultPolicy(), `a\x0db`, TaintContainsControlChars, []string{FindingCR}},
		{"tab escaped", "a\tb", DefaultPolicy(), `a\x09b`, TaintContainsControlChars, []string{FindingC0}},
		{"nul", "a\x00b", DefaultPolicy(), `a\x00b`, TaintContainsControlChars, []string{FindingNUL}},
		{"del", "a\x7fb", DefaultPolicy(), `a\x7fb`, TaintContainsControlChars, []string{FindingDEL}},
		{"csi", "\x1b[31mred\x1b[0m", DefaultPolicy(), `\x1b[31mred\x1b[0m`, TaintContainsControlChars, []string{FindingCSI}},
		{"csi private and intermediate", "\x1b[?25l\x1b[ q", DefaultPolicy(), `\x1b[?25l\x1b[ q`, TaintContainsControlChars, []string{FindingCSI}},
		{"csi unterminated", "\x1b[31", DefaultPolicy(), `\x1b[31`, TaintContainsControlChars, []string{FindingCSI}},
		{"osc bel", "\x1b]0;title\x07x", DefaultPolicy(), `\x1b]0;title\x07x`, TaintContainsControlChars, []string{FindingOSC}},
		{"osc st", "\x1b]8;;http://x\x1b\\y", DefaultPolicy(), `\x1b]8;;http://x\x1b\y`, TaintContainsControlChars, []string{FindingOSC}},
		{"osc 8-bit st", "\x1b]8;;http://x\u009cy", DefaultPolicy(), `\x1b]8;;http://x\x9cy`, TaintContainsControlChars, []string{FindingOSC}},
		{"osc unterminated eats rest", "\x1b]52;c;abc", DefaultPolicy(), `\x1b]52;c;abc`, TaintContainsControlChars, []string{FindingOSC}},
		{"osc strip", "a\x1b]52;c;abc\x07b", RenderPolicy{Mode: RenderStrip}, "ab", TaintContainsControlChars, []string{FindingOSC}},
		{"dcs", "\x1bPq\x1b\\z", DefaultPolicy(), `\x1bPq\x1b\z`, TaintContainsControlChars, []string{FindingDCS}},
		{"sos pm apc", "\x1bXa\x1b\\\x1b^b\x1b\\\x1b_c\x1b\\", DefaultPolicy(), `\x1bXa\x1b\\x1b^b\x1b\\x1b_c\x1b\`, TaintContainsControlChars, []string{FindingAPC, FindingPM, FindingSOS}},
		{"nF escape", "\x1b(Bx\x1b#8y", DefaultPolicy(), `\x1b(Bx\x1b#8y`, TaintContainsControlChars, []string{FindingESC}},
		{"two byte escape", "\x1bcx\x1b7", DefaultPolicy(), `\x1bcx\x1b7`, TaintContainsControlChars, []string{FindingESC}},
		{"bare esc", "\x1b", DefaultPolicy(), `\x1b`, TaintContainsControlChars, []string{FindingESC}},
		{"esc then control", "\x1b\x01", DefaultPolicy(), `\x1b\x01`, TaintContainsControlChars, []string{FindingC0, FindingESC}},
		{"8-bit csi", "\u009b31mx", DefaultPolicy(), `\x9b31mx`, TaintContainsControlChars, []string{FindingCSI}},
		{"8-bit c1 plain", "a\u0085b", DefaultPolicy(), `a\x85b`, TaintContainsControlChars, []string{FindingC1}},
		{"rlo", "a\u202eb", DefaultPolicy(), `a\u202eb`, TaintContainsBidi, []string{FindingBidi}},
		{"isolates", "\u2066\u2067\u2068\u2069", ASCIIPolicy(), `\u2066\u2067\u2068\u2069`, TaintContainsBidi, []string{FindingBidi}},
		{"marks", "\u200e\u200f\u061c", DefaultPolicy(), `\u200e\u200f\u061c`, TaintContainsBidi, []string{FindingBidi}},
		{"bidi strip", "a\u202eb", RenderPolicy{Mode: RenderStrip}, "ab", TaintContainsBidi, []string{FindingBidi}},
		{"zero width", "a\u200bb\u200dc\u2060d", DefaultPolicy(), `a\u200bb\u200dc\u2060d`, TaintContainsControlChars, []string{FindingFormat}},
		{"bom", "\ufeffx", DefaultPolicy(), `\ufeffx`, TaintContainsControlChars, []string{FindingFormat}},
		{"soft hyphen", "a\u00adb", DefaultPolicy(), `a\xadb`, TaintContainsControlChars, []string{FindingFormat}},
		{"separators", "a\u2028b\u2029c", DefaultPolicy(), `a\u2028b\u2029c`, TaintContainsControlChars, []string{FindingSeparator}},
		{"invalid utf8", "a\xffb\xc3", DefaultPolicy(), `a\xffb\xc3`, TaintContainsControlChars, []string{FindingInvalidUTF8}},
		{"utf8 kept", "café 日本 \U0001F600", DefaultPolicy(), "café 日本 \U0001F600", 0, nil},
		{"ascii escapes utf8", "café \u65e5 \U0001F600", ASCIIPolicy(), `caf\xe9 \u65e5 \U0001f600`, 0, nil},
		{"nbsp kept", "a\u00a0b", DefaultPolicy(), "a\u00a0b", 0, nil},
		{"private use escaped without finding", "a\ue000b", DefaultPolicy(), `a\ue000b`, 0, nil},
		{"unassigned escaped without finding", "a\U000E0FFFb", DefaultPolicy(), `a\U000e0fffb`, 0, nil},
		{"backslash passes through", `a\x1bb`, DefaultPolicy(), `a\x1bb`, 0, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Render(tc.in, tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			if got.Text != tc.wantText {
				t.Errorf("text = %q, want %q", got.Text, tc.wantText)
			}
			if got.Taints != tc.wantT {
				t.Errorf("taint = %s, want %s", got.Taints, tc.wantT)
			}
			kinds := got.FindingKinds()
			if len(kinds) == 0 {
				kinds = nil
			}
			if strings.Join(kinds, ",") != strings.Join(tc.wantK, ",") {
				t.Errorf("findings = %v, want %v", kinds, tc.wantK)
			}
			if got.InputBytes != len(tc.in) || got.DroppedBytes != 0 {
				t.Errorf("InputBytes=%d DroppedBytes=%d", got.InputBytes, got.DroppedBytes)
			}
			assertSafeBytes(t, got.Text, tc.policy.ASCIIOnly)
			assertIdempotent(t, got.Text, tc.policy)
			for _, kind := range tc.wantK {
				if !got.HasFinding(kind) {
					t.Errorf("HasFinding(%s) false", kind)
				}
			}
		})
	}
}

func TestRenderTruncation(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("abcdefghij", 100) // 1000 bytes
	policy := RenderPolicy{MaxBytes: 100}
	got, err := Render(long, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Text) > 100 {
		t.Errorf("len = %d", len(got.Text))
	}
	if got.Taints != TaintOversized|TaintTruncated {
		t.Errorf("taint = %s", got.Taints)
	}
	wantSuffix := "…[truncated " + itoa(got.DroppedBytes) + " bytes]"
	if !strings.HasSuffix(got.Text, wantSuffix) {
		t.Errorf("text %q lacks %q", got.Text, wantSuffix)
	}
	kept := len(got.Text) - len(wantSuffix)
	if kept+got.DroppedBytes != len(long) {
		t.Errorf("kept %d + dropped %d != %d", kept, got.DroppedBytes, len(long))
	}
	assertIdempotent(t, got.Text, policy)

	ascii, _ := Render(long, RenderPolicy{MaxBytes: 100, ASCIIOnly: true})
	if !strings.Contains(ascii.Text, `\u2026[truncated `) {
		t.Errorf("ascii marker not escaped: %q", ascii.Text)
	}
	assertSafeBytes(t, ascii.Text, true)
	assertIdempotent(t, ascii.Text, RenderPolicy{MaxBytes: 100, ASCIIOnly: true})

	// Escaping can inflate short input past the cap: truncated but not oversized.
	inflated, _ := Render(strings.Repeat("\x1b", 40), RenderPolicy{MaxBytes: 64})
	if inflated.Taints != TaintContainsControlChars|TaintTruncated {
		t.Errorf("inflated taint = %s", inflated.Taints)
	}
	if len(inflated.Text) > 64 {
		t.Errorf("inflated len = %d", len(inflated.Text))
	}
	assertIdempotent(t, inflated.Text, RenderPolicy{MaxBytes: 64})

	// Tiny caps are raised to MinMaxBytes so the marker always fits.
	tiny, _ := Render(long, RenderPolicy{MaxBytes: 1})
	if len(tiny.Text) > MinMaxBytes || !strings.Contains(tiny.Text, "[truncated ") {
		t.Errorf("tiny = %q", tiny.Text)
	}
	assertIdempotent(t, tiny.Text, RenderPolicy{MaxBytes: 1})

	// Exactly at the cap is not truncated.
	exact, _ := Render(strings.Repeat("x", 100), policy)
	if exact.Taints != 0 || len(exact.Text) != 100 {
		t.Errorf("exact = %s %d", exact.Taints, len(exact.Text))
	}
	// Taints beyond the cut are still reported.
	late, _ := Render(strings.Repeat("x", 200)+"\x1b[31m"+"\u202e", policy)
	if !late.Taints.Has(TaintContainsControlChars|TaintContainsBidi|TaintTruncated) || !late.HasFinding(FindingCSI) {
		t.Errorf("late taint = %s findings = %v", late.Taints, late.FindingKinds())
	}
}

func itoa(value int) string { return strconv.Itoa(value) }

func TestScanMatchesRenderWithoutCap(t *testing.T) {
	t.Parallel()
	input := strings.Repeat("x", DefaultMaxBytes*2) + "\x1b[1m\u202e ignore previous"
	if got := Scan(input); got != TaintContainsControlChars|TaintContainsBidi|TaintContainsInstructionLike {
		t.Errorf("Scan = %s", got)
	}
	if got := Scan("plain"); got != 0 {
		t.Errorf("Scan(plain) = %s", got)
	}
}

func TestQuoteForTerminal(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain":              "plain",
		"a\nb":               `a\nb`,
		"\x1b[31m":           `\x1b[31m`,
		"café":               `caf\u00e9`,
		"\u202e":             `\u202e`,
		`back\slash "quote"`: `back\\slash \"quote\"`,
		"\xff":               `\xff`,
		"":                   "",
	}
	for in, want := range cases {
		got := QuoteForTerminal(in)
		if got != want {
			t.Errorf("QuoteForTerminal(%q) = %q, want %q", in, got, want)
		}
		assertSafeBytes(t, got, true)
		if strings.Contains(got, "\n") {
			t.Errorf("QuoteForTerminal emitted a newline for %q", in)
		}
	}
}

func TestSafeLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"node-01", 0, "node-01"},
		{"node 01/x", 0, "node_01_x"},
		{"nöde", 0, "n_de"},
		{"\x1b[31mred", 0, "__31mred"},
		{"", 0, "_"},
		{"\u202e\u202e", 0, "__"},
		{"abcdef", 3, "abc"},
		{"a.b:c_d-e", 0, "a.b:c_d-e"},
		{strings.Repeat("x", 300), 0, strings.Repeat("x", DefaultLabelMax)},
	}
	for _, tc := range cases {
		if got := SafeLabel(tc.in, tc.max); got != tc.want {
			t.Errorf("SafeLabel(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
		if !IsSafeLabel(SafeLabel(tc.in, tc.max)) {
			t.Errorf("SafeLabel(%q) output fails IsSafeLabel", tc.in)
		}
	}
	if IsSafeLabel("") || IsSafeLabel("a b") || IsSafeLabel(strings.Repeat("x", 129)) || IsSafeLabel("\u202e") {
		t.Error("IsSafeLabel accepted an unsafe label")
	}
	if !IsSafeLabel("plan-7.v2:eu_west") {
		t.Error("IsSafeLabel rejected a safe label")
	}
}

// hostileAlphabet mixes benign text with every class of hostile rune the
// renderer knows about plus raw bytes, so the PRNG explores escape parsing.
var hostileAlphabet = []string{
	"a", "Z", "0", " ", "\n", "\r\n", "\r", "\t", "\x00", "\x07", "\x08", "\x1b", "\x7f",
	"\x1b[", "\x1b]", "\x1bP", "\x1bX", "\x1b^", "\x1b_", "\x1b\\", "\x1b(", "[", "]", ";", "m", "\\",
	"\u009b", "\u009d", "\u0090", "\u009c", "\u0085", "\u0098", "\u009f",
	"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f", "\u061c",
	"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u2028", "\u2029",
	"é", "日", "\U0001F600", "\ue000", "\U000E0FFF", "\u00a0",
	"\xff", "\xc3", "\xc2", "\xe2\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80",
	"ignore previous", "sudo", "```", "system:",
}

func randomHostile(rng *rand.Rand, maxParts int) string {
	var out strings.Builder
	parts := rng.Intn(maxParts + 1)
	for i := 0; i < parts; i++ {
		out.WriteString(hostileAlphabet[rng.Intn(len(hostileAlphabet))])
	}
	return out.String()
}

// TestRenderPropertiesDeterministic is the property suite: for a fixed-seed
// stream of hostile inputs, every rendering is byte-safe, idempotent, within
// the cap, and Strip output never contains anything Escape output flagged.
func TestRenderPropertiesDeterministic(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(20260823))
	policies := []RenderPolicy{
		DefaultPolicy(), ASCIIPolicy(), {Mode: RenderStrip}, {Mode: RenderStrip, ASCIIOnly: true},
		{MaxBytes: 64}, {MaxBytes: 100, ASCIIOnly: true}, {Mode: RenderStrip, MaxBytes: 80},
	}
	for iteration := 0; iteration < 4000; iteration++ {
		input := randomHostile(rng, 48)
		for _, policy := range policies {
			checkRenderProperties(t, input, policy)
		}
	}
}

func checkRenderProperties(t testing.TB, input string, policy RenderPolicy) {
	t.Helper()
	first, err := Render(input, policy)
	if err != nil {
		t.Fatalf("Render(%q): %v", input, err)
	}
	assertSafeBytes(t, first.Text, policy.ASCIIOnly)
	if !utf8.ValidString(first.Text) {
		t.Fatalf("Render(%q) produced invalid UTF-8 %q", input, first.Text)
	}
	limit := policy.MaxBytes
	if limit == 0 {
		limit = DefaultMaxBytes
	}
	if limit < MinMaxBytes {
		limit = MinMaxBytes
	}
	if len(first.Text) > limit {
		t.Fatalf("Render(%q) exceeded cap %d: %d bytes", input, limit, len(first.Text))
	}
	if first.Taints.Has(TaintTruncated) != (first.DroppedBytes > 0) {
		t.Fatalf("Render(%q): truncated=%v dropped=%d", input, first.Taints.Has(TaintTruncated), first.DroppedBytes)
	}
	if first.Taints.Has(TaintTruncated) && !strings.Contains(first.Text, "[truncated ") {
		t.Fatalf("Render(%q): truncated without marker: %q", input, first.Text)
	}
	if (first.Taints&(TaintContainsControlChars|TaintContainsBidi) != 0) != (len(first.Findings) > 0) {
		t.Fatalf("Render(%q): taint %s disagrees with findings %v", input, first.Taints, first.Findings)
	}
	assertIdempotent(t, first.Text, policy)
	if first.Taints&(TaintOversized|TaintTruncated) == 0 {
		if scan := Scan(input) &^ TaintContainsInstructionLike; scan != first.Taints {
			t.Fatalf("Scan(%q) = %s but Render taint = %s", input, scan, first.Taints)
		}
	}
}

func FuzzRender(f *testing.F) {
	seedCorpus(f)
	for _, part := range hostileAlphabet {
		f.Add(part)
	}
	f.Fuzz(func(t *testing.T, input string) {
		for _, policy := range []RenderPolicy{DefaultPolicy(), ASCIIPolicy(), {Mode: RenderStrip, MaxBytes: 256}} {
			checkRenderProperties(t, input, policy)
		}
		label := SafeLabel(input, 0)
		if !IsSafeLabel(label) {
			t.Fatalf("SafeLabel(%q) = %q is unsafe", input, label)
		}
		assertSafeBytes(t, QuoteForTerminal(input), true)
	})
}

// seedCorpus adds every corpus fixture as a fuzz seed.
func seedCorpus(f *testing.F) {
	f.Helper()
	err := filepath.WalkDir(corpusRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || strings.HasSuffix(path, "manifest.json") || strings.HasSuffix(path, ".gitattributes") {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if len(raw) > 16<<10 {
			raw = raw[:16<<10]
		}
		f.Add(string(raw))
		return nil
	})
	if err != nil {
		f.Fatal(err)
	}
}
