package trust

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RenderMode selects what happens to hostile runes and sequences.
type RenderMode uint8

// RenderMode values.
const (
	// RenderEscape replaces each hostile byte or rune with a printable ASCII
	// escape such as \x1b or \u202e. Whole terminal sequences are escaped
	// byte by byte so an operator can see exactly what was sent.
	RenderEscape RenderMode = iota
	// RenderStrip drops hostile runes and whole terminal sequences.
	RenderStrip
)

// DefaultMaxBytes is the rendering cap used when RenderPolicy.MaxBytes is 0.
const DefaultMaxBytes = 4096

// MinMaxBytes is the smallest cap Render honours; smaller values are raised
// so the truncation marker always fits and rendering stays idempotent.
const MinMaxBytes = 64

// markerReserve is the output space held back for the truncation marker.
const markerReserve = 48

// maxSequenceBytes bounds how far an OSC/DCS/SOS/PM/APC body may extend
// before the rest of the input is rendered normally again.
const maxSequenceBytes = 1024

// RenderPolicy configures Render. The zero value is a safe policy:
// escape mode, UTF-8 output, DefaultMaxBytes cap.
type RenderPolicy struct {
	Mode RenderMode
	// ASCIIOnly escapes every rune at or above U+0080 so the output is pure
	// printable ASCII plus newline.
	ASCIIOnly bool
	// MaxBytes caps len(Rendered.Text), marker included. 0 means
	// DefaultMaxBytes; values below MinMaxBytes are raised to it.
	MaxBytes int
}

// DefaultPolicy returns the UTF-8 escape policy.
func DefaultPolicy() RenderPolicy { return RenderPolicy{Mode: RenderEscape, MaxBytes: DefaultMaxBytes} }

// ASCIIPolicy returns the ASCII-only escape policy.
func ASCIIPolicy() RenderPolicy {
	return RenderPolicy{Mode: RenderEscape, ASCIIOnly: true, MaxBytes: DefaultMaxBytes}
}

// ErrInvalidPolicy is returned for an unknown RenderMode.
var ErrInvalidPolicy = errors.New("trust: invalid render policy")

// Finding kinds reported in Rendered.Findings.
const (
	FindingNUL         = "NUL"          // U+0000
	FindingC0          = "C0"           // other U+0001..U+001F except \n and CRLF
	FindingCR          = "CR"           // lone carriage return
	FindingDEL         = "DEL"          // U+007F
	FindingESC         = "ESC"          // bare or two/three byte escape
	FindingCSI         = "CSI"          // ESC [ ... or U+009B ...
	FindingOSC         = "OSC"          // ESC ] ... ST/BEL or U+009D ... (OSC 8, OSC 52, ...)
	FindingDCS         = "DCS"          // ESC P ... ST or U+0090 ...
	FindingSOS         = "SOS"          // ESC X ... ST or U+0098 ...
	FindingPM          = "PM"           // ESC ^ ... ST or U+009E ...
	FindingAPC         = "APC"          // ESC _ ... ST or U+009F ...
	FindingC1          = "C1"           // other U+0080..U+009F
	FindingBidi        = "BIDI"         // U+202A..U+202E, U+2066..U+2069, U+200E, U+200F, U+061C
	FindingFormat      = "FORMAT"       // other Cf runes: zero-width, joiners, BOM, soft hyphen, ...
	FindingSeparator   = "SEPARATOR"    // U+2028, U+2029
	FindingInvalidUTF8 = "INVALID_UTF8" // byte that is not part of a valid encoding
)

// Finding counts one kind of hostile shape.
type Finding struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// Rendered is the result of Render.
type Rendered struct {
	// Text is safe for terminals and JSON: no byte below 0x20 except '\n',
	// no 0x7f, and no byte at or above 0x80 under an ASCII policy.
	Text string
	// Taints reports what was found or done (control, bidi, oversized,
	// truncated). It never includes TaintUntrusted; Wrap adds that.
	Taints Taint
	// Findings lists the kinds found, sorted by Kind.
	Findings []Finding
	// InputBytes is len(raw).
	InputBytes int
	// DroppedBytes is how many input bytes were not rendered because of the
	// cap; it is the N in the truncation marker.
	DroppedBytes int
}

// HasFinding reports whether a kind was seen.
func (r Rendered) HasFinding(kind string) bool {
	for _, finding := range r.Findings {
		if finding.Kind == kind {
			return true
		}
	}
	return false
}

// FindingKinds returns the sorted kinds.
func (r Rendered) FindingKinds() []string {
	kinds := make([]string, len(r.Findings))
	for index, finding := range r.Findings {
		kinds[index] = finding.Kind
	}
	return kinds
}

// Render produces a terminal- and JSON-safe rendering of raw.
//
// Rules: CRLF becomes LF; a lone CR, NUL, other C0 controls, DEL, C1
// controls, bidi controls, zero-width and other format runes, line and
// paragraph separators, BOM, and invalid UTF-8 bytes are escaped (or stripped
// under RenderStrip). ESC/CSI/OSC/DCS/SOS/PM/APC sequences in 7-bit and
// 8-bit form are recognised as units, so an OSC 8 hyperlink or OSC 52
// clipboard write is escaped or stripped whole. Runes that are not printable
// (unassigned, surrogates, private use, non-ASCII spaces are kept) are
// escaped without a finding. Output is capped at MaxBytes including an
// escaped marker of the form "…[truncated N bytes]".
//
// Render is idempotent: Render(Render(x).Text) yields the same Text with no
// taints, because every emitted byte is in the pass-through set.
func Render(raw string, policy RenderPolicy) (Rendered, error) {
	if policy.Mode != RenderEscape && policy.Mode != RenderStrip {
		return Rendered{}, ErrInvalidPolicy
	}
	limit := policy.MaxBytes
	if limit == 0 {
		limit = DefaultMaxBytes
	}
	if limit < MinMaxBytes {
		limit = MinMaxBytes
	}
	strip := policy.Mode == RenderStrip
	budget := limit - markerReserve

	var out strings.Builder
	out.Grow(min(len(raw)+16, limit))
	counts := map[string]int{}
	var taint Taint
	appending := true
	cutOut, cutIn := -1, -1

	for index := 0; index < len(raw); {
		piece, size, kind := classify(raw, index, policy.ASCIIOnly)
		if kind != "" {
			counts[kind]++
			switch kind {
			case FindingBidi:
				taint |= TaintContainsBidi
			default:
				taint |= TaintContainsControlChars
			}
			if strip {
				piece = ""
			}
		}
		if appending {
			if cutOut < 0 && out.Len()+len(piece) > budget {
				cutOut, cutIn = out.Len(), index
			}
			if out.Len()+len(piece) > limit {
				appending = false
			} else {
				out.WriteString(piece)
			}
		}
		index += size
	}

	result := Rendered{Taints: taint, InputBytes: len(raw)}
	if len(raw) > limit {
		result.Taints |= TaintOversized
	}
	if appending {
		result.Text = out.String()
	} else {
		if cutOut < 0 {
			cutOut, cutIn = 0, 0
		}
		result.DroppedBytes = len(raw) - cutIn
		result.Taints |= TaintTruncated
		result.Text = out.String()[:cutOut] + truncationMarker(result.DroppedBytes, policy.ASCIIOnly)
	}
	result.Findings = make([]Finding, 0, len(counts))
	for kind, count := range counts {
		result.Findings = append(result.Findings, Finding{Kind: kind, Count: count})
	}
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].Kind < result.Findings[j].Kind })
	return result, nil
}

// Scan classifies raw without rendering it: the control, bidi, and
// instruction-like taints Render and LooksInstructionLike would report, with
// no size cap and therefore never TaintOversized or TaintTruncated.
func Scan(raw string) Taint {
	var taint Taint
	for index := 0; index < len(raw); {
		_, size, kind := classify(raw, index, false)
		switch kind {
		case "":
		case FindingBidi:
			taint |= TaintContainsBidi
		default:
			taint |= TaintContainsControlChars
		}
		index += size
	}
	if hit, _ := LooksInstructionLike(raw); hit {
		taint |= TaintContainsInstructionLike
	}
	return taint
}

func truncationMarker(dropped int, asciiOnly bool) string {
	ellipsis := "…"
	if asciiOnly {
		ellipsis = escapeRune('…')
	}
	return ellipsis + "[truncated " + strconv.Itoa(dropped) + " bytes]"
}

// classify decides how raw[index:] begins: it returns the rendered piece in
// escape mode, the number of input bytes consumed, and the finding kind ("" for
// a pass-through rune).
func classify(raw string, index int, asciiOnly bool) (piece string, size int, kind string) {
	r, size := utf8.DecodeRuneInString(raw[index:])
	switch {
	case r == utf8.RuneError && size == 1:
		return escapeByte(raw[index]), 1, FindingInvalidUTF8
	case r == '\n':
		return "\n", 1, ""
	case r == '\r':
		if index+1 < len(raw) && raw[index+1] == '\n' {
			return "\n", 2, ""
		}
		return escapeRune(r), 1, FindingCR
	case r == 0:
		return escapeRune(r), 1, FindingNUL
	case r == 0x1b:
		length, seqKind := scanEscape(raw, index)
		return escapeSequence(raw[index : index+length]), length, seqKind
	case r < 0x20:
		return escapeRune(r), 1, FindingC0
	case r == 0x7f:
		return escapeRune(r), 1, FindingDEL
	case r >= 0x80 && r <= 0x9f:
		if seqKind, ok := c1Introducer(r); ok {
			length := scanSequenceBody(raw, index, index+size, seqKind)
			return escapeSequence(raw[index : index+length]), length, seqKind
		}
		return escapeRune(r), size, FindingC1
	case isBidiControl(r):
		return escapeRune(r), size, FindingBidi
	case r == 0x2028 || r == 0x2029:
		return escapeRune(r), size, FindingSeparator
	case unicode.Is(unicode.Cf, r):
		return escapeRune(r), size, FindingFormat
	case asciiOnly && r >= 0x80:
		return escapeRune(r), size, ""
	case r >= 0x80 && !unicode.IsPrint(r) && !unicode.Is(unicode.Zs, r):
		return escapeRune(r), size, ""
	default:
		return raw[index : index+size], size, ""
	}
}

func isBidiControl(r rune) bool {
	switch {
	case r >= 0x202a && r <= 0x202e: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	case r == 0x200e || r == 0x200f || r == 0x061c: // LRM RLM ALM
		return true
	}
	return false
}

func c1Introducer(r rune) (string, bool) {
	switch r {
	case 0x9b:
		return FindingCSI, true
	case 0x9d:
		return FindingOSC, true
	case 0x90:
		return FindingDCS, true
	case 0x98:
		return FindingSOS, true
	case 0x9e:
		return FindingPM, true
	case 0x9f:
		return FindingAPC, true
	}
	return "", false
}

// scanEscape measures the sequence that starts with ESC at raw[index].
func scanEscape(raw string, index int) (length int, kind string) {
	if index+1 >= len(raw) {
		return 1, FindingESC
	}
	next := raw[index+1]
	switch next {
	case '[':
		return scanSequenceBody(raw, index, index+2, FindingCSI), FindingCSI
	case ']':
		return scanSequenceBody(raw, index, index+2, FindingOSC), FindingOSC
	case 'P':
		return scanSequenceBody(raw, index, index+2, FindingDCS), FindingDCS
	case 'X':
		return scanSequenceBody(raw, index, index+2, FindingSOS), FindingSOS
	case '^':
		return scanSequenceBody(raw, index, index+2, FindingPM), FindingPM
	case '_':
		return scanSequenceBody(raw, index, index+2, FindingAPC), FindingAPC
	}
	if next >= 0x20 && next <= 0x2f {
		// nF escape: intermediates then a final byte 0x30..0x7e.
		end := index + 2
		for end < len(raw) && raw[end] >= 0x20 && raw[end] <= 0x2f {
			end++
		}
		if end < len(raw) && raw[end] >= 0x30 && raw[end] <= 0x7e {
			end++
		}
		return end - index, FindingESC
	}
	if next >= 0x30 && next <= 0x7e {
		return 2, FindingESC
	}
	return 1, FindingESC
}

// scanSequenceBody returns the total length of a sequence whose introducer
// begins at start and whose body begins at bodyStart: a CSI parameter string
// up to its final byte, or a string-terminated body (BEL, ESC \, or U+009C)
// bounded by maxSequenceBytes.
func scanSequenceBody(raw string, start, bodyStart int, kind string) int {
	end := bodyStart
	if kind == FindingCSI {
		for end < len(raw) && raw[end] >= 0x30 && raw[end] <= 0x3f {
			end++
		}
		for end < len(raw) && raw[end] >= 0x20 && raw[end] <= 0x2f {
			end++
		}
		if end < len(raw) && raw[end] >= 0x40 && raw[end] <= 0x7e {
			end++
		}
		return end - start
	}
	for end < len(raw) && end-bodyStart < maxSequenceBytes {
		switch {
		case raw[end] == 0x07:
			return end + 1 - start
		case raw[end] == 0x1b && end+1 < len(raw) && raw[end+1] == '\\':
			return end + 2 - start
		case raw[end] == 0xc2 && end+1 < len(raw) && raw[end+1] == 0x9c:
			return end + 2 - start
		}
		end++
	}
	return end - start
}

// escapeSequence renders every byte of a terminal sequence as printable
// ASCII so the operator sees exactly what was sent.
func escapeSequence(sequence string) string {
	var out strings.Builder
	out.Grow(len(sequence) * 4)
	for index := 0; index < len(sequence); {
		r, size := utf8.DecodeRuneInString(sequence[index:])
		switch {
		case r == utf8.RuneError && size == 1:
			out.WriteString(escapeByte(sequence[index]))
		case r >= 0x20 && r <= 0x7e:
			out.WriteByte(byte(r))
		default:
			out.WriteString(escapeRune(r))
		}
		index += size
	}
	return out.String()
}

func escapeByte(b byte) string { return fmt.Sprintf(`\x%02x`, b) }

func escapeRune(r rune) string {
	switch {
	case r < 0x100:
		return fmt.Sprintf(`\x%02x`, r)
	case r < 0x10000:
		return fmt.Sprintf(`\u%04x`, r)
	default:
		return fmt.Sprintf(`\U%08x`, r)
	}
}

// QuoteForTerminal returns an always-ASCII rendering in strconv.QuoteToASCII
// form without the surrounding quotes. Use it when a value must be shown
// verbatim (including backslashes) on one line, for example identifiers in a
// human-readable report. Newlines are escaped as \n.
func QuoteForTerminal(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

// DefaultLabelMax is the SafeLabel cap when max is not positive. It matches
// the 128-byte identifier bound used by plan verification.
const DefaultLabelMax = 128

// SafeLabel maps an untrusted identifier onto the allowlist [A-Za-z0-9._:-].
// Every disallowed rune (not byte) becomes "_", the result is cut to max
// bytes, and an empty result becomes "_". The mapping is lossy by design:
// use Envelope.Digest to distinguish labels that collide.
func SafeLabel(value string, max int) string {
	if max <= 0 {
		max = DefaultLabelMax
	}
	var out strings.Builder
	out.Grow(min(len(value), max))
	for _, r := range value {
		if out.Len() >= max {
			break
		}
		if isLabelRune(r) {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	if out.Len() == 0 {
		return "_"
	}
	return out.String()
}

// IsSafeLabel reports whether value is non-empty, at most DefaultLabelMax
// bytes, and entirely within [A-Za-z0-9._:-].
func IsSafeLabel(value string) bool {
	if value == "" || len(value) > DefaultLabelMax {
		return false
	}
	for _, r := range value {
		if !isLabelRune(r) {
			return false
		}
	}
	return true
}

func isLabelRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '.' || r == '_' || r == ':' || r == '-'
}
