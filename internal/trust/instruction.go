package trust

import (
	"sort"
	"strings"
	"unicode"
)

// instructionPhrases are matched case-insensitively against text whose
// whitespace has been collapsed and whose format runes have been removed
// (so zero-width joiners cannot split a phrase). Each entry is matched as a
// substring; short single words are additionally required to sit on word
// boundaries (see wordPhrases).
var instructionPhrases = []string{
	"ignore previous",
	"ignore all previous",
	"ignore the above",
	"disregard previous",
	"disregard the above",
	"you are now",
	"act as",
	"pretend you are",
	"new instructions",
	"system prompt",
	"system:",
	"assistant:",
	"user:",
	"developer:",
	"run the following",
	"execute the following",
	"do not tell",
	"rm -rf",
	"nft ",
	"iptables ",
	"curl ",
	"wget ",
	"<|im_start|>",
	"<|im_end|>",
	"[inst]",
	"### instruction",
	"### system",
	"```",
}

// wordPhrases are single tokens that are only counted when they appear as a
// whole word. They are common in legitimate prose, which is why the detector
// is advisory.
var wordPhrases = []string{
	"execute",
	"approve",
	"approved",
	"grant",
	"sudo",
	"override",
	"bypass",
	"authorize",
	"authorise",
}

// LooksInstructionLike reports whether text is shaped like an instruction to
// an operator or a model, and which markers matched (sorted, deduplicated).
//
// Stance on false positives: the detector is deliberately conservative in
// what it does with a hit (nothing) and deliberately liberal in what it
// counts as a hit. A plan description that says "approve" or a commit message
// that mentions "sudo" will be flagged; that is acceptable because the only
// effect of a hit is the advisory TaintContainsInstructionLike bit, which
// callers display or log alongside the quoted text. The bit never blocks,
// never changes policy, and never grants or denies anything. Missing a real
// injection (a false negative) is also tolerable for the same reason: even
// unflagged text is DataOnly and cannot instruct anything.
func LooksInstructionLike(text string) (bool, []string) {
	normalised := normaliseForMatch(text)
	if normalised == "" {
		return false, nil
	}
	found := map[string]struct{}{}
	for _, phrase := range instructionPhrases {
		if strings.Contains(normalised, phrase) {
			found[strings.TrimSpace(phrase)] = struct{}{}
		}
	}
	for _, word := range wordPhrases {
		if containsWord(normalised, word) {
			found[word] = struct{}{}
		}
	}
	if len(found) == 0 {
		return false, nil
	}
	matches := make([]string, 0, len(found))
	for phrase := range found {
		matches = append(matches, phrase)
	}
	sort.Strings(matches)
	return true, matches
}

// normaliseForMatch lowercases, drops format and control runes, and collapses
// runs of whitespace to one space.
func normaliseForMatch(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	space := false
	for _, r := range text {
		switch {
		case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Cc, r) && !unicode.IsSpace(r):
			continue
		case unicode.IsSpace(r):
			space = true
		default:
			if space && out.Len() > 0 {
				out.WriteByte(' ')
			}
			space = false
			out.WriteRune(unicode.ToLower(r))
		}
	}
	return out.String()
}

func containsWord(haystack, word string) bool {
	offset := 0
	for {
		index := strings.Index(haystack[offset:], word)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(word)
		before := start == 0 || !isWordRune(rune(haystack[start-1]))
		after := end == len(haystack) || !isWordRune(rune(haystack[end]))
		if before && after {
			return true
		}
		offset = start + 1
	}
}

func isWordRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r >= 0x80
}
