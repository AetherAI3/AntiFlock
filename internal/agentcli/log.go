package agentcli

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"sync"
)

// Redacted is the replacement text for every masked secret.
const Redacted = "[REDACTED]"

// secretPatterns are applied to every complete line written through a
// RedactingWriter. Hex digests are deliberately not matched: checksums are
// part of the update contract and must stay visible.
var secretPatterns = []*regexp.Regexp{
	// Authorization headers in any casing, including "Authorization: Bearer x".
	regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)[^\s"',}]+(\s+[^\s"',}]+)?`),
	// Bare bearer tokens.
	regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
	// key=value and "key": "value" forms for well-known secret names.
	regexp.MustCompile(`(?i)\b((?:token|secret|password|passwd|api[_-]?key|apikey|private[_-]?key|seed)\s*["']?\s*[:=]\s*["']?)[^\s"',}]+`),
	// Known token prefixes used by hosted services and this project's demos.
	regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat|sk|xox[abp])_[A-Za-z0-9_\-]{16,}\b`),
}

// PEM markers are assembled at runtime so that no private-key armor literal
// exists in the source tree (secret scanners match the literal form).
const pemDashes = "-----"

var (
	pemBegin     = pemDashes + "BEGIN"
	pemEnd       = pemDashes + "END"
	pemKeyMarker = "PRIVATE " + "KEY" + pemDashes
)

// pemPrivateKey spans lines, so it is applied to the whole buffered chunk.
var pemPrivateKey = regexp.MustCompile(pemBegin + ` [A-Z0-9 ]*` + pemKeyMarker + `[\s\S]*?` + pemEnd + ` [A-Z0-9 ]*` + pemKeyMarker)

// Redact masks secrets in one string.
func Redact(value string) string {
	value = pemPrivateKey.ReplaceAllString(value, pemBegin+" "+pemKeyMarker+Redacted+pemEnd+" "+pemKeyMarker)
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllStringFunc(value, func(match string) string {
			groups := pattern.FindStringSubmatch(match)
			if len(groups) >= 2 && groups[1] != "" {
				return groups[1] + Redacted
			}
			return Redacted
		})
	}
	return value
}

// RedactingWriter masks secrets line by line before they reach the
// underlying writer. Partial lines are buffered until a newline or Flush so
// that a secret split across two Write calls is still masked.
type RedactingWriter struct {
	mu      sync.Mutex
	target  io.Writer
	pending bytes.Buffer
}

// NewRedactingWriter wraps target. A nil target discards output.
func NewRedactingWriter(target io.Writer) *RedactingWriter {
	if target == nil {
		target = io.Discard
	}
	return &RedactingWriter{target: target}
}

func (writer *RedactingWriter) Write(content []byte) (int, error) {
	if writer == nil {
		return 0, errors.New("redacting writer is required")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.pending.Write(content)
	if err := writer.flushCompleteLines(); err != nil {
		return 0, err
	}
	return len(content), nil
}

// Flush writes any buffered partial line (redacted) to the target.
func (writer *RedactingWriter) Flush() error {
	if writer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.pending.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(writer.target, Redact(writer.pending.String()))
	writer.pending.Reset()
	return err
}

func (writer *RedactingWriter) flushCompleteLines() error {
	for {
		content := writer.pending.Bytes()
		index := bytes.LastIndexByte(content, '\n')
		if index < 0 {
			return nil
		}
		// A PEM block may still be open: keep buffering until it closes.
		if bytes.Contains(content[:index+1], []byte(pemBegin)) && !bytes.Contains(content[:index+1], []byte(pemEnd)) {
			return nil
		}
		line := string(content[:index+1])
		writer.pending.Next(index + 1)
		if _, err := io.WriteString(writer.target, Redact(line)); err != nil {
			return err
		}
	}
}
