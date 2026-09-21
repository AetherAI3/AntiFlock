package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Limits bounds BoundedJSON. Zero fields take the Default* values.
type Limits struct {
	// MaxBytes bounds len(raw) before any decoding happens.
	MaxBytes int
	// MaxDepth bounds container nesting; the top-level container is depth 1.
	MaxDepth int
	// MaxTokens bounds the total number of JSON tokens (delimiters, keys,
	// values) visited.
	MaxTokens int
	// MaxStringBytes bounds the decoded length of any string token.
	MaxStringBytes int
	// MaxNumberBytes bounds the literal length of any number token.
	MaxNumberBytes int
}

// Default limits.
const (
	DefaultMaxJSONBytes   = 4 << 20
	DefaultMaxDepth       = 32
	DefaultMaxTokens      = 100_000
	DefaultMaxStringBytes = 64 << 10
	DefaultMaxNumberBytes = 64
)

// DefaultLimits returns the defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:       DefaultMaxJSONBytes,
		MaxDepth:       DefaultMaxDepth,
		MaxTokens:      DefaultMaxTokens,
		MaxStringBytes: DefaultMaxStringBytes,
		MaxNumberBytes: DefaultMaxNumberBytes,
	}
}

func (l Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if l.MaxBytes <= 0 {
		l.MaxBytes = defaults.MaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = defaults.MaxDepth
	}
	if l.MaxTokens <= 0 {
		l.MaxTokens = defaults.MaxTokens
	}
	if l.MaxStringBytes <= 0 {
		l.MaxStringBytes = defaults.MaxStringBytes
	}
	if l.MaxNumberBytes <= 0 {
		l.MaxNumberBytes = defaults.MaxNumberBytes
	}
	return l
}

// Typed errors returned by BoundedJSON. Wrap them with %w; compare with
// errors.Is.
var (
	ErrJSONOversized    = errors.New("trust: json exceeds byte limit")
	ErrJSONDepth        = errors.New("trust: json nesting exceeds depth limit")
	ErrJSONTokens       = errors.New("trust: json exceeds token limit")
	ErrJSONStringLength = errors.New("trust: json string exceeds length limit")
	ErrJSONNumberLength = errors.New("trust: json number exceeds length limit")
	ErrJSONDuplicateKey = errors.New("trust: json object repeats a key")
	ErrJSONTrailing     = errors.New("trust: json has trailing content")
	ErrJSONMalformed    = errors.New("trust: json is malformed")
	ErrJSONEmpty        = errors.New("trust: json is empty")
)

// JSONError carries the typed error plus position detail. Detail never
// contains bytes from the input.
type JSONError struct {
	Err    error
	Offset int64
	Depth  int
	Detail string
}

func (e *JSONError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%v at offset %d depth %d", e.Err, e.Offset, e.Depth)
	}
	return fmt.Sprintf("%v at offset %d depth %d: %s", e.Err, e.Offset, e.Depth, e.Detail)
}

// Unwrap exposes the typed error for errors.Is.
func (e *JSONError) Unwrap() error { return e.Err }

type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

// BoundedJSON walks raw with encoding/json's streaming tokenizer and enforces
// limits before any caller unmarshals it. It returns the taint set observed
// (TaintOversized for any exceeded limit, TaintDuplicateFields for a
// repeated key, plus the control/bidi/instruction taints found inside string
// tokens) and the first typed error. The walk stops at the first error; the
// taint returned alongside an error reflects what was seen up to and
// including the failing token.
//
// The tokenizer never builds the document, so a 1000-deep array costs a
// frame per level but no recursion. Depth is counted as containers currently
// open; the top-level container is depth 1.
func BoundedJSON(raw []byte, limits Limits) (Taint, error) {
	limits = limits.withDefaults()
	var taint Taint
	if len(raw) > limits.MaxBytes {
		return taint | TaintOversized, &JSONError{Err: ErrJSONOversized, Detail: fmt.Sprintf("%d bytes > %d", len(raw), limits.MaxBytes)}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return taint, &JSONError{Err: ErrJSONEmpty}
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var stack []*jsonFrame
	tokens := 0
	fail := func(err error, detail string) (Taint, error) {
		return taint, &JSONError{Err: err, Offset: decoder.InputOffset(), Depth: len(stack), Detail: detail}
	}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if tokens == 0 {
				return fail(ErrJSONEmpty, "")
			}
			return fail(ErrJSONMalformed, "unexpected end of input")
		}
		if err != nil {
			return fail(ErrJSONMalformed, "")
		}
		tokens++
		if tokens > limits.MaxTokens {
			taint |= TaintOversized
			return fail(ErrJSONTokens, fmt.Sprintf("more than %d tokens", limits.MaxTokens))
		}

		var frame *jsonFrame
		if len(stack) > 0 {
			frame = stack[len(stack)-1]
		}
		isKey := frame != nil && frame.object && frame.expectKey

		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				if len(stack)+1 > limits.MaxDepth {
					taint |= TaintOversized
					return fail(ErrJSONDepth, fmt.Sprintf("deeper than %d", limits.MaxDepth))
				}
				stack = append(stack, &jsonFrame{object: value == '{', expectKey: value == '{', keys: map[string]struct{}{}})
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
				frame = nil
				if len(stack) > 0 {
					frame = stack[len(stack)-1]
				}
			}
		case string:
			if len(value) > limits.MaxStringBytes {
				taint |= TaintOversized
				return fail(ErrJSONStringLength, fmt.Sprintf("%d bytes > %d", len(value), limits.MaxStringBytes))
			}
			taint |= Scan(value)
			if isKey {
				if _, dup := frame.keys[value]; dup {
					taint |= TaintDuplicateFields
					return fail(ErrJSONDuplicateKey, "")
				}
				frame.keys[value] = struct{}{}
			}
		case json.Number:
			if len(value) > limits.MaxNumberBytes {
				taint |= TaintOversized
				return fail(ErrJSONNumberLength, fmt.Sprintf("%d bytes > %d", len(value), limits.MaxNumberBytes))
			}
		}

		if frame != nil && frame.object {
			frame.expectKey = !frame.expectKey
		}
		if len(stack) == 0 {
			break
		}
	}

	if _, err := decoder.Token(); err != io.EOF {
		return fail(ErrJSONTrailing, "")
	}
	return taint, nil
}
