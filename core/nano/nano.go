// Package nano implements AntiFlock's deterministic, I/O-free conformance
// runtime for Nano v0.1. It follows DBarr3/Nano PR #1 without copying its
// Python implementation. Programs can only produce typed intents; this
// package has no filesystem, process, network, clock, randomness, or host
// mutation capability.
package nano

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	IRVersion      = "0.1.0"
	UpstreamCommit = "40f697ba9020a4d4fee985406779c0d90ea2d6f4"
)

var (
	ErrLimitExceeded    = errors.New("Nano resource limit exceeded")
	ErrAdmissionDenied  = errors.New("Nano program is outside the AntiFlock intent profile")
	ErrInvalidFrame     = errors.New("Nano evaluation frame is invalid")
	ErrInstructionLimit = errors.New("Nano instruction budget exhausted")
)

type Limits struct {
	MaxSourceBytes  int
	MaxTokens       int
	MaxAgents       int
	MaxConditions   int
	MaxIntents      int
	MaxSignals      int
	MaxTimestamps   int
	MaxInstructions int
	MaxOutputs      int
}

var DefaultLimits = Limits{
	MaxSourceBytes: 64 << 10, MaxTokens: 4096, MaxAgents: 16,
	MaxConditions: 64, MaxIntents: 16, MaxSignals: 128,
	MaxTimestamps: 1024, MaxInstructions: 8192, MaxOutputs: 128,
}

type Schedule struct {
	Interval string `json:"interval"`
	Seconds  int64  `json:"-"`
}

type Condition struct {
	Signal   string  `json:"signal"`
	Operator string  `json:"operator"`
	Value    float64 `json:"value"`
}

type Intent struct {
	Action     string   `json:"action"`
	Asset      string   `json:"asset,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
}

type Program struct {
	Name       string
	Schedule   *Schedule
	Conditions []Condition
	Intents    []Intent
	Agents     []string
}

type irNode struct {
	Type       string   `json:"type"`
	Interval   string   `json:"interval,omitempty"`
	Signal     string   `json:"signal,omitempty"`
	Operator   string   `json:"operator,omitempty"`
	Value      *float64 `json:"value,omitempty"`
	Action     string   `json:"action,omitempty"`
	Asset      string   `json:"asset,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Name       string   `json:"name,omitempty"`
}

type canonicalIR struct {
	Type          string   `json:"type"`
	NanoIRVersion string   `json:"nanoIrVersion"`
	Name          string   `json:"name"`
	Effects       []string `json:"effects"`
	Nodes         []irNode `json:"nodes"`
}

func (program Program) CanonicalJSON() ([]byte, error) {
	if strings.TrimSpace(program.Name) == "" {
		return nil, errors.New("Nano program name is required")
	}
	nodes := make([]irNode, 0, 1+len(program.Conditions)+len(program.Intents)+len(program.Agents))
	if program.Schedule != nil {
		nodes = append(nodes, irNode{Type: "Schedule", Interval: program.Schedule.Interval})
	}
	for _, condition := range program.Conditions {
		value := condition.Value
		nodes = append(nodes, irNode{Type: "Condition", Signal: condition.Signal, Operator: condition.Operator, Value: &value})
	}
	for _, intent := range program.Intents {
		nodes = append(nodes, irNode{Type: "Intent", Action: intent.Action, Asset: intent.Asset, Confidence: intent.Confidence})
	}
	for _, agent := range program.Agents {
		nodes = append(nodes, irNode{Type: "Agent", Name: agent})
	}
	value := canonicalIR{
		Type: "Strategy", NanoIRVersion: IRVersion, Name: program.Name,
		Effects: []string{"intent.emit", "log.append"}, Nodes: nodes,
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func (program Program) Digest() (string, error) {
	canonical, err := program.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type SyntaxError struct {
	Message string
	Line    int
	Column  int
}

func (err *SyntaxError) Error() string {
	return fmt.Sprintf("%s at line %d, column %d", err.Message, err.Line, err.Column)
}

type token struct {
	kind   string
	value  string
	line   int
	column int
}

func Compile(source string, limits Limits) (Program, error) {
	if err := limits.validate(); err != nil {
		return Program{}, err
	}
	if len(source) == 0 || len(source) > limits.MaxSourceBytes || !utf8.ValidString(source) {
		return Program{}, ErrLimitExceeded
	}
	tokens, err := tokenize(source, limits.MaxTokens)
	if err != nil {
		return Program{}, err
	}
	parser := parser{tokens: tokens, limits: limits}
	program, err := parser.parseProgram()
	if err != nil {
		return Program{}, err
	}
	if program.Schedule == nil && len(program.Agents) == 0 {
		return Program{}, errors.New("Nano strategy requires at least one IR node")
	}
	return program, nil
}

func AdmitWatchdog(program Program) error {
	for _, intent := range program.Intents {
		if intent.Action != "EXECUTE" && intent.Action != "OBSERVE" {
			return fmt.Errorf("%w: %s intents are not admitted", ErrAdmissionDenied, intent.Action)
		}
		if intent.Asset != "" || intent.Confidence != nil {
			return fmt.Errorf("%w: watchdog intents cannot carry script-selected parameters", ErrAdmissionDenied)
		}
	}
	return nil
}

func (limits Limits) validate() error {
	values := []int{limits.MaxSourceBytes, limits.MaxTokens, limits.MaxAgents, limits.MaxConditions,
		limits.MaxIntents, limits.MaxSignals, limits.MaxTimestamps, limits.MaxInstructions, limits.MaxOutputs}
	for _, value := range values {
		if value < 1 {
			return errors.New("every Nano resource limit must be positive")
		}
	}
	return nil
}

func tokenize(source string, maximum int) ([]token, error) {
	result := make([]token, 0)
	line, column := 1, 1
	for offset := 0; offset < len(source); {
		character := source[offset]
		if character == '\n' {
			offset++
			line++
			column = 1
			continue
		}
		if character == ' ' || character == '\t' || character == '\r' {
			offset++
			column++
			continue
		}
		if character == '/' && offset+1 < len(source) && source[offset+1] == '/' {
			for offset < len(source) && source[offset] != '\n' {
				offset++
				column++
			}
			continue
		}
		start, startColumn := offset, column
		add := func(kind, value string) error {
			result = append(result, token{kind: kind, value: value, line: line, column: startColumn})
			if len(result) > maximum {
				return ErrLimitExceeded
			}
			return nil
		}
		switch character {
		case '{', '}', '(', ')', ',':
			kinds := map[byte]string{'{': "LBRACE", '}': "RBRACE", '(': "LPAREN", ')': "RPAREN", ',': "COMMA"}
			if err := add(kinds[character], string(character)); err != nil {
				return nil, err
			}
			offset++
			column++
			continue
		case '<', '>':
			value := string(character)
			if offset+1 < len(source) && source[offset+1] == '=' {
				value += "="
				offset++
				column++
			}
			if err := add("OP", value); err != nil {
				return nil, err
			}
			offset++
			column++
			continue
		case '=', '!':
			if offset+1 >= len(source) || source[offset+1] != '=' {
				return nil, syntax("unknown comparison operator", line, startColumn)
			}
			if err := add("OP", source[offset:offset+2]); err != nil {
				return nil, err
			}
			offset += 2
			column += 2
			continue
		}
		if identifierStart(character) {
			for offset < len(source) && identifierPart(source[offset]) {
				offset++
				column++
			}
			if err := add("IDENT", source[start:offset]); err != nil {
				return nil, err
			}
			continue
		}
		if character >= '0' && character <= '9' {
			for offset < len(source) && source[offset] >= '0' && source[offset] <= '9' {
				offset++
				column++
			}
			kind := "INT"
			if offset < len(source) && source[offset] == '.' {
				kind = "FLOAT"
				offset++
				column++
				if offset >= len(source) || source[offset] < '0' || source[offset] > '9' {
					return nil, syntax("digits are required after a decimal point", line, startColumn)
				}
				for offset < len(source) && source[offset] >= '0' && source[offset] <= '9' {
					offset++
					column++
				}
			}
			if offset < len(source) && identifierPart(source[offset]) {
				for offset < len(source) && identifierPart(source[offset]) {
					offset++
					column++
				}
				value := source[start:offset]
				if kind != "INT" || len(value) < 2 || !strings.Contains("smhd", value[len(value)-1:]) ||
					strings.IndexFunc(value[:len(value)-1], func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
					return nil, syntax("malformed interval", line, startColumn)
				}
				if err := add("INTERVAL", value); err != nil {
					return nil, err
				}
				continue
			}
			if err := add(kind, source[start:offset]); err != nil {
				return nil, err
			}
			continue
		}
		return nil, syntax(fmt.Sprintf("unexpected character %q", character), line, startColumn)
	}
	result = append(result, token{kind: "EOF", line: line, column: column})
	return result, nil
}

func identifierStart(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '_'
}

func identifierPart(value byte) bool {
	return identifierStart(value) || (value >= '0' && value <= '9')
}

func syntax(message string, line, column int) error {
	return &SyntaxError{Message: message, Line: line, Column: column}
}

type parser struct {
	tokens []token
	index  int
	limits Limits
}

func (parser *parser) current() token { return parser.tokens[parser.index] }

func (parser *parser) take() token {
	value := parser.current()
	if value.kind != "EOF" {
		parser.index++
	}
	return value
}

func (parser *parser) expect(kind, description string) (token, error) {
	value := parser.current()
	if value.kind != kind {
		return token{}, syntax("expected "+description, value.line, value.column)
	}
	return parser.take(), nil
}

func (parser *parser) keyword(value string) bool {
	current := parser.current()
	return current.kind == "IDENT" && current.value == value
}

func (parser *parser) expectKeyword(value string) error {
	current := parser.current()
	if !parser.keyword(value) {
		return syntax("expected keyword "+value, current.line, current.column)
	}
	parser.take()
	return nil
}

func (parser *parser) parseProgram() (Program, error) {
	if err := parser.expectKeyword("strategy"); err != nil {
		return Program{}, err
	}
	name, err := parser.expect("IDENT", "strategy name")
	if err != nil {
		return Program{}, err
	}
	if _, err := parser.expect("LBRACE", "{"); err != nil {
		return Program{}, err
	}
	program := Program{Name: name.value}
	for parser.current().kind != "RBRACE" {
		if parser.current().kind == "EOF" {
			return Program{}, syntax("unterminated strategy block", parser.current().line, parser.current().column)
		}
		switch {
		case parser.keyword("agent"):
			parser.take()
			agent, nameErr := parser.expect("IDENT", "agent name")
			if nameErr != nil {
				return Program{}, nameErr
			}
			program.Agents = append(program.Agents, agent.value)
			if len(program.Agents) > parser.limits.MaxAgents {
				return Program{}, ErrLimitExceeded
			}
		case parser.keyword("every"):
			if program.Schedule != nil {
				return Program{}, syntax("at most one schedule is allowed", parser.current().line, parser.current().column)
			}
			if err := parser.parseSchedule(&program); err != nil {
				return Program{}, err
			}
		default:
			return Program{}, syntax("expected every or agent", parser.current().line, parser.current().column)
		}
	}
	parser.take()
	if parser.current().kind != "EOF" {
		return Program{}, syntax("unexpected input after strategy", parser.current().line, parser.current().column)
	}
	return program, nil
}

func (parser *parser) parseSchedule(program *Program) error {
	parser.take()
	interval, err := parser.expect("INTERVAL", "schedule interval")
	if err != nil {
		return err
	}
	seconds, err := intervalSeconds(interval.value)
	if err != nil {
		return syntax(err.Error(), interval.line, interval.column)
	}
	program.Schedule = &Schedule{Interval: interval.value, Seconds: seconds}
	if _, err := parser.expect("LBRACE", "{"); err != nil {
		return err
	}
	if parser.keyword("if") {
		if err := parser.parseRule(program); err != nil {
			return err
		}
	}
	if parser.keyword("if") {
		return syntax("at most one rule is allowed", parser.current().line, parser.current().column)
	}
	if _, err := parser.expect("RBRACE", "schedule closing brace"); err != nil {
		return err
	}
	return nil
}

func (parser *parser) parseRule(program *Program) error {
	parser.take()
	for {
		condition, err := parser.parseCondition()
		if err != nil {
			return err
		}
		program.Conditions = append(program.Conditions, condition)
		if len(program.Conditions) > parser.limits.MaxConditions {
			return ErrLimitExceeded
		}
		if !parser.keyword("and") {
			break
		}
		parser.take()
	}
	if _, err := parser.expect("LBRACE", "rule opening brace"); err != nil {
		return err
	}
	if parser.current().kind != "IDENT" {
		return syntax("rule requires at least one action", parser.current().line, parser.current().column)
	}
	for parser.current().kind == "IDENT" {
		intent, err := parser.parseIntent()
		if err != nil {
			return err
		}
		program.Intents = append(program.Intents, intent)
		if len(program.Intents) > parser.limits.MaxIntents {
			return ErrLimitExceeded
		}
	}
	_, err := parser.expect("RBRACE", "rule closing brace")
	return err
}

func (parser *parser) parseCondition() (Condition, error) {
	signal, err := parser.expect("IDENT", "signal name")
	if err != nil {
		return Condition{}, err
	}
	if parser.current().kind == "LPAREN" {
		parser.take()
		if _, err := parser.expect("INT", "integer signal argument"); err != nil {
			return Condition{}, err
		}
		if _, err := parser.expect("RPAREN", ")"); err != nil {
			return Condition{}, err
		}
	}
	operator, err := parser.expect("OP", "comparison operator")
	if err != nil {
		return Condition{}, err
	}
	number, err := parser.number("condition value")
	if err != nil {
		return Condition{}, err
	}
	return Condition{Signal: signal.value, Operator: operator.value, Value: number}, nil
}

func (parser *parser) parseIntent() (Intent, error) {
	action := parser.take()
	actions := map[string]string{"buy": "BUY", "sell": "SELL", "execute": "EXECUTE", "pause": "PAUSE", "observe": "OBSERVE"}
	canonical, known := actions[action.value]
	if !known {
		return Intent{}, syntax("unknown action", action.line, action.column)
	}
	if _, err := parser.expect("LPAREN", "("); err != nil {
		return Intent{}, err
	}
	intent := Intent{Action: canonical}
	if canonical == "BUY" || canonical == "SELL" {
		asset, err := parser.expect("IDENT", "asset name")
		if err != nil {
			return Intent{}, err
		}
		intent.Asset = asset.value
		if parser.current().kind == "COMMA" {
			parser.take()
			value, numberErr := parser.number("confidence")
			if numberErr != nil {
				return Intent{}, numberErr
			}
			if value < 0 || value > 1 {
				return Intent{}, syntax("confidence must be within [0, 1]", action.line, action.column)
			}
			intent.Confidence = &value
		}
	}
	if _, err := parser.expect("RPAREN", ")"); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

func (parser *parser) number(description string) (float64, error) {
	value := parser.current()
	if value.kind != "INT" && value.kind != "FLOAT" {
		return 0, syntax("expected numeric "+description, value.line, value.column)
	}
	parser.take()
	parsed, err := strconv.ParseFloat(value.value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, syntax("invalid numeric "+description, value.line, value.column)
	}
	return parsed, nil
}

func intervalSeconds(value string) (int64, error) {
	if len(value) < 2 {
		return 0, errors.New("invalid interval")
	}
	amount, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
	if err != nil || amount <= 0 {
		return 0, errors.New("interval must be positive")
	}
	multipliers := map[byte]int64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
	multiplier, found := multipliers[value[len(value)-1]]
	if !found || amount > math.MaxInt64/multiplier {
		return 0, errors.New("invalid interval")
	}
	return amount * multiplier, nil
}

type Frame struct {
	Timestamps []int64
	Signals    map[string][]float64
}

type Cursor struct {
	Initialized bool  `json:"initialized"`
	NextDueUnix int64 `json:"nextDueUnix"`
}

type EmittedIntent struct {
	Action    string `json:"action"`
	Timestamp int64  `json:"timestamp"`
}

type TraceEntry struct {
	Event     string `json:"event"`
	Timestamp int64  `json:"timestamp"`
	Detail    string `json:"detail"`
}

type EvaluationResult struct {
	Intents      []EmittedIntent `json:"intents"`
	Trace        []TraceEntry    `json:"trace"`
	Instructions int             `json:"instructions"`
}

func Evaluate(program Program, frame Frame, cursor Cursor, limits Limits) (EvaluationResult, Cursor, error) {
	if err := limits.validate(); err != nil {
		return EvaluationResult{}, cursor, err
	}
	if err := AdmitWatchdog(program); err != nil {
		return EvaluationResult{}, cursor, err
	}
	if len(frame.Timestamps) == 0 || len(frame.Timestamps) > limits.MaxTimestamps || len(frame.Signals) > limits.MaxSignals {
		return EvaluationResult{}, cursor, ErrInvalidFrame
	}
	for index, timestamp := range frame.Timestamps {
		if index > 0 && timestamp < frame.Timestamps[index-1] {
			return EvaluationResult{}, cursor, ErrInvalidFrame
		}
	}
	for name, values := range frame.Signals {
		if strings.TrimSpace(name) == "" || len(values) != len(frame.Timestamps) {
			return EvaluationResult{}, cursor, ErrInvalidFrame
		}
		for _, value := range values {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return EvaluationResult{}, cursor, ErrInvalidFrame
			}
		}
	}
	step := int64(1)
	if program.Schedule != nil {
		step = program.Schedule.Seconds
	}
	result := EvaluationResult{Intents: []EmittedIntent{}, Trace: []TraceEntry{{Event: "strategy.loaded", Timestamp: frame.Timestamps[0], Detail: program.Name}}}
	next := cursor
	for index, timestamp := range frame.Timestamps {
		if next.Initialized && timestamp < next.NextDueUnix {
			continue
		}
		next.Initialized = true
		if timestamp > math.MaxInt64-step {
			return EvaluationResult{}, cursor, ErrInvalidFrame
		}
		next.NextDueUnix = timestamp + step
		matched := len(program.Conditions) > 0
		for _, condition := range program.Conditions {
			result.Instructions++
			if result.Instructions > limits.MaxInstructions {
				return EvaluationResult{}, cursor, ErrInstructionLimit
			}
			series, found := frame.Signals[condition.Signal]
			if !found {
				return EvaluationResult{}, cursor, fmt.Errorf("%w: signal %s is missing", ErrInvalidFrame, condition.Signal)
			}
			observed := series[index]
			passed := compare(observed, condition.Operator, condition.Value)
			result.Trace = append(result.Trace, TraceEntry{
				Event: "condition.evaluated", Timestamp: timestamp,
				Detail: fmt.Sprintf("%s %s %s observed=%s -> %t", condition.Signal, condition.Operator,
					strconv.FormatFloat(condition.Value, 'g', -1, 64), strconv.FormatFloat(observed, 'g', -1, 64), passed),
			})
			if !passed {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for _, intent := range program.Intents {
			result.Instructions++
			if result.Instructions > limits.MaxInstructions || len(result.Intents) >= limits.MaxOutputs {
				return EvaluationResult{}, cursor, ErrInstructionLimit
			}
			result.Intents = append(result.Intents, EmittedIntent{Action: intent.Action, Timestamp: timestamp})
			result.Trace = append(result.Trace, TraceEntry{Event: "intent.emitted", Timestamp: timestamp, Detail: intent.Action})
		}
	}
	return result, next, nil
}

func compare(observed float64, operator string, expected float64) bool {
	switch operator {
	case "<":
		return observed < expected
	case "<=":
		return observed <= expected
	case ">":
		return observed > expected
	case ">=":
		return observed >= expected
	case "==":
		return observed == expected
	case "!=":
		return observed != expected
	default:
		return false
	}
}

type FindingContext struct {
	FindingID    string
	NodeID       string
	ReasonCode   string
	Confidence   float64
	ObservedUnix int64
}

func FrameForFinding(finding FindingContext) (Frame, string, error) {
	if finding.FindingID == "" || finding.NodeID == "" || finding.ReasonCode == "" ||
		finding.Confidence < 0 || finding.Confidence > 1 || math.IsNaN(finding.Confidence) || math.IsInf(finding.Confidence, 0) {
		return Frame{}, "", ErrInvalidFrame
	}
	signal := "REASON_" + normalizeReason(finding.ReasonCode)
	if signal == "REASON_" {
		return Frame{}, "", ErrInvalidFrame
	}
	frame := Frame{Timestamps: []int64{finding.ObservedUnix}, Signals: map[string][]float64{
		signal: {1}, "CONFIDENCE": {finding.Confidence},
	}}
	keys := []string{signal, "CONFIDENCE"}
	sort.Strings(keys)
	hasher := sha256.New()
	for _, value := range []string{"AntiFlock-Nano-Finding-v1", finding.FindingID, finding.NodeID, finding.ReasonCode,
		strconv.FormatFloat(finding.Confidence, 'g', -1, 64), strconv.FormatInt(finding.ObservedUnix, 10)} {
		_, _ = hasher.Write([]byte(strconv.Itoa(len(value))))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(value))
	}
	return frame, "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func normalizeReason(reason string) string {
	var builder strings.Builder
	lastUnderscore := false
	for _, character := range strings.ToUpper(reason) {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			builder.WriteRune(character)
			lastUnderscore = false
		} else if !lastUnderscore && builder.Len() > 0 {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}
