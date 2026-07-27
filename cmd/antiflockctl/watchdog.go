package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maximumWatchdogSource = 64 << 10
	maximumWatchdogReply  = 1 << 20
)

func runWatchdog(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "usage: antiflockctl watchdog <admit|run|run-open-findings> ...")
		return 2
	}
	switch arguments[0] {
	case "admit":
		return runWatchdogAdmit(arguments[1:], stdout, stderr)
	case "run":
		return runWatchdogRun(arguments[1:], stdout, stderr)
	case "run-open-findings":
		return runWatchdogRunOpenFindings(arguments[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown watchdog command %q\n", arguments[0])
		return 2
	}
}

func runWatchdogAdmit(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("antiflockctl watchdog admit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("url", "", "Core HTTPS base URL")
	tokenFile := flags.String("token-file", "", "private operator bearer-token file")
	caFile := flags.String("ca-cert", "", "optional Core CA PEM for a private HTTPS certificate")
	nodeID := flags.String("node-id", "", "enrolled AntiFlock node id")
	sourceFile := flags.String("source-file", "", "regular Nano source file")
	bindingID := flags.String("binding-id", "", "admitted fixed binding id")
	operationID := flags.String("operation-id", "", "idempotency operation id")
	timeout := flags.Duration("timeout", 15*time.Second, "request timeout")
	if err := flags.Parse(arguments); err != nil { return 2 }
	if flags.NArg() != 0 || !canonicalWatchdogValue(*nodeID, 128) || !canonicalWatchdogValue(*bindingID, 128) || !canonicalWatchdogValue(*operationID, 128) {
		fmt.Fprintln(stderr, "admit requires canonical node-id, binding-id, and operation-id values")
		return 2
	}
	source, err := readRegularBoundedFile(*sourceFile, maximumWatchdogSource, false)
	if err != nil || strings.TrimSpace(string(source)) == "" { fmt.Fprintln(stderr, "admit requires a non-empty bounded regular source-file"); return 2 }
	endpoint, token, client, err := watchdogConnection(*baseURL, *tokenFile, *caFile, *timeout)
	if err != nil { fmt.Fprintf(stderr, "watchdog connection: %v\n", err); return 2 }
	payload := map[string]any{"nodeId": *nodeID, "source": string(source), "bindingId": *bindingID, "operationId": *operationID}
	if err := submitWatchdogJSON(context.Background(), client, endpoint+"/v1/watchdogs", token, payload, http.StatusCreated, stdout); err != nil { fmt.Fprintf(stderr, "watchdog admission failed: %v\n", err); return 1 }
	return 0
}

func runWatchdogRun(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("antiflockctl watchdog run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("url", "", "Core HTTPS base URL")
	tokenFile := flags.String("token-file", "", "private operator bearer-token file")
	caFile := flags.String("ca-cert", "", "optional Core CA PEM for a private HTTPS certificate")
	programID := flags.String("program-id", "", "admitted watchdog id")
	findingID := flags.String("finding-id", "", "typed finding id")
	nodeID := flags.String("node-id", "", "enrolled AntiFlock node id")
	reasonCode := flags.String("reason-code", "", "typed finding reason code")
	confidence := flags.Float64("confidence", 0, "finding confidence from 0 through 1")
	observedUnix := flags.Int64("observed-unix", 0, "finding observed Unix second")
	timeout := flags.Duration("timeout", 15*time.Second, "request timeout")
	if err := flags.Parse(arguments); err != nil { return 2 }
	if flags.NArg() != 0 || !canonicalWatchdogValue(*programID, 128) || !canonicalWatchdogValue(*findingID, 128) || !canonicalWatchdogValue(*nodeID, 128) || !canonicalWatchdogValue(*reasonCode, 128) || math.IsNaN(*confidence) || math.IsInf(*confidence, 0) || *confidence < 0 || *confidence > 1 || *observedUnix <= 0 {
		fmt.Fprintln(stderr, "run requires canonical ids/reason-code, confidence from 0 through 1, and a positive observed-unix")
		return 2
	}
	endpoint, token, client, err := watchdogConnection(*baseURL, *tokenFile, *caFile, *timeout)
	if err != nil { fmt.Fprintf(stderr, "watchdog connection: %v\n", err); return 2 }
	payload := map[string]any{"findingId": *findingID, "nodeId": *nodeID, "reasonCode": *reasonCode, "confidence": *confidence, "observedUnix": *observedUnix}
	if err := submitWatchdogJSON(context.Background(), client, endpoint+"/v1/watchdogs/"+url.PathEscape(*programID)+"/run", token, payload, http.StatusOK, stdout); err != nil { fmt.Fprintf(stderr, "watchdog run failed: %v\n", err); return 1 }
	return 0
}


func runWatchdogRunOpenFindings(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("antiflockctl watchdog run-open-findings", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("url", "", "Core HTTPS base URL")
	tokenFile := flags.String("token-file", "", "private operator bearer-token file")
	caFile := flags.String("ca-cert", "", "optional Core CA PEM for a private HTTPS certificate")
	programID := flags.String("program-id", "", "admitted watchdog id")
	timeout := flags.Duration("timeout", 15*time.Second, "request timeout")
	if err := flags.Parse(arguments); err != nil { return 2 }
	if flags.NArg() != 0 || !canonicalWatchdogValue(*programID, 128) {
		fmt.Fprintln(stderr, "run-open-findings requires a canonical program-id")
		return 2
	}
	endpoint, token, client, err := watchdogConnection(*baseURL, *tokenFile, *caFile, *timeout)
	if err != nil { fmt.Fprintf(stderr, "watchdog connection: %v\n", err); return 2 }
	if err := submitWatchdogJSON(context.Background(), client, endpoint+"/v1/watchdogs/"+url.PathEscape(*programID)+"/run-open-findings", token, map[string]any{}, http.StatusOK, stdout); err != nil { fmt.Fprintf(stderr, "watchdog Core-finding run failed: %v\n", err); return 1 }
	return 0
}

func watchdogConnection(rawURL, tokenPath, caPath string, timeout time.Duration) (string, string, *http.Client, error) {
	if timeout < 100*time.Millisecond || timeout > time.Minute { return "", "", nil, errors.New("timeout must be from 100ms through one minute") }
	endpoint, err := watchdogBaseURL(rawURL)
	if err != nil { return "", "", nil, err }
	token, err := readWatchdogToken(tokenPath)
	if err != nil { return "", "", nil, err }
	client, err := watchdogHTTPClient(caPath, timeout)
	if err != nil { return "", "", nil, err }
	return endpoint, token, client, nil
}

func watchdogBaseURL(raw string) (string, error) {
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || value.Scheme == "" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || (value.Scheme != "https" && value.Scheme != "http") { return "", errors.New("core URL must be an absolute HTTP(S) URL without credentials, query, or fragment") }
	if value.Scheme == "http" && !watchdogLoopback(value.Hostname()) { return "", errors.New("core requires HTTPS outside loopback") }
	return strings.TrimRight(value.String(), "/"), nil
}

func watchdogLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") { return true }
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readWatchdogToken(path string) (string, error) {
	content, err := readRegularBoundedFile(path, 16<<10, true)
	if err != nil { return "", errors.New("token-file must be a private regular file") }
	token := strings.TrimSpace(string(content))
	if len(token) < 32 { return "", errors.New("token-file must contain a bearer token of at least 32 bytes") }
	return token, nil
}

func readRegularBoundedFile(path string, maximum int64, private bool) ([]byte, error) {
	if strings.TrimSpace(path) == "" { return nil, errors.New("file path is required") }
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maximum || (private && info.Mode().Perm() != 0o600) { return nil, errors.New("file is invalid") }
	return os.ReadFile(path)
}

func watchdogHTTPClient(caPath string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(caPath) != "" {
		content, err := readRegularBoundedFile(caPath, 1<<20, false)
		if err != nil || len(content) == 0 { return nil, errors.New("read bounded Core CA certificate") }
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(content) { return nil, errors.New("core CA certificate does not contain PEM certificates") }
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func submitWatchdogJSON(ctx context.Context, client *http.Client, endpoint, token string, payload map[string]any, expectedStatus int, stdout io.Writer) error {
	encoded, err := json.Marshal(payload)
	if err != nil { return errors.New("encode watchdog request") }
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil { return errors.New("build watchdog request") }
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil { return errors.New("submit watchdog request") }
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumWatchdogReply+1))
	if err != nil || len(content) > maximumWatchdogReply { return errors.New("read bounded watchdog response") }
	if response.StatusCode != expectedStatus { return fmt.Errorf("core returned HTTP %d", response.StatusCode) }
	var value any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil { return errors.New("core returned invalid watchdog JSON") }
	if err := requireWatchdogEOF(decoder); err != nil { return err }
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil { return errors.New("format watchdog response") }
	if _, err := fmt.Fprintln(stdout, string(pretty)); err != nil { return errors.New("write watchdog response") }
	return nil
}

func requireWatchdogEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF { return nil }
	return errors.New("core returned trailing watchdog JSON")
}

func canonicalWatchdogValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
