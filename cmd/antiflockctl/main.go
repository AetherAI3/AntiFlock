package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maximumHealthBody = 4 << 10

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "usage: antiflockctl health --url <core-base-url> [--timeout 3s]")
		return 2
	}
	switch arguments[0] {
	case "health":
		flags := flag.NewFlagSet("antiflockctl health", flag.ContinueOnError)
		flags.SetOutput(stderr)
		baseURL := flags.String("url", "", "AntiFlock Core base URL")
		timeout := flags.Duration("timeout", 3*time.Second, "health request timeout")
		if err := flags.Parse(arguments[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 || *timeout < 100*time.Millisecond || *timeout > 30*time.Second {
			fmt.Fprintln(stderr, "health requires no positional arguments and a timeout from 100ms through 30s")
			return 2
		}
		endpoint, err := validateHealthURL(*baseURL)
		if err != nil {
			fmt.Fprintf(stderr, "invalid Core URL: %v\n", err)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		client := &http.Client{
			Timeout: *timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		if err := checkHealth(ctx, client, endpoint); err != nil {
			fmt.Fprintf(stderr, "Core health check failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "alive")
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", arguments[0])
		return 2
	}
}

func validateHealthURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > 2048 {
		return nil, errors.New("a bounded absolute URL is required")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, errors.New("a valid absolute URL is required")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return nil, errors.New("credentials, query, fragment, and base paths are not allowed")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("port is invalid")
		}
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, errors.New("host is required")
	}
	if parsed.Scheme == "http" {
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || (!ip.IsLoopback() && !ip.IsPrivate())) {
			return nil, errors.New("plain HTTP is limited to loopback or private IP addresses")
		}
	}
	parsed.Path = "/healthz"
	return parsed, nil
}

func checkHealth(ctx context.Context, client *http.Client, endpoint *url.URL) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("health response is not application/json")
	}
	limited := io.LimitReader(response.Body, maximumHealthBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) > maximumHealthBody {
		return errors.New("health response exceeds 4096 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("health response JSON is invalid")
	}
	status, seenStatus := "", false
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != "status" || seenStatus {
			return errors.New("health response must contain exactly one lowercase status field")
		}
		if err := decoder.Decode(&status); err != nil {
			return errors.New("health response status is invalid")
		}
		seenStatus = true
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || !seenStatus {
		return errors.New("health response JSON is invalid")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("health response contains trailing JSON")
	}
	if status != "alive" {
		return fmt.Errorf("unexpected health status %q", status)
	}
	return nil
}
