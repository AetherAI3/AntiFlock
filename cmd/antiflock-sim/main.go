package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DBarr3/AntiFlock/agent/sim"
)

const defaultStart = "2026-07-22T12:00:00Z"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if ctx == nil || stdout == nil || stderr == nil {
		return errors.New("simulator context and output streams are required")
	}
	command := "offline"
	if len(arguments) != 0 && !strings.HasPrefix(arguments[0], "-") {
		command, arguments = arguments[0], arguments[1:]
	}
	switch command {
	case "offline":
		return runOffline(arguments, stdout, stderr)
	case "stream":
		return runStream(ctx, arguments, stdout, stderr)
	case "coffee-shop":
		return runCoffeeShop(ctx, arguments, stdout, stderr)
	default:
		return errors.New("antiflock-sim command must be offline, stream, or coffee-shop")
	}
}

func runOffline(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("antiflock-sim offline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	startValue := flags.String("start", defaultStart, "fixed RFC3339Nano scenario start time")
	compact := flags.Bool("compact", false, "write compact JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("offline simulation accepts flags only")
	}
	start, err := time.Parse(time.RFC3339Nano, *startValue)
	if err != nil {
		return errors.New("start must use RFC3339Nano")
	}
	result, err := sim.RunCoffeeShop(start)
	if err != nil {
		return fmt.Errorf("run offline coffee-shop simulation: %w", err)
	}
	return encodeJSON(stdout, result, *compact)
}

func runStream(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("antiflock-sim stream", flag.ContinueOnError)
	flags.SetOutput(stderr)
	coreURL := flags.String("core", "", "Core HTTP(S) origin (non-secret; defaults to ANTIFLOCK_CORE_URL)")
	interval := flags.Duration("interval", 30*time.Second, "signed heartbeat interval")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *interval < time.Second {
		return errors.New("stream accepts flags only and requires interval >= 1s")
	}
	config, err := liveConfigFromEnvironment(*coreURL)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return sim.RunLiveStream(ctx, config, *interval, func(event sim.LiveStreamEvent) error {
		if err := encoder.Encode(event); err != nil {
			return errors.New("write simulator stream status")
		}
		return nil
	})
}

func runCoffeeShop(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("antiflock-sim coffee-shop", flag.ContinueOnError)
	flags.SetOutput(stderr)
	coreURL := flags.String("core", "", "Core HTTP(S) origin (non-secret; defaults to ANTIFLOCK_CORE_URL)")
	verify := flags.Bool("verify", false, "require durable Core readback and audit replay")
	compact := flags.Bool("compact", false, "write compact JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("coffee-shop accepts flags only")
	}
	config, err := liveConfigFromEnvironment(*coreURL)
	if err != nil {
		return err
	}
	result, err := sim.RunLiveCoffeeShop(ctx, config, *verify)
	if err != nil {
		return err
	}
	return encodeJSON(stdout, result, *compact)
}

func liveConfigFromEnvironment(coreOverride string) (sim.LiveConfig, error) {
	coreURL := coreOverride
	if coreURL == "" {
		coreURL = os.Getenv("ANTIFLOCK_CORE_URL")
	}
	operatorToken, err := secretFromEnvironment("ANTIFLOCK_OPERATOR_TOKEN")
	if err != nil {
		return sim.LiveConfig{}, err
	}
	agentToken, err := secretFromEnvironment("ANTIFLOCK_AGENT_TOKEN")
	if err != nil {
		return sim.LiveConfig{}, err
	}
	sdkToken, err := secretFromEnvironment("ANTIFLOCK_SDK_TOKEN")
	if err != nil {
		return sim.LiveConfig{}, err
	}
	demoMode, err := parseBooleanEnvironment("ANTIFLOCK_DEMO_MODE")
	if err != nil {
		return sim.LiveConfig{}, err
	}
	return sim.LiveConfig{
		CoreURL: coreURL, OperatorToken: operatorToken, AgentToken: agentToken, SDKToken: sdkToken,
		NodeID: os.Getenv("ANTIFLOCK_SIM_NODE_ID"), ApplicationID: os.Getenv("ANTIFLOCK_SIM_APPLICATION_ID"),
		StateDirectory: os.Getenv("ANTIFLOCK_SIM_STATE_DIR"), BootID: os.Getenv("ANTIFLOCK_SIM_BOOT_ID"),
		DemoMode: demoMode,
	}, nil
}

func secretFromEnvironment(name string) (string, error) {
	direct := os.Getenv(name)
	filePath := os.Getenv(name + "_FILE")
	if direct != "" && filePath != "" {
		return "", fmt.Errorf("%s and %s_FILE cannot both be set", name, name)
	}
	if direct != "" {
		if strings.TrimSpace(direct) != direct {
			return "", fmt.Errorf("%s contains surrounding whitespace", name)
		}
		return direct, nil
	}
	if filePath == "" {
		return "", fmt.Errorf("%s or %s_FILE is required", name, name)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE", name)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(content) > 64<<10 {
		return "", fmt.Errorf("read %s_FILE", name)
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(content), "\n"), "\r")
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%s_FILE contains an invalid credential", name)
	}
	return value, nil
}

func parseBooleanEnvironment(name string) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func encodeJSON(output io.Writer, value any, compact bool) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if !compact {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(value); err != nil {
		return errors.New("write simulator result")
	}
	return nil
}
