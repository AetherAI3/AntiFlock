package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"runtime"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	"github.com/DBarr3/AntiFlock/internal/agentcli"
)

func runCaptureRotation(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("antiflock-agent capture-rotation", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", agentcli.DefaultConfigPath, "enrolled route observer config")
	intentPath := flags.String("intent", "", "owner-signed rotation intent file")
	ownerID := flags.String("owner-id", "", "enrolled Predator owner id")
	workloadID := flags.String("workload-id", "", "enrolled Predator workload id")
	intentKey := flags.String("intent-public-key", "", "pinned owner Ed25519 public key in lowercase hex")
	output := flags.String("output", "", "new private native protobuf capture file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || flags.NArg() != 0 || *intentPath == "" || *ownerID == "" || *workloadID == "" || *output == "" {
		return errors.New("capture-rotation requires Linux, intent, owner-id, workload-id, intent-public-key, and output")
	}
	key, err := hex.DecodeString(*intentKey)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != *intentKey {
		return errors.New("capture requires a canonical owner public key pin")
	}
	return captureRotation(ctx, *configPath, *intentPath, *output, collectors.RotationEnrollment{
		OwnerID: *ownerID, WorkloadID: *workloadID, IntentPublicKey: key,
	}, stdout)
}
