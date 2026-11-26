package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	agentruntime "github.com/DBarr3/AntiFlock/agent/runtime"
	"github.com/DBarr3/AntiFlock/internal/agentcli"
	"google.golang.org/protobuf/proto"
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
	if err := checkCaptureDestination(*output); err != nil {
		return err
	}
	config, _, err := agentcli.LoadConfig(*configPath)
	if err != nil {
		return errors.New("capture observer config refused")
	}
	raw, err := readRotationIntentFile(*intentPath)
	if err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return errors.New("read kernel boot identity")
	}
	bootID := strings.TrimSpace(string(boot))
	if len(bootID) != 36 {
		return errors.New("kernel boot identity refused")
	}
	signer, err := agentruntime.LoadFileSigner(config.NodeID, config.KeyPath(), nil)
	if err != nil {
		return err
	}
	queue, err := agentruntime.OpenQueue(config.QueueDir, config.NodeID)
	if err != nil {
		return err
	}
	defer queue.Close()
	builder, err := collectors.NewTelemetryBuilder(config.DeploymentID, config.NodeID, bootID, queue, signer, nil)
	if err != nil {
		return err
	}
	event, err := builder.CaptureRotationRoute(ctx, raw, collectors.RotationEnrollment{
		OwnerID: *ownerID, WorkloadID: *workloadID, IntentPublicKey: key,
	})
	if err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		return errors.New("encode rotation route observation")
	}
	if err := writePrivateCapture(*output, encoded); err != nil {
		return err
	}
	_, err = io.WriteString(stdout, "Private rotation route observation captured\n")
	return err
}

func readRotationIntentFile(path string) ([]byte, error) {
	if err := requirePrivateCaptureDirectory(filepath.Dir(path)); err != nil {
		return nil, errors.New("rotation intent requires a real private directory")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > collectors.MaxRotationIntentBytes {
		return nil, errors.New("rotation intent must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("read rotation intent")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("rotation intent changed before reading")
	}
	raw, err := io.ReadAll(io.LimitReader(file, collectors.MaxRotationIntentBytes+1))
	if err != nil || len(raw) != int(before.Size()) {
		return nil, errors.New("rotation intent changed while reading")
	}
	return raw, nil
}

func checkCaptureDestination(path string) error {
	if err := requirePrivateCaptureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("capture destination must not exist")
	}
	return nil
}

func requirePrivateCaptureDirectory(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("invalid capture destination")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return errors.New("capture requires a real private directory")
	}
	parent, err := os.Lstat(absolute)
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != agentcli.PrivateDirectoryMode {
		return errors.New("capture requires a real private directory")
	}
	return nil
}

func writePrivateCapture(path string, encoded []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".rotation-capture-*")
	if err != nil {
		return errors.New("stage private route capture")
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return errors.New("write private route capture")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync private route capture")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private route capture")
	}
	if err := os.Link(file.Name(), path); err != nil {
		return errors.New("publish new private route capture")
	}
	return nil
}
