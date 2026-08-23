package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/DBarr3/AntiFlock/agent/enforcement"
)

type driverAvailability struct {
	Domain     string `json:"domain"`
	Available  bool   `json:"available"`
	ReasonCode string `json:"reasonCode"`
	Detail     string `json:"detail"`
}

type planVerificationOutput struct {
	*enforcement.PlanVerification
	Mode    string               `json:"mode"`
	Drivers []driverAvailability `json:"drivers"`
}

func runPlan(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if ctx == nil || stdout == nil || stderr == nil {
		return errors.New("plan context and output streams are required")
	}
	if len(arguments) == 0 || arguments[0] != "verify" {
		return errors.New("unknown plan command; use plan verify")
	}
	return runPlanVerify(arguments[1:], stdout, stderr)
}

func runPlanVerify(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("antiflock-agent plan verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planFile := flags.String("plan", "", "bounded signed plan JSON file")
	deploymentID := flags.String("deployment-id", "", "expected AntiFlock deployment id")
	nodeID := flags.String("node-id", "", "expected enrolled node id")
	planKeyID := flags.String("plan-key-id", "", "expected Core policy signing key id")
	planPublicKey := flags.String("plan-public-key", "", "pinned Ed25519 policy public key PEM")
	capabilitiesFile := flags.String("capabilities", "", "node-bound capability manifest JSON file")
	format := flags.String("format", "json", "output format: json or human")
	compact := flags.Bool("compact", false, "write compact JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*planFile) == "" || strings.TrimSpace(*deploymentID) == "" ||
		strings.TrimSpace(*nodeID) == "" || strings.TrimSpace(*planKeyID) == "" ||
		strings.TrimSpace(*planPublicKey) == "" || strings.TrimSpace(*capabilitiesFile) == "" {
		return errors.New("plan verify requires plan, deployment-id, node-id, plan-key-id, plan-public-key, and capabilities")
	}
	if *format != "json" && *format != "human" {
		return errors.New("plan verify format must be json or human")
	}
	if *format == "human" && *compact {
		return errors.New("compact is available only with JSON output")
	}
	plan, err := enforcement.LoadPlanJSON(*planFile)
	if err != nil {
		return err
	}
	publicKey, err := enforcement.LoadPlanPublicKey(*planPublicKey)
	if err != nil {
		return err
	}
	capabilities, err := enforcement.LoadCapabilityManifestJSON(*capabilitiesFile)
	if err != nil {
		return err
	}
	verification, err := enforcement.VerifyPlan(enforcement.PlanVerificationConfig{
		DeploymentID: *deploymentID, NodeID: *nodeID, PlanKeyID: *planKeyID,
		PlanPublicKey: publicKey, Capabilities: capabilities,
	}, plan)
	if err != nil {
		return err
	}
	output := planVerificationOutput{
		PlanVerification: verification,
		Mode:             "verify-only-no-host-mutation",
		Drivers:          currentDriverAvailability(),
	}
	if *format == "human" {
		writePlanVerificationHuman(stdout, output)
	} else {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if !*compact {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(output); err != nil {
			return errors.New("write plan verification output")
		}
	}
	if !verification.Valid {
		return fmt.Errorf("plan verification failed: %s", verification.ReasonCode)
	}
	return nil
}

func currentDriverAvailability() []driverAvailability {
	return []driverAvailability{
		{Domain: "firewall", Available: false, ReasonCode: "AF-DRIVER-RECOVERY-INCOMPLETE", Detail: "The nftables adapter is library-only; durable crash recovery and executable wiring are absent."},
		{Domain: "mesh", Available: false, ReasonCode: "AF-DRIVER-UNAVAILABLE", Detail: "No production mesh enforcement driver is installed."},
		{Domain: "route", Available: false, ReasonCode: "AF-DRIVER-UNAVAILABLE", Detail: "No production route enforcement driver is installed."},
		{Domain: "dns", Available: false, ReasonCode: "AF-DRIVER-UNAVAILABLE", Detail: "No production DNS enforcement driver is installed."},
		{Domain: "recovery", Available: false, ReasonCode: "AF-RECOVERY-UNAVAILABLE", Detail: "No independently verified host recovery path is installed."},
	}
}

func writePlanVerificationHuman(writer io.Writer, output planVerificationOutput) {
	fmt.Fprintf(writer, "Plan %s\n", output.PlanID)
	fmt.Fprintf(writer, "  valid: %t\n", output.Valid)
	fmt.Fprintf(writer, "  capability compatible: %t\n", output.CapabilityCompatible)
	fmt.Fprintln(writer, "  executable: false")
	fmt.Fprintf(writer, "  reason: %s\n", output.ReasonCode)
	fmt.Fprintf(writer, "  detail: %s\n", output.SafeMessage)
	if len(output.MissingCapabilities) != 0 {
		fmt.Fprintf(writer, "  missing capabilities: %s\n", strings.Join(output.MissingCapabilities, ", "))
	}
	fmt.Fprintln(writer, "Driver readiness")
	for _, driver := range output.Drivers {
		fmt.Fprintf(writer, "  %s: unavailable (%s) — %s\n", driver.Domain, driver.ReasonCode, driver.Detail)
	}
}
