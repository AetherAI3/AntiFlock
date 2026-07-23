package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/config"
	"github.com/DBarr3/AntiFlock/core/enrollment"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/core/findings"
	"github.com/DBarr3/AntiFlock/core/identity"
	"github.com/DBarr3/AntiFlock/core/policy"
	"github.com/DBarr3/AntiFlock/core/posture"
	"github.com/DBarr3/AntiFlock/core/scrambler"
	"github.com/DBarr3/AntiFlock/core/server"
	"github.com/DBarr3/AntiFlock/core/storage"
)

var (
	version = "development"
	commit  = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	command := "serve"
	if len(arguments) != 0 && !strings.HasPrefix(arguments[0], "-") {
		command, arguments = arguments[0], arguments[1:]
	}
	switch command {
	case "version":
		fmt.Printf("antiflock-core %s (%s)\n", version, commit)
		return 0
	case "serve":
		if err := serve(arguments); err != nil {
			slog.Error("Core stopped", "error", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		return 2
	}
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("antiflock-core serve", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to the Core YAML configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	operatorToken, err := loadToken("ANTIFLOCK_OPERATOR_TOKEN", "ANTIFLOCK_OPERATOR_TOKEN_FILE", "ANTIFLOCK_API_TOKEN", "ANTIFLOCK_API_TOKEN_FILE")
	if err != nil {
		return err
	}
	sdkToken, err := loadToken("ANTIFLOCK_SDK_TOKEN", "ANTIFLOCK_SDK_TOKEN_FILE", "", "")
	if err != nil {
		return err
	}
	agentToken, err := loadOptionalToken("ANTIFLOCK_AGENT_TOKEN", "ANTIFLOCK_AGENT_TOKEN_FILE")
	if err != nil {
		return err
	}
	sdkApplicationID := strings.TrimSpace(os.Getenv("ANTIFLOCK_SDK_APPLICATION_ID"))
	sdkNodeID := strings.TrimSpace(os.Getenv("ANTIFLOCK_SDK_NODE_ID"))
	agentNodeID := strings.TrimSpace(os.Getenv("ANTIFLOCK_AGENT_NODE_ID"))
	if sdkApplicationID == "" || sdkNodeID == "" {
		return errors.New("ANTIFLOCK_SDK_APPLICATION_ID and ANTIFLOCK_SDK_NODE_ID are required")
	}
	if agentToken != "" && agentNodeID == "" {
		return errors.New("ANTIFLOCK_AGENT_NODE_ID is required when ANTIFLOCK_AGENT_TOKEN is configured")
	}
	now := time.Now().UTC()
	authority, err := identity.Ensure(configuration.Identity.StateDirectory, now)
	if err != nil {
		return fmt.Errorf("initialize deployment identity: %w", err)
	}
	if authority.CACert == nil || now.Before(authority.CACert.NotBefore) || !now.Before(authority.CACert.NotAfter) {
		return errors.New("deployment certificate authority is outside its validity window")
	}
	database, err := storage.Open(context.Background(), configuration.Storage.Path)
	if err != nil {
		return err
	}
	defer database.Close()
	auditService, err := audit.NewWithKeyring(
		database, authority.AuditPrivateKey(), authority.HistoricalAuditPublicKeys(), authority.AuditAnchorPath(),
	)
	if err != nil {
		return fmt.Errorf("initialize audit journal: %w", err)
	}
	eventStore, err := events.New(database, authority)
	if err != nil {
		return fmt.Errorf("initialize event store: %w", err)
	}
	enrollmentService := enrollment.New(database, authority, auditService, configuration.Identity.EnrollmentTokenTTL)
	policySeed := sha256.Sum256(append([]byte("AntiFlock-Policy-Signing-v1\x00"), authority.AuditPrivateKey().Seed()...))
	policyKey := ed25519.NewKeyFromSeed(policySeed[:])
	policyKeyDigest := sha256.Sum256(policyKey.Public().(ed25519.PublicKey))
	policyCompiler, err := policy.NewCompiler(
		authority.Deployment.DeploymentID, fmt.Sprintf("policy:%x", policyKeyDigest[:]), policyKey,
	)
	if err != nil {
		return fmt.Errorf("initialize policy compiler: %w", err)
	}
	postureEngine, err := posture.New(configuration.Protection.TelemetryStaleAfter)
	if err != nil {
		return fmt.Errorf("initialize posture engine: %w", err)
	}
	findingService, err := findings.New(authority.Deployment.DeploymentID)
	if err != nil {
		return fmt.Errorf("initialize finding projection: %w", err)
	}
	scramblerPlanner, err := scrambler.New(5 * time.Minute)
	if err != nil {
		return fmt.Errorf("initialize Scrambler planner: %w", err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(authority.CACert)
	host, _, _ := net.SplitHostPort(configuration.Server.Listen)
	listenIP := net.ParseIP(host)
	demoInsecurePrivateHTTP := configuration.DemoInsecurePrivateHTTP()
	requireAgentMTLS := (listenIP == nil || !listenIP.IsLoopback()) && !demoInsecurePrivateHTTP
	if demoInsecurePrivateHTTP {
		slog.Warn("DEMO SECURITY EXCEPTION ACTIVE: Core private HTTP and bearer-only agent ingestion are enabled",
			"listen", configuration.Server.Listen, "productionSafe", false)
	}
	credentials := []server.Credential{
		{Token: operatorToken, PrincipalID: authority.Deployment.OperatorID, Scopes: []string{server.ScopeDashboardRead, server.ScopeOperatorMutate, server.ScopeEnrollmentAdmin, server.ScopeActionsAuthorize}},
		{Token: sdkToken, PrincipalID: "application:" + sdkApplicationID, ApplicationID: sdkApplicationID, NodeID: sdkNodeID, Scopes: []string{server.ScopeActionsExecute}},
	}
	if agentToken != "" {
		credentials = append(credentials, server.Credential{Token: agentToken, PrincipalID: "node:" + agentNodeID, NodeID: agentNodeID, Scopes: []string{server.ScopeAgentIngest}, RequireMTLS: requireAgentMTLS})
	}
	coreServer, err := server.New(server.Options{
		Config: configuration, Database: database, Events: eventStore, Audit: auditService,
		Enrollment: enrollmentService, DeploymentID: authority.Deployment.DeploymentID,
		PolicyCompiler: policyCompiler, PostureEngine: postureEngine,
		Findings: findingService, Scrambler: scramblerPlanner, Credentials: credentials,
		AuthorizationKey: []byte(sdkToken), NodeClientCAs: clientCAs, Version: version,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	retentionDone := make(chan struct{})
	go func() {
		defer close(retentionDone)
		runEventRetention(ctx, database, configuration.Storage.EventRetention, slog.Default())
	}()
	slog.Info("AntiFlock Core ready", "listen", configuration.Server.Listen, "deployment", authority.Deployment.DeploymentID, "version", version)
	serveErr := coreServer.Serve(ctx)
	stop()
	<-retentionDone
	return serveErr
}


func loadOptionalToken(environmentName, fileEnvironmentName string) (string, error) {
	if os.Getenv(environmentName) == "" && os.Getenv(fileEnvironmentName) == "" {
		return "", nil
	}
	return loadToken(environmentName, fileEnvironmentName, "", "")
}

func loadToken(environmentName, fileEnvironmentName, legacyName, legacyFileName string) (string, error) {
	if token := os.Getenv(environmentName); token != "" {
		if len(token) < 32 {
			return "", fmt.Errorf("%s must contain at least 32 bytes", environmentName)
		}
		return token, nil
	}
	if legacyName != "" {
		if token := os.Getenv(legacyName); token != "" {
			if len(token) < 32 {
				return "", fmt.Errorf("%s must contain at least 32 bytes", legacyName)
			}
			return token, nil
		}
	}
	path := os.Getenv(fileEnvironmentName)
	if path == "" && legacyFileName != "" {
		path = os.Getenv(legacyFileName)
	}
	if path == "" {
		return "", fmt.Errorf("%s or %s is required", environmentName, fileEnvironmentName)
	}
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read API token file: %w", err)
	}
	token := strings.TrimSpace(string(content))
	if token == "" {
		return "", errors.New("API token file is empty")
	}
	if len(token) < 32 {
		return "", errors.New("credential token file must contain at least 32 bytes")
	}
	return token, nil
}
