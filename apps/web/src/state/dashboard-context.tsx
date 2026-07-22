"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { DashboardData } from "../api/contracts";
import {
  COMMAND_ENDPOINTS,
  loadDashboard,
  openLiveStream,
  postCommand,
} from "../api/client";
import { createDemoData } from "../test-fixtures/demo";
import {
  dataForScenario,
  initialScenario,
  scenarioState,
  type ScenarioState,
} from "./scenario";

export type DataMode = "checking" | "live" | "partial" | "demo" | "error";
export type StreamStatus = "idle" | "connecting" | "connected" | "reconnecting" | "unsupported" | "simulated";

interface CommandFeedback {
  kind: "success" | "error" | "info";
  message: string;
}

interface EnrollmentSecret {
  tokenValue: string;
  expiresAt: string;
}

interface DashboardContextValue {
  data: DashboardData;
  mode: DataMode;
  streamStatus: StreamStatus;
  isLoading: boolean;
  error: string | null;
  failedEndpoints: string[];
  lastRefresh: string | null;
  apiBase: string;
  demoFallback: boolean;
  scenario: ScenarioState;
  commandFeedback: CommandFeedback | null;
  pendingCommand: string | null;
  enrollmentSecret: EnrollmentSecret | null;
  refresh: () => Promise<void>;
  updateConnectionSettings: (apiBase: string, demoFallback: boolean) => void;
  replayCoffeeShop: () => void;
  restoreShield: () => void;
  sendOnce: (actionId: string) => Promise<void>;
  simulateScrambler: () => Promise<void>;
  activateScrambler: () => Promise<void>;
  validatePolicy: () => Promise<void>;
  createEnrollmentToken: () => Promise<void>;
  clearEnrollmentSecret: () => void;
  clearFeedback: () => void;
}

const DashboardContext = createContext<DashboardContextValue | null>(null);

const DEFAULT_API_BASE = "";

function operationId(prefix: string): string {
  return `${prefix}-${globalThis.crypto.randomUUID()}`;
}

function policyValidationRequest(data: DashboardData): unknown {
  const profile = data.policies.find((candidate) => candidate.status === "active") ?? data.policies[0];
  const currentExit = data.scrambler.currentExit && !data.scrambler.currentExit.toLowerCase().includes("not reported")
    ? data.scrambler.currentExit
    : "home-gateway";
  const resolver = data.overview.dnsResolver && !data.overview.dnsResolver.toLowerCase().includes("not reported")
    ? data.overview.dnsResolver
    : "resolver.internal";
  return {
    profile: {
      metadata: { id: profile?.id ?? "policy-shielded", revision: String(profile?.revision ?? 1) },
      apiVersion: "antiflock.policy/v1",
      mode: "PROTECTION_MODE_GUARD",
      mesh: { required: true, provider: "tailscale" },
      egress: {
        mode: "EGRESS_MODE_TRUSTED_EXIT",
        failMode: "FAIL_MODE_CLOSED",
        allowedExitNodeIds: [currentExit],
        recoveryDestinations: ["core.internal"],
      },
      dns: { mode: "DNS_MODE_PROTECTED", allowedResolvers: [resolver], requirePathVerification: true },
      networks: {
        requireMeshOnUntrusted: true,
        untrustedNetworkBypass: "BYPASS_MODE_ONE_TIME",
        blockOpenWifiWithoutMesh: true,
      },
      actions: [{
        dataClasses: ["repository-source"],
        applicationIds: ["aether-code"],
        requireProtectedState: true,
        bypassMode: "BYPASS_MODE_ONE_TIME",
      }],
      telemetry: { flowMetadata: true, payloadCapture: false, retentionDays: 14 },
      scrambler: { enabled: false },
    },
  };
}

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<DashboardData>(() => createDemoData("EXPOSED"));
  const [mode, setMode] = useState<DataMode>("checking");
  const [streamStatus, setStreamStatus] = useState<StreamStatus>("idle");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [failedEndpoints, setFailedEndpoints] = useState<string[]>([]);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [apiBase, setApiBase] = useState(DEFAULT_API_BASE);
  const [demoFallback, setDemoFallback] = useState(true);
  const [scenario, setScenario] = useState<ScenarioState>(initialScenario);
  const [commandFeedback, setCommandFeedback] = useState<CommandFeedback | null>(null);
  const [pendingCommand, setPendingCommand] = useState<string | null>(null);
  const [enrollmentSecret, setEnrollmentSecret] = useState<EnrollmentSecret | null>(null);
  const scenarioTimers = useRef<number[]>([]);
  const refreshTimer = useRef<number | null>(null);
  const enrollmentTimer = useRef<number | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const storedFallback = window.localStorage.getItem("antiflock.demoFallback");
      window.localStorage.removeItem("antiflock.apiBase");
      if (storedFallback !== null) setDemoFallback(storedFallback !== "false");
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5_000);
    try {
      const result = await loadDashboard(apiBase, controller.signal);
      setData(result.data);
      setMode(result.mode);
      setFailedEndpoints(result.failedEndpoints);
      setLastRefresh(new Date().toISOString());
      setScenario(scenarioState(result.data.posture.state === "PROTECTED" ? "recovered" : "exposed"));
    } catch (reason) {
      const message = reason instanceof Error && reason.name !== "AbortError"
        ? reason.message
        : "AntiFlock Core did not respond before the local timeout.";
      setError(message);
      setFailedEndpoints([]);
      if (demoFallback) {
        setData(createDemoData("EXPOSED"));
        setMode("demo");
        setStreamStatus("simulated");
        setScenario(initialScenario);
      } else {
        setMode("error");
        setStreamStatus("idle");
      }
    } finally {
      window.clearTimeout(timeout);
      setIsLoading(false);
    }
  }, [apiBase, demoFallback]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  useEffect(() => {
    if (mode !== "live" && mode !== "partial") return undefined;
    const onEnvelope = () => {
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current);
      refreshTimer.current = window.setTimeout(() => void refresh(), 180);
    };
    const close = openLiveStream(apiBase, onEnvelope, setStreamStatus);
    return () => {
      close();
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current);
    };
  }, [apiBase, mode, refresh]);

  useEffect(() => () => {
    scenarioTimers.current.forEach((timer) => window.clearTimeout(timer));
    if (enrollmentTimer.current !== null) window.clearTimeout(enrollmentTimer.current);
  }, []);

  const clearScenarioTimers = useCallback(() => {
    scenarioTimers.current.forEach((timer) => window.clearTimeout(timer));
    scenarioTimers.current = [];
  }, []);

  const transitionScenario = useCallback((stage: ScenarioState["stage"]) => {
    setData((previous) => dataForScenario(stage, previous));
    setScenario(scenarioState(stage));
  }, []);

  const replayCoffeeShop = useCallback(() => {
    clearScenarioTimers();
    setMode("demo");
    setStreamStatus("simulated");
    setError("Replay uses deterministic local fixtures; it is not live telemetry.");
    transitionScenario("protected");
    scenarioTimers.current = [
      window.setTimeout(() => transitionScenario("joining"), 550),
      window.setTimeout(() => transitionScenario("verifying"), 1_250),
      window.setTimeout(() => transitionScenario("exposed"), 2_150),
    ];
  }, [clearScenarioTimers, transitionScenario]);

  const restoreShield = useCallback(() => {
    if (mode !== "demo") {
      setCommandFeedback({
        kind: "info",
        message: "Route restoration is performed by the endpoint agent. The dashboard requested fresh verified telemetry; it did not change network state.",
      });
      void refresh();
      return;
    }
    clearScenarioTimers();
    transitionScenario("restoring");
    scenarioTimers.current = [
      window.setTimeout(() => transitionScenario("recovered"), 1_900),
    ];
  }, [clearScenarioTimers, mode, refresh, transitionScenario]);

  const runCommand = useCallback(async (
    label: string,
    path: string,
    body: unknown,
    demoAction: () => void,
    successMessage: string,
  ) => {
    setPendingCommand(label);
    setCommandFeedback(null);
    try {
      if (mode === "demo" || mode === "checking") {
        demoAction();
        setCommandFeedback({ kind: "info", message: `${successMessage} Demo mode changed local fixtures only.` });
      } else {
        await postCommand(apiBase, path, body);
        setCommandFeedback({ kind: "success", message: successMessage });
        await refresh();
      }
    } catch (reason) {
      setCommandFeedback({
        kind: "error",
        message: reason instanceof Error ? `Command failed: ${reason.message}` : "Command failed without an error message.",
      });
    } finally {
      setPendingCommand(null);
    }
  }, [apiBase, mode, refresh]);

  const sendOnce = useCallback(async (actionId: string) => {
    const action = data.actions.find((candidate) => candidate.id === actionId);
    if (!action) {
      setCommandFeedback({ kind: "error", message: "The selected held action is no longer available." });
      return;
    }
    const authorization = action.oneTimeAuthorization;
    if (mode !== "demo" && (!authorization?.enabled || !authorization.maximumExpiresAt || !action.operationId || !action.destinations.length)) {
      setCommandFeedback({ kind: "error", message: "Core did not offer a complete, bounded one-time authorization for this action." });
      return;
    }
    await runCommand(
      "send-once",
      COMMAND_ENDPOINTS.authorizeAction(action.id),
      {
        actionId: action.id,
        operationId: action.operationId,
        authorizedDestinations: action.destinations,
        expiresAt: authorization?.maximumExpiresAt,
        consentReasonCode: authorization?.consentReasonCode || "USER_EXPLICIT",
      },
      () => transitionScenario("bypassed"),
      "A bounded exception for this action was authorized and written to the audit trail.",
    );
  }, [data.actions, mode, runCommand, transitionScenario]);

  const simulateScrambler = useCallback(async () => runCommand(
    "scrambler-simulate",
    COMMAND_ENDPOINTS.simulateScrambler,
    {
      nodeId: data.nodes[0]?.id,
      operationId: operationId("scrambler-simulate"),
      constraints: {
        allowedDimensions: ["SCRAMBLER_DIMENSION_EXIT_NODE", "SCRAMBLER_DIMENSION_DNS_PROFILE"],
        approvedExitNodeIds: [data.scrambler.proposedExit ?? data.scrambler.currentExit],
        approvedDnsProfileIds: [data.overview.dnsResolver],
        requiredDestinations: ["core.internal"],
        maximumTransitionLatency: "30s",
        operatorConsentRequired: true,
      },
    },
    () => setData((previous) => ({
      ...previous,
      scrambler: {
        ...previous.scrambler,
        state: "PREFLIGHT",
        simulationOnly: true,
        proposedExit: "home-gateway-backup · iad",
        checks: previous.scrambler.checks.map((check) => ({ ...check, state: check.state === "fail" ? "fail" : "pass" })),
      },
    })),
    "Scrambler preflight simulation completed. No network state was changed.",
  ), [data.nodes, data.overview.dnsResolver, data.scrambler.currentExit, data.scrambler.proposedExit, runCommand]);

  const activateScrambler = useCallback(async () => {
    setCommandFeedback({
      kind: "info",
      message: "Scrambler activation is outside this release boundary. Simulation did not change route or DNS state.",
    });
  }, []);

  const validatePolicy = useCallback(async () => runCommand(
    "policy-validate",
    COMMAND_ENDPOINTS.validatePolicy,
    policyValidationRequest(data),
    () => undefined,
    "The policy contract was validated. No plan was compiled or applied.",
  ), [data, runCommand]);

  const createEnrollmentToken = useCallback(async () => {
    if (mode === "demo" || mode === "checking") {
      setCommandFeedback({ kind: "info", message: "Demo mode cannot issue enrollment credentials. Connect to a private Core deployment first." });
      return;
    }
    setPendingCommand("enrollment-token");
    setCommandFeedback(null);
    try {
      const result = await postCommand<{ tokenValue?: unknown; token?: { expiresAt?: unknown } }>(
        apiBase,
        COMMAND_ENDPOINTS.enrollmentToken,
        {
          allowedNodeType: "NODE_TYPE_AGENT",
          allowedTags: ["operator-approved"],
          operationId: operationId("enrollment-token"),
        },
      );
      if (typeof result.tokenValue !== "string" || !result.tokenValue.startsWith("af_enroll_v1.") || typeof result.token?.expiresAt !== "string") {
        throw new Error("Core returned an invalid enrollment credential response.");
      }
      setEnrollmentSecret({ tokenValue: result.tokenValue, expiresAt: result.token.expiresAt });
      if (enrollmentTimer.current !== null) window.clearTimeout(enrollmentTimer.current);
      const remaining = Math.max(0, Math.min(15 * 60_000, Date.parse(result.token.expiresAt) - Date.now()));
      enrollmentTimer.current = window.setTimeout(() => setEnrollmentSecret(null), remaining);
      setCommandFeedback({ kind: "success", message: "A single-use enrollment token was created. Copy it now; this dashboard does not persist it." });
    } catch (reason) {
      setCommandFeedback({
        kind: "error",
        message: reason instanceof Error ? `Command failed: ${reason.message}` : "Enrollment token creation failed.",
      });
    } finally {
      setPendingCommand(null);
    }
  }, [apiBase, mode]);

  const clearEnrollmentSecret = useCallback(() => {
    if (enrollmentTimer.current !== null) window.clearTimeout(enrollmentTimer.current);
    enrollmentTimer.current = null;
    setEnrollmentSecret(null);
  }, []);

  const updateConnectionSettings = useCallback((nextApiBase: string, nextDemoFallback: boolean) => {
    if (nextApiBase.trim() !== "") {
      setCommandFeedback({ kind: "error", message: "Direct browser Core origins are unsupported. Use the authenticated same-origin private proxy." });
      return;
    }
    window.localStorage.removeItem("antiflock.apiBase");
    window.localStorage.setItem("antiflock.demoFallback", String(nextDemoFallback));
    setApiBase("");
    setDemoFallback(nextDemoFallback);
    setCommandFeedback({ kind: "success", message: "Connection settings saved. Dashboard projections will be reloaded." });
  }, []);

  const value = useMemo<DashboardContextValue>(() => ({
    data,
    mode,
    streamStatus,
    isLoading,
    error,
    failedEndpoints,
    lastRefresh,
    apiBase,
    demoFallback,
    scenario,
    commandFeedback,
    pendingCommand,
    enrollmentSecret,
    refresh,
    updateConnectionSettings,
    replayCoffeeShop,
    restoreShield,
    sendOnce,
    simulateScrambler,
    activateScrambler,
    validatePolicy,
    createEnrollmentToken,
    clearEnrollmentSecret,
    clearFeedback: () => setCommandFeedback(null),
  }), [
    data,
    mode,
    streamStatus,
    isLoading,
    error,
    failedEndpoints,
    lastRefresh,
    apiBase,
    demoFallback,
    scenario,
    commandFeedback,
    pendingCommand,
    enrollmentSecret,
    refresh,
    updateConnectionSettings,
    replayCoffeeShop,
    restoreShield,
    sendOnce,
    simulateScrambler,
    activateScrambler,
    validatePolicy,
    createEnrollmentToken,
    clearEnrollmentSecret,
  ]);

  return <DashboardContext.Provider value={value}>{children}</DashboardContext.Provider>;
}

export function useDashboard(): DashboardContextValue {
  const value = useContext(DashboardContext);
  if (!value) throw new Error("useDashboard must be used inside DashboardProvider");
  return value;
}
