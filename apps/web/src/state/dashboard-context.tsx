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
  refresh: () => Promise<void>;
  updateConnectionSettings: (apiBase: string, demoFallback: boolean) => void;
  replayCoffeeShop: () => void;
  restoreShield: () => void;
  sendOnce: () => Promise<void>;
  simulateScrambler: () => Promise<void>;
  activateScrambler: () => Promise<void>;
  validatePolicy: () => Promise<void>;
  createEnrollmentToken: () => Promise<void>;
  clearFeedback: () => void;
}

const DashboardContext = createContext<DashboardContextValue | null>(null);

const DEFAULT_API_BASE = process.env.NEXT_PUBLIC_ANTIFLOCK_API_URL ?? "";

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
  const scenarioTimers = useRef<number[]>([]);
  const refreshTimer = useRef<number | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const storedBase = window.localStorage.getItem("antiflock.apiBase");
      const storedFallback = window.localStorage.getItem("antiflock.demoFallback");
      if (storedBase !== null) setApiBase(storedBase);
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
    clearScenarioTimers();
    transitionScenario("restoring");
    scenarioTimers.current = [
      window.setTimeout(() => transitionScenario("recovered"), 1_900),
    ];
  }, [clearScenarioTimers, transitionScenario]);

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

  const sendOnce = useCallback(async () => runCommand(
    "send-once",
    COMMAND_ENDPOINTS.authorizeAction(data.actions[0]?.id ?? "unknown"),
    { scope: "one-action", expires_in: "5m", destination: data.actions[0]?.destination },
    () => transitionScenario("bypassed"),
    "A one-action, five-minute exception was authorized and written to the audit trail.",
  ), [data.actions, runCommand, transitionScenario]);

  const simulateScrambler = useCallback(async () => runCommand(
    "scrambler-simulate",
    COMMAND_ENDPOINTS.simulateScrambler,
    { profile: data.scrambler.profile, apply: false },
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
  ), [data.scrambler.profile, runCommand]);

  const activateScrambler = useCallback(async () => runCommand(
    "scrambler-activate",
    COMMAND_ENDPOINTS.activateScrambler,
    { profile: data.scrambler.profile, candidate_exit: data.scrambler.proposedExit },
    () => setCommandFeedback({ kind: "info", message: "Demo activation remains simulation-only; no route was changed." }),
    "Scrambler activation was accepted. Transition verification is in progress.",
  ), [data.scrambler.profile, data.scrambler.proposedExit, runCommand]);

  const validatePolicy = useCallback(async () => runCommand(
    "policy-validate",
    COMMAND_ENDPOINTS.validatePolicy,
    { policy_id: data.policies[0]?.id, revision: data.policies[0]?.revision, dry_run: true },
    () => undefined,
    "Shielded policy validation passed for the current capability set.",
  ), [data.policies, runCommand]);

  const createEnrollmentToken = useCallback(async () => runCommand(
    "enrollment-token",
    COMMAND_ENDPOINTS.enrollmentToken,
    { expires_in: "10m", single_use: true },
    () => undefined,
    "A single-use enrollment token was created with a ten-minute expiry.",
  ), [runCommand]);

  const updateConnectionSettings = useCallback((nextApiBase: string, nextDemoFallback: boolean) => {
    const normalized = nextApiBase.trim().replace(/\/$/, "");
    window.localStorage.setItem("antiflock.apiBase", normalized);
    window.localStorage.setItem("antiflock.demoFallback", String(nextDemoFallback));
    setApiBase(normalized);
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
    refresh,
    updateConnectionSettings,
    replayCoffeeShop,
    restoreShield,
    sendOnce,
    simulateScrambler,
    activateScrambler,
    validatePolicy,
    createEnrollmentToken,
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
    refresh,
    updateConnectionSettings,
    replayCoffeeShop,
    restoreShield,
    sendOnce,
    simulateScrambler,
    activateScrambler,
    validatePolicy,
    createEnrollmentToken,
  ]);

  return <DashboardContext.Provider value={value}>{children}</DashboardContext.Provider>;
}

export function useDashboard(): DashboardContextValue {
  const value = useContext(DashboardContext);
  if (!value) throw new Error("useDashboard must be used inside DashboardProvider");
  return value;
}
