import { join } from "node:path";
import { createAdmissionRuntime, type AdmissionRuntime } from "../admission/runtime.js";
import { AdmissionTurnCoordinator } from "../admission/turn-coordinator.js";
import type { AgyAdmissionDispatchBoundary } from "../admission/dispatch-boundary.js";

export function officialAdmissionStateDir(stateDir: string): string {
  return join(stateDir, "official-kernel");
}

export function isAdmissionDiscoveryEnvironment(environment: NodeJS.ProcessEnv): boolean {
  const enabled = environment.AGY_ACP_ADMISSION_ENABLED;
  const agentId = environment.PASEO_AGENT_ID;
  return (
    (enabled === "1" || enabled === "true") &&
    (agentId === undefined || agentId.length === 0)
  );
}

export function issueAdmittedOfficialPromptWrite(
  boundary: AgyAdmissionDispatchBoundary,
  processId: number,
  write: () => void
): void {
  boundary.prepare(processId);
  boundary.commitDispatchIntent();
  boundary.beforePromptWrite();
  try {
    write();
  } catch (error) {
    boundary.markDispatchAmbiguous();
    throw error;
  }
  boundary.afterPromptWrite();
}

export function createOfficialAdmission(
  environment: NodeJS.ProcessEnv
): { runtime: AdmissionRuntime; coordinator: AdmissionTurnCoordinator } | undefined {
  if (isAdmissionDiscoveryEnvironment(environment)) return undefined;
  const enabled = environment.AGY_ACP_ADMISSION_ENABLED;
  if (enabled !== "1" && enabled !== "true") return undefined;
  const parentStateDir = environment.AGY_ACP_STATE_DIR;
  const isolated: NodeJS.ProcessEnv = {
    ...environment,
    AGY_ACP_STATE_DIR:
      parentStateDir && parentStateDir.length > 0
        ? officialAdmissionStateDir(parentStateDir)
        : parentStateDir
  };
  const runtime = createAdmissionRuntime(isolated);
  if (runtime === null) return undefined;
  return {
    runtime,
    coordinator: new AdmissionTurnCoordinator({
      controller: runtime.controller,
      agentId: isolated.PASEO_AGENT_ID,
      processEvidence: runtime.processEvidence
    })
  };
}
