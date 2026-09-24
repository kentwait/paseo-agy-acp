import type { AdmissionController } from "../../Admission Controller/controller.js";
import {
  requireProcessEvidence,
  type ProcessEvidence,
  type ProcessIdentityState
} from "../../Admission Controller/process-evidence.js";
import { observePersistedConnectorOwnerIdentity } from "./owner-instance.js";

export interface AdmissionStartupRecoveryOptions {
  readonly processEvidence?: ProcessEvidence;
  readonly now?: () => number;
}

export interface AdmissionStartupRecoverySummary {
  readonly inspected: number;
  readonly released: number;
  readonly retained: number;
  readonly markedRecoveryRequired: number;
}

/**
 * Conservatively reconcile durable seats when an enabled connector starts.
 * This code can only inspect process evidence and settle an existing fence; it
 * cannot enqueue, start, write, replay, or deliver a business prompt.
 */
export function recoverExitedAdmissionSeats(
  controller: AdmissionController,
  options: AdmissionStartupRecoveryOptions = {}
): AdmissionStartupRecoverySummary {
  const evidence = requireProcessEvidence(options.processEvidence ?? controller.processEvidence);
  if (evidence.platform !== controller.processEvidence.platform) {
    throw new Error("process evidence platform does not match durable admission platform");
  }
  const now = readNow(options.now ?? Date.now);

  let released = 0;
  let retained = 0;
  let markedRecoveryRequired = 0;
  for (const queuedOwner of controller.listRecoverableQueuedOwners()) {
    const owner = observePersistedConnectorOwnerIdentity(queuedOwner.owner, evidence);
    if (!isGoneIdentity(owner)) continue;
    try {
      controller.settleQueuedOwnerDeath(queuedOwner.requestId, queuedOwner.owner.ownerInstanceId, now);
    } catch {
      // A concurrent owner may have admitted, cancelled, or otherwise settled the request.
    }
  }

  const dispatches = controller.listRecoverableDispatches();
  for (const dispatch of dispatches) {
    const identity = dispatch.processIdentity;
    if (identity === null) {
      retained += 1;
      continue;
    }

    const connector = observePersistedConnectorOwnerIdentity(identity.connector, evidence);
    if (connector === "same" || connector === "unverifiable") {
      retained += 1;
      continue;
    }

    const child = evidence.observe(identity.child);
    const residue = evidence.inspectProcessGroup(identity.child);
    if (isGoneIdentity(child) && residue === "empty") {
      try {
        controller.releaseExitedRecoverySeat(dispatch.fence, now);
        released += 1;
        continue;
      } catch {
        retained += 1;
        continue;
      }
    }

    if (child !== "unverifiable" && residue !== "unverifiable") {
      try {
        controller.markExecutionRecoveryRequired(dispatch.fence, now);
        markedRecoveryRequired += 1;
      } catch {
        // A concurrent owner may have advanced or settled the exact fence.
      }
    }
    retained += 1;
  }

  return Object.freeze({
    inspected: dispatches.length,
    released,
    retained,
    markedRecoveryRequired
  });
}

function isGoneIdentity(value: ProcessIdentityState): boolean {
  return value === "gone" || value === "pid_reused";
}

function readNow(now: () => number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("admission startup recovery clock is invalid");
  return value;
}
