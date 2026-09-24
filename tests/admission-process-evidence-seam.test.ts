import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  AdmissionController,
  type AdmissionLease,
  type AdmissionPolicy
} from "../Admission Controller/controller.js";
import {
  createLinuxProcessEvidence,
  type LinuxProcessEvidenceReaders,
  type ProcessEvidence,
  type ProcessGroupState,
  type ProcessIdentity,
  type ProcessIdentityState
} from "../Admission Controller/process-evidence.js";
import { recoverExitedAdmissionSeats } from "../ACP Connector/admission/startup-recovery.js";
import { AdmissionTurnCoordinator } from "../ACP Connector/admission/turn-coordinator.js";
import { issueAdmittedOfficialPromptWrite } from "../ACP Connector/official-kernel/admission-fence.js";
import type { AgyAdmissionDispatchBoundary } from "../ACP Connector/admission/dispatch-boundary.js";
import { TurnClaim } from "../ACP Connector/acp/session/turn-scheduler.js";

const BOOT_ID = "f4bca3da-9bd5-4f2e-89b8-5e12e5ee8f31";
const NAMESPACE_INODE = 4_026_531_836;
const OWNER_ID = "11111111-1111-4111-8111-111111111111";
const CONNECTOR_CREATED_AT = "2026-08-14T00:00:00.000Z";
const stateDirs: string[] = [];
const controllers: AdmissionController[] = [];

const POLICY: AdmissionPolicy = {
  maxActiveTurns: 3,
  maxConcurrentStarts: 1,
  minStartIntervalMs: 0,
  queueTimeoutMs: 30 * 60_000,
  capacityCooldownMs: 30_000
};

function identity(pid: number, overrides: Partial<ProcessIdentity> = {}): ProcessIdentity {
  return Object.freeze({
    bootId: BOOT_ID,
    pid,
    startTimeTicks: String(100 + pid),
    pidNamespaceInode: NAMESPACE_INODE,
    ppid: 1,
    pgrp: pid,
    session: pid,
    ...overrides
  });
}

function controller(processEvidence: ProcessEvidence): AdmissionController {
  const stateDir = mkdtempSync(path.join(os.tmpdir(), "paseo-agy-process-evidence-seam-"));
  stateDirs.push(stateDir);
  const admission = new AdmissionController({
    databasePath: path.join(stateDir, "runtime.sqlite"),
    policy: POLICY,
    encryptionKey: Buffer.alloc(32, 31),
    contentFingerprintKey: Buffer.alloc(32, 32),
    processEvidence
  });
  controllers.push(admission);
  return admission;
}

function dispatch(
  admission: AdmissionController,
  requestId: string,
  ownerInstanceId: string,
  now = 1_000
): AdmissionLease {
  admission.enqueueWithPayload({
    requestId,
    sessionId: `session-${requestId}`,
    agentId: `agent-${requestId}`,
    fingerprint: `fingerprint-${requestId}`,
    provider: "antigravity",
    model: "model-test",
    now
  }, "must never replay", now + 60_000);
  const lease = admission.admitNext(now + 1, ownerInstanceId)!;
  admission.markStarting(lease, now + 2);
  expect(admission.recordProcessIdentity({
    requestId: lease.requestId,
    leaseId: lease.leaseId,
    generation: lease.generation,
    ownerInstanceId: lease.ownerInstanceId,
    processIdentity: {
      connector: {
        ownerInstanceId,
        createdAt: CONNECTOR_CREATED_AT,
        ...identity(3_711)
      },
      child: identity(4_182)
    },
    promptChannel: "stdin"
  })).toEqual({ status: "recorded", idempotent: false });
  return lease;
}

interface FakeEvidenceOptions {
  readonly connector: ProcessIdentity;
  readonly child: ProcessIdentity;
  readonly states?: ReadonlyMap<number, ProcessIdentityState>;
  readonly group?: ProcessGroupState;
  readonly calls?: string[];
}

function fakeEvidence(options: FakeEvidenceOptions): ProcessEvidence {
  const calls = options.calls ?? [];
  const states = options.states ?? new Map();
  const identities = new Map<number, ProcessIdentity>([
    [process.pid, options.connector],
    [options.connector.pid, options.connector],
    [options.child.pid, options.child]
  ]);
  return Object.freeze({
    platform: "linux",
    capture(pid: number): ProcessIdentity {
      calls.push(`capture:${pid}`);
      const captured = identities.get(pid);
      if (captured === undefined) throw new Error("fake process evidence does not know this PID");
      return captured;
    },
    observe(expected: unknown): ProcessIdentityState {
      calls.push("observe");
      return states.get((expected as ProcessIdentity).pid) ?? "gone";
    },
    inspectProcessGroup(_expected: unknown): ProcessGroupState {
      calls.push("inspectProcessGroup");
      return options.group ?? "empty";
    }
  });
}

function processReaders(
  expected: ProcessIdentity,
  overrides: Partial<{ bootId: string; stat: string; throwOnReadFile: boolean }> = {}
): LinuxProcessEvidenceReaders {
  return {
    readFile(filePath) {
      if (overrides.throwOnReadFile) throw new Error("unavailable");
      if (filePath === "/proc/sys/kernel/random/boot_id") return `${overrides.bootId ?? expected.bootId}\n`;
      if (filePath === `/proc/${expected.pid}/stat`) return overrides.stat ?? processStat(expected);
      throw Object.assign(new Error("gone"), { code: "ENOENT" });
    },
    readLink(filePath) {
      if (filePath === `/proc/${expected.pid}/ns/pid`) return `pid:[${expected.pidNamespaceInode}]`;
      throw Object.assign(new Error("gone"), { code: "ENOENT" });
    }
  };
}

function processStat(expected: ProcessIdentity): string {
  const fields = [
    "S",
    String(expected.ppid),
    String(expected.pgrp),
    String(expected.session),
    "0", "-1", "4194560", "1", "0", "0", "0", "4", "2", "0", "0", "20", "0", "1", "0",
    expected.startTimeTicks,
    "0", "0"
  ];
  return `${expected.pid} (agy) ${fields.join(" ")}\n`;
}

function leaseIdentityChildPid(admission: AdmissionController, requestId: string): number | null {
  const database = new Database(admission.databasePath, { readonly: true });
  try {
    const row = database
      .prepare("SELECT child_pid AS childPid FROM lease_process_identities WHERE request_id = ?")
      .get(requestId) as { childPid: number } | undefined;
    return row?.childPid ?? null;
  } finally {
    database.close();
  }
}

afterEach(() => {
  for (const admission of controllers.splice(0)) admission.close();
  for (const stateDir of stateDirs.splice(0)) rmSync(stateDir, { recursive: true, force: true });
});

describe("shared process evidence seam", () => {
  it("exposes platform, capture, conservative observation and process-group inspection on the Linux adapter", () => {
    const child = identity(4_182);
    const adapter = createLinuxProcessEvidence({
      readers: processReaders(child),
      listProcessIds: () => []
    });

    expect(adapter.platform).toBe("linux");
    expect(Object.keys(adapter).sort()).toEqual(["capture", "inspectProcessGroup", "observe", "platform"]);
    expect(adapter.capture(child.pid)).toEqual(child);
    expect(adapter.observe(child)).toBe("same");
    expect(
      createLinuxProcessEvidence({
        readers: processReaders(child, { bootId: "f4bca3da-9bd5-4f2e-89b8-5e12e5ee8f32" }),
        listProcessIds: () => []
      }).observe(child)
    ).toBe("pid_reused");
    expect(
      createLinuxProcessEvidence({
        readers: processReaders(child, { stat: processStat({ ...child, startTimeTicks: "999" }) }),
        listProcessIds: () => []
      }).observe(child)
    ).toBe("pid_reused");
    expect(
      createLinuxProcessEvidence({
        readers: {
          readFile(filePath) {
            if (filePath === "/proc/sys/kernel/random/boot_id") return `${BOOT_ID}\n`;
            throw Object.assign(new Error("gone"), { code: "ENOENT" });
          },
          readLink() {
            throw Object.assign(new Error("gone"), { code: "ENOENT" });
          }
        },
        listProcessIds: () => []
      }).observe(child)
    ).toBe("gone");
    expect(
      createLinuxProcessEvidence({
        readers: processReaders(child, { throwOnReadFile: true }),
        listProcessIds: () => []
      }).observe(child)
    ).toBe("unverifiable");

    const residue = identity(4_183, { pgrp: child.pgrp, session: child.session, ppid: child.pid });
    const present = createLinuxProcessEvidence({
      readers: {
        readFile(filePath) {
          if (filePath === "/proc/sys/kernel/random/boot_id") return `${BOOT_ID}\n`;
          if (filePath === `/proc/${residue.pid}/stat`) return processStat(residue);
          if (filePath === `/proc/${child.pid}/stat`) return processStat(child);
          throw Object.assign(new Error("gone"), { code: "ENOENT" });
        },
        readLink(filePath) {
          if (filePath === `/proc/${residue.pid}/ns/pid`) return `pid:[${NAMESPACE_INODE}]`;
          if (filePath === `/proc/${child.pid}/ns/pid`) return `pid:[${NAMESPACE_INODE}]`;
          throw Object.assign(new Error("gone"), { code: "ENOENT" });
        }
      },
      listProcessIds: () => [residue.pid]
    });
    expect(present.inspectProcessGroup(child)).toBe("present");
    expect(adapter.inspectProcessGroup(child)).toBe("empty");

    const unavailable = createLinuxProcessEvidence({
      readers: processReaders(child),
      listProcessIds: () => {
        throw new Error("inventory unavailable");
      }
    });
    expect(unavailable.inspectProcessGroup(child)).toBe("unverifiable");
  });

  it("shares one selected adapter across controller, startup recovery, reaper and coordinator", async () => {
    const calls: string[] = [];
    const adapter = fakeEvidence({
      connector: identity(3_711, { bootId: BOOT_ID }),
      child: identity(4_182),
      calls
    });
    const admission = controller(adapter);
    expect(admission.processEvidence).toBe(adapter);

    const recovered = dispatch(admission, "recover-request", OWNER_ID);
    admission.markActive(recovered, 1_003);
    admission.markExecutionRecoveryRequired(recovered, 1_004);
    expect(recoverExitedAdmissionSeats(admission, { processEvidence: adapter, now: () => 2_000 })).toEqual({
      inspected: 1,
      released: 1,
      retained: 0,
      markedRecoveryRequired: 0
    });
    expect(admission.getRequest("recover-request")?.state).toBe("recovery_required");
    expect(calls).toContain("observe");
    expect(calls).toContain("inspectProcessGroup");

    const reaped = dispatch(admission, "reap-request", "22222222-2222-4222-8222-222222222222", 3_000);
    admission.markActive(reaped, 3_003);
    admission.markExecutionRecoveryRequired(reaped, 3_004);
    expect(admission.reapSuspects(4_000, adapter)).toMatchObject({ inspected: 1, released: 1, retained: 0 });

    const coordinator = new AdmissionTurnCoordinator({
      controller: admission,
      agentId: "seam-agent",
      processEvidence: adapter,
      createRequestId: () => "request-seam"
    });
    expect(coordinator.processEvidence).toBe(adapter);
    expect(coordinator.ownerIdentity).toMatchObject({ pid: 3_711, bootId: BOOT_ID });

    let persistedChildPid: number | null = null;
    await coordinator.admit({
      sessionId: "seam-session",
      model: "model-test",
      promptText: "seam prompt",
      claim: new TurnClaim("foreground"),
      execute: async (boundary) => {
        boundary.prepare(4_182);
        boundary.commitDispatchIntent();
        persistedChildPid = leaseIdentityChildPid(admission, "request-seam");
        boundary.beforePromptWrite();
        boundary.afterPromptWrite();
        return { stopReason: "end_turn" };
      }
    });

    expect(persistedChildPid).toBe(4_182);
    expect(admission.getRequest("request-seam")?.state).toBe("completed");
  });

  it("retains local capacity when the adapter reports conservative group residue", () => {
    const adapter = fakeEvidence({
      connector: identity(3_711),
      child: identity(4_182),
      states: new Map([
        [3_711, "gone"],
        [4_182, "gone"]
      ]),
      group: "unverifiable"
    });
    const admission = controller(adapter);
    const lease = dispatch(admission, "residue-request", OWNER_ID);
    admission.markActive(lease, 1_003);
    admission.markExecutionRecoveryRequired(lease, 1_004);

    expect(recoverExitedAdmissionSeats(admission, { processEvidence: adapter, now: () => 2_000 })).toEqual({
      inspected: 1,
      released: 0,
      retained: 1,
      markedRecoveryRequired: 0
    });
    expect(admission.listRecoverableDispatches()).toHaveLength(1);
  });

  it("requires dispatch intent and ambiguous-write transitions on the prompt boundary", () => {
    const boundary = {
      prepare() {},
      beforePromptWrite() {},
      afterPromptWrite() {}
    } as unknown as AgyAdmissionDispatchBoundary;

    expect(() => issueAdmittedOfficialPromptWrite(boundary, 42, () => {})).toThrow(TypeError);

    const calls: string[] = [];
    const complete: AgyAdmissionDispatchBoundary = {
      prepare(processId: number) {
        calls.push(`prepare:${processId}`);
      },
      commitDispatchIntent() {
        calls.push("commitDispatchIntent");
      },
      beforePromptWrite() {
        calls.push("beforePromptWrite");
      },
      markDispatchAmbiguous() {
        calls.push("markDispatchAmbiguous");
      },
      afterPromptWrite() {
        calls.push("afterPromptWrite");
      }
    };

    expect(() => issueAdmittedOfficialPromptWrite(complete, 42, () => {
      calls.push("write");
      throw new Error("write failed");
    })).toThrow(/write failed/);
    expect(calls).toEqual(["prepare:42", "commitDispatchIntent", "beforePromptWrite", "write", "markDispatchAmbiguous"]);
  });
});
