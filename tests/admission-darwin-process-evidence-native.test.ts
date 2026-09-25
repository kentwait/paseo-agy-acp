import { spawn, type ChildProcess } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import {
  createDarwinProcessEvidence,
  loadSourceBuiltDarwinProcessEvidenceSource,
  parseDarwinProcessIdentity,
  serializeDarwinProcessIdentity,
  type DarwinNativeProcessRecord,
  type DarwinProcessEvidenceSource
} from "../Admission Controller/darwin-process-evidence.js";

const LIVE_PROCESS = "process.stdout.write('ready\\n'); setInterval(() => {}, 1000);";
const DESCENDANT_HELPER = `
const { spawn } = require("node:child_process");
const child = spawn(process.execPath, ["-e", "process.stdout.write('ready\\\\n'); setInterval(() => {}, 1000);"], {
  stdio: ["ignore", "pipe", "inherit"]
});
child.stdout.once("data", () => process.stdout.write("grandchild:" + child.pid + "\\n"));
process.stdin.once("data", () => process.exit(0));
`;
const children: ChildProcess[] = [];
const processGroups = new Set<number>();

function track(child: ChildProcess, detached: boolean): ChildProcess {
  children.push(child);
  if (detached) {
    if (child.pid === undefined) throw new Error("detached child has no PID");
    processGroups.add(child.pid);
  }
  return child;
}

async function waitForOutput(child: ChildProcess, expected: string, timeoutMs = 5_000): Promise<string> {
  const stdoutStream = child.stdout;
  const stderrStream = child.stderr;
  if (stdoutStream === null || stderrStream === null) throw new Error("child stdio is unavailable");
  stdoutStream.setEncoding("utf8");
  stderrStream.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for ${expected}; stdout=${stdout}; stderr=${stderr}`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      stdoutStream.off("data", onStdout);
      stderrStream.off("data", onStderr);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const onStdout = (chunk: string) => {
      stdout += chunk;
      const match = /grandchild:([1-9][0-9]*)/.exec(stdout);
      if (expected === "grandchild" && match !== null) {
        cleanup();
        resolve(match[1]);
      } else if (expected === "ready" && stdout.includes("ready\n")) {
        cleanup();
        resolve("ready");
      }
    };
    const onStderr = (chunk: string) => {
      stderr += chunk;
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(new Error(`child exited before ${expected}; code=${code}; signal=${signal}; stderr=${stderr}`));
    };
    stdoutStream.on("data", onStdout);
    stderrStream.on("data", onStderr);
    child.once("error", onError);
    child.once("exit", onExit);
  });
}

async function spawnLiveProcess(detached: boolean): Promise<ChildProcess> {
  const child = track(
    spawn(process.execPath, ["-e", LIVE_PROCESS], {
      detached,
      stdio: ["ignore", "pipe", "pipe"]
    }),
    detached
  );
  await waitForOutput(child, "ready");
  return child;
}

async function terminate(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const cleanup = () => {
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const onError = () => {
      cleanup();
      resolve();
    };
    const onExit = () => {
      cleanup();
      resolve();
    };
    child.once("error", onError);
    child.once("exit", onExit);
    if (child.exitCode !== null || child.signalCode !== null) {
      cleanup();
      resolve();
      return;
    }
    child.kill("SIGKILL");
  });
}

function killProcessGroup(processGroup: number): void {
  try {
    process.kill(-processGroup, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

async function waitForState(
  read: () => string,
  expected: string,
  description: string,
  timeoutMs = 5_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let observed: string | null = null;
  while (Date.now() < deadline) {
    observed = read();
    if (observed === expected) return;
    await delay(25);
  }
  throw new Error(`timed out waiting for ${description}; observed=${observed}`);
}

function mutateObservedProcess(
  source: DarwinProcessEvidenceSource,
  mutate: (value: DarwinNativeProcessRecord) => DarwinNativeProcessRecord
): DarwinProcessEvidenceSource {
  return {
    captureProcess(pid: number): unknown {
      const result = source.captureProcess(pid) as { status?: unknown; process?: unknown };
      if (result.status !== "ok" || typeof result.process !== "object" || result.process === null) return result;
      return { status: "ok", process: mutate({ ...(result.process as DarwinNativeProcessRecord) }) };
    },
    listProcesses(processGroup: number, session: number): unknown {
      return source.listProcesses(processGroup, session);
    }
  };
}

afterEach(async () => {
  let failure: unknown = null;
  for (const processGroup of processGroups) {
    try {
      killProcessGroup(processGroup);
    } catch (error) {
      failure ??= error;
    }
  }
  processGroups.clear();
  for (const child of children.splice(0)) await terminate(child);
  if (failure !== null) throw failure;
});

describe.skipIf(process.platform !== "darwin")("source-built Darwin process evidence", () => {
  it("captures and re-observes the real current process through libproc", () => {
    const source = loadSourceBuiltDarwinProcessEvidenceSource();
    const adapter = createDarwinProcessEvidence(source);
    const identity = adapter.capture(process.pid);

    expect(identity.platform).toBe("darwin");
    expect(identity.formatVersion).toBe(1);
    expect(identity.pid).toBe(process.pid);
    expect(identity.ppid).toBe(process.ppid);
    expect(BigInt(identity.bootSessionToken)).toBeGreaterThan(0n);
    expect(BigInt(identity.processStartMicros)).toBeGreaterThan(0n);
    expect(parseDarwinProcessIdentity(serializeDarwinProcessIdentity(identity))).toEqual(identity);
    expect(adapter.observe(identity)).toBe("same");
    expect(adapter.inspectProcessGroup(identity)).toBe("present");
  });

  it("captures a real child and reports gone only after the child exits", async () => {
    const source = loadSourceBuiltDarwinProcessEvidenceSource();
    const adapter = createDarwinProcessEvidence(source);
    const child = await spawnLiveProcess(false);
    if (child.pid === undefined) throw new Error("live child has no PID");
    const identity = adapter.capture(child.pid);

    expect(identity.pid).toBe(child.pid);
    expect(identity.ppid).toBe(process.pid);
    expect(adapter.observe(identity)).toBe("same");

    await terminate(child);
    await waitForState(() => adapter.observe(identity), "gone", "real child disappearance");
  });

  it("uses a real live child to reject changed boot and start identities as pid_reused", async () => {
    const source = loadSourceBuiltDarwinProcessEvidenceSource();
    const adapter = createDarwinProcessEvidence(source);
    const child = await spawnLiveProcess(false);
    if (child.pid === undefined) throw new Error("live child has no PID");
    const identity = adapter.capture(child.pid);
    const changedBootAdapter = createDarwinProcessEvidence(
      mutateObservedProcess(source, (value) => ({
        ...value,
        bootSessionToken: (BigInt(value.bootSessionToken) + 1n).toString()
      }))
    );
    const changedStartAdapter = createDarwinProcessEvidence(
      mutateObservedProcess(source, (value) => ({
        ...value,
        processStartMicros: (BigInt(value.processStartMicros) + 1n).toString()
      }))
    );

    expect(changedBootAdapter.observe(identity)).toBe("pid_reused");
    expect(changedStartAdapter.observe(identity)).toBe("pid_reused");
    expect(adapter.observe(identity)).toBe("same");
  });

  it("finds a live descendant after its group leader exits and reports empty after cleanup", async () => {
    const source = loadSourceBuiltDarwinProcessEvidenceSource();
    const adapter = createDarwinProcessEvidence(source);
    const leader = track(
      spawn(process.execPath, ["-e", DESCENDANT_HELPER], {
        detached: true,
        stdio: ["pipe", "pipe", "pipe"]
      }),
      true
    );
    const grandchildPid = Number(await waitForOutput(leader, "grandchild"));
    if (leader.pid === undefined || !Number.isSafeInteger(grandchildPid)) throw new Error("group child PID is invalid");
    const identity = adapter.capture(leader.pid);

    expect(identity.pgrp).toBe(leader.pid);
    expect(identity.session).toBe(leader.pid);
    expect(() => source.captureProcess(Number.NaN)).toThrow(/invalid/i);
    expect(() => source.listProcesses(Number.POSITIVE_INFINITY, identity.session)).toThrow(/invalid/i);
    expect(adapter.inspectProcessGroup(identity)).toBe("present");

    leader.stdin?.write("exit\n");
    await terminate(leader);
    expect(adapter.inspectProcessGroup(identity)).toBe("present");

    killProcessGroup(leader.pid);
    processGroups.delete(leader.pid);
    await waitForState(() => adapter.inspectProcessGroup(identity), "empty", "empty process group");
  });
});
