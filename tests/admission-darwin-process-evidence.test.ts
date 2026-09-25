import { describe, expect, it } from "vitest";
import { requireProcessEvidence } from "../Admission Controller/process-evidence.js";
import {
  createDarwinProcessEvidence,
  DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION,
  isSameDarwinProcessIdentity,
  parseDarwinProcessIdentity,
  serializeDarwinProcessIdentity,
  type DarwinNativeProcessRecord,
  type DarwinProcessEvidenceSource,
  type DarwinProcessIdentity
} from "../Admission Controller/darwin-process-evidence.js";

const BOOT_SESSION_TOKEN = "1800000000000000000";
const PROCESS_START_MICROS = "1700000000123456";

function record(overrides: Partial<DarwinNativeProcessRecord> = {}): DarwinNativeProcessRecord {
  return {
    bootSessionToken: BOOT_SESSION_TOKEN,
    pid: 4_182,
    processStartMicros: PROCESS_START_MICROS,
    ppid: 3_711,
    pgrp: 4_182,
    session: 4_182,
    ...overrides
  };
}

function captured(value: DarwinNativeProcessRecord): unknown {
  return { status: "ok", process: value };
}

function inventory(processes: readonly DarwinNativeProcessRecord[], complete = true): unknown {
  return { status: "ok", complete, processes };
}

class FakeSource implements DarwinProcessEvidenceSource {
  readonly captures = new Map<number, unknown>();
  readonly inventories: unknown[] = [];
  captureError: Error | null = null;
  inventoryError: Error | null = null;
  captureCalls = 0;
  inventoryCalls = 0;

  captureProcess(pid: number): unknown {
    this.captureCalls += 1;
    if (this.captureError !== null) throw this.captureError;
    return this.captures.get(pid) ?? { status: "gone" };
  }

  listProcesses(): unknown {
    const index = Math.min(this.inventoryCalls, this.inventories.length - 1);
    this.inventoryCalls += 1;
    if (this.inventoryError !== null) throw this.inventoryError;
    return this.inventories[index];
  }
}

function sourceWithCapture(value: DarwinNativeProcessRecord): FakeSource {
  const source = new FakeSource();
  source.captures.set(4_182, captured(value));
  source.inventories.push(inventory([value]));
  return source;
}

describe("Darwin process evidence", () => {
  it("captures a frozen platform and format tagged identity with canonical serialization", () => {
    const nativeRecord = record();
    const adapter = createDarwinProcessEvidence(sourceWithCapture(nativeRecord));
    const identity = adapter.capture(nativeRecord.pid);

    expect(identity).toEqual({
      platform: "darwin",
      formatVersion: DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION,
      bootSessionToken: BOOT_SESSION_TOKEN,
      pid: nativeRecord.pid,
      processStartMicros: PROCESS_START_MICROS,
      ppid: nativeRecord.ppid,
      pgrp: nativeRecord.pgrp,
      session: nativeRecord.session
    });
    expect(Object.isFrozen(identity)).toBe(true);
    expect(adapter.platform).toBe("darwin");
    expect(requireProcessEvidence<DarwinProcessIdentity>(adapter)).toBe(adapter);
    expect(() => requireProcessEvidence({ ...adapter, platform: "freebsd" })).toThrow(/invalid/i);
    expect(Object.keys(adapter).sort()).toEqual(["capture", "inspectProcessGroup", "observe", "platform"]);
    expect(serializeDarwinProcessIdentity(identity)).toBe(
      `{"platform":"darwin","formatVersion":1,"bootSessionToken":"${BOOT_SESSION_TOKEN}","pid":4182,"processStartMicros":"${PROCESS_START_MICROS}","ppid":3711,"pgrp":4182,"session":4182}`
    );
    expect(parseDarwinProcessIdentity(serializeDarwinProcessIdentity(identity))).toEqual(identity);
  });

  it("requires exact canonical identities and rejects unsafe native values", () => {
    const identity = createDarwinProcessEvidence(sourceWithCapture(record())).capture(4_182);
    const canonical = serializeDarwinProcessIdentity(identity);

    expect(() => parseDarwinProcessIdentity(` ${canonical}`)).toThrow(/malformed/i);
    expect(
      () =>
        parseDarwinProcessIdentity(
          JSON.stringify({
            pid: identity.pid,
            platform: identity.platform,
            formatVersion: identity.formatVersion,
            bootSessionToken: identity.bootSessionToken,
            processStartMicros: identity.processStartMicros,
            ppid: identity.ppid,
            pgrp: identity.pgrp,
            session: identity.session
          })
        )
    ).toThrow(/malformed/i);
    expect(() => parseDarwinProcessIdentity(JSON.stringify({ ...identity, extra: true }))).toThrow(/malformed/i);
    expect(() => parseDarwinProcessIdentity(JSON.stringify({ ...identity, platform: "linux" }))).toThrow(/malformed/i);
    expect(() => parseDarwinProcessIdentity(JSON.stringify({ ...identity, formatVersion: 2 }))).toThrow(/malformed/i);

    for (const overrides of [
      { bootSessionToken: "0" },
      { bootSessionToken: `0${BOOT_SESSION_TOKEN}` },
      { bootSessionToken: (18_446_744_073_709_551_616n).toString() },
      { processStartMicros: "0" },
      { processStartMicros: "01" },
      { pid: 0 },
      { ppid: -1 },
      { pgrp: Number.MAX_SAFE_INTEGER + 1 },
      { session: 2_147_483_648 }
    ]) {
      const source = sourceWithCapture(record(overrides));
      expect(() => createDarwinProcessEvidence(source).capture(4_182)).toThrow(/unavailable|malformed/i);
    }

    const accessor = { ...identity } as Record<string, unknown>;
    Object.defineProperty(accessor, "pid", { enumerable: true, get: () => identity.pid });
    expect(isSameDarwinProcessIdentity(accessor, identity)).toBe(false);
  });

  it("classifies exact evidence as same and every persisted identity change as pid_reused", () => {
    const nativeRecord = record();
    const source = sourceWithCapture(nativeRecord);
    const adapter = createDarwinProcessEvidence(source);
    const identity = adapter.capture(nativeRecord.pid);

    expect(adapter.observe(identity)).toBe("same");
    for (const overrides of [
      { bootSessionToken: "1800000000000000001" },
      { processStartMicros: "1700000000123457" },
      { ppid: nativeRecord.ppid + 1 },
      { pgrp: nativeRecord.pgrp + 1 },
      { session: nativeRecord.session + 1 }
    ]) {
      source.captures.set(nativeRecord.pid, captured(record(overrides)));
      expect(adapter.observe(identity)).toBe("pid_reused");
    }
  });

  it("returns gone only for direct native absence and fails closed for all other capture failures", () => {
    const nativeRecord = record();
    const source = sourceWithCapture(nativeRecord);
    const adapter = createDarwinProcessEvidence(source);
    const identity = adapter.capture(nativeRecord.pid);

    source.captures.delete(nativeRecord.pid);
    expect(adapter.observe(identity)).toBe("gone");

    source.captureError = Object.assign(new Error("permission denied"), { code: "EPERM" });
    expect(adapter.observe(identity)).toBe("unverifiable");

    source.captureError = null;
    source.captures.set(nativeRecord.pid, { status: "ok", process: { ...record(), unexpected: true } });
    expect(adapter.observe(identity)).toBe("unverifiable");

    expect(adapter.observe({ ...identity, processStartMicros: "not-a-time" })).toBe("unverifiable");
  });

  it("returns present only for a matching member of a complete stable process inventory", () => {
    const expectedRecord = record();
    const source = sourceWithCapture(expectedRecord);
    const adapter = createDarwinProcessEvidence(source);
    const expected = adapter.capture(expectedRecord.pid);

    expect(adapter.inspectProcessGroup(expected)).toBe("present");

    source.inventories.length = 0;
    source.inventoryCalls = 0;
    source.inventories.push(inventory([]), inventory([]));
    expect(adapter.inspectProcessGroup(expected)).toBe("empty");

    const residue = record({ pid: 4_183, ppid: 4_182, pgrp: 4_182, session: 4_182 });
    source.inventories.length = 0;
    source.inventoryCalls = 0;
    source.inventories.push(inventory([expectedRecord, residue]), inventory([expectedRecord, residue]));
    expect(adapter.inspectProcessGroup(expected)).toBe("present");
  });

  it("retries unavailable inventory and never calls incomplete or malformed enumeration empty", () => {
    const expectedRecord = record();
    const source = sourceWithCapture(expectedRecord);
    const adapter = createDarwinProcessEvidence(source);
    const expected = adapter.capture(expectedRecord.pid);

    source.inventories.length = 0;
    source.inventoryCalls = 0;
    source.inventories.push(inventory([], false), inventory([]));
    expect(adapter.inspectProcessGroup(expected)).toBe("empty");
    expect(source.inventoryCalls).toBe(2);

    source.inventories.length = 0;
    source.inventoryCalls = 0;
    source.inventories.push(...Array.from({ length: 6 }, () => inventory([], false)));
    expect(adapter.inspectProcessGroup(expected)).toBe("unverifiable");
    expect(source.inventoryCalls).toBe(5);

    source.inventories.length = 0;
    source.inventoryCalls = 0;
    source.inventories.push(
      ...Array.from({ length: 6 }, () => inventory([{ ...expectedRecord, session: 2_147_483_648 }]))
    );
    expect(adapter.inspectProcessGroup(expected)).toBe("unverifiable");
    expect(source.inventoryCalls).toBe(5);

    source.inventories.length = 0;
    source.inventoryCalls = 0;
    source.inventoryError = new Error("inventory unavailable");
    expect(adapter.inspectProcessGroup(expected)).toBe("unverifiable");
    expect(source.inventoryCalls).toBe(5);
  });

  it("rejects invalid source and process-group inputs without weakening the seam", () => {
    expect(() => createDarwinProcessEvidence({} as DarwinProcessEvidenceSource)).toThrow(/invalid/i);
    expect(() => createDarwinProcessEvidence({ captureProcess() {}, listProcesses: null } as unknown as DarwinProcessEvidenceSource)).toThrow(
      /invalid/i
    );

    const source = sourceWithCapture(record());
    const adapter = createDarwinProcessEvidence(source);
    expect(adapter.inspectProcessGroup(null)).toBe("unverifiable");
    expect(() => adapter.capture(0)).toThrow(/pid/i);
    expect(() => adapter.capture(2_147_483_648)).toThrow(/pid/i);
  });
});
