import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  ProcessEvidenceError,
  type ProcessEvidence,
  type ProcessGroupState,
  type ProcessIdentityState
} from "./process-evidence.js";

export const DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION = 1 as const;

const MAX_PID = 2_147_483_647;
const MAX_UINT64 = 18_446_744_073_709_551_615n;
const CANONICAL_DECIMAL_PATTERN = /^[1-9][0-9]*$/;
const MAX_IDENTITY_JSON_LENGTH = 1_024;
const MAX_INVENTORY_ATTEMPTS = 5;

export interface DarwinProcessIdentity {
  readonly platform: "darwin";
  readonly formatVersion: typeof DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION;
  readonly bootSessionToken: string;
  readonly pid: number;
  readonly processStartMicros: string;
  readonly ppid: number;
  readonly pgrp: number;
  readonly session: number;
}

export interface DarwinNativeProcessRecord {
  readonly bootSessionToken: string;
  readonly pid: number;
  readonly processStartMicros: string;
  readonly ppid: number;
  readonly pgrp: number;
  readonly session: number;
}

export interface DarwinProcessEvidenceSource {
  captureProcess(pid: number): unknown;
  listProcesses(processGroup: number, session: number): unknown;
}

export function createDarwinProcessEvidence(source: unknown): ProcessEvidence<DarwinProcessIdentity> {
  requireDarwinSource(source);
  return Object.freeze({
    platform: "darwin",
    capture(pid: number): DarwinProcessIdentity {
      return captureDarwinProcessIdentity(pid, source);
    },
    observe(expected: unknown): ProcessIdentityState {
      return observeDarwinProcessIdentity(expected, source);
    },
    inspectProcessGroup(expected: unknown): ProcessGroupState {
      return inspectDarwinProcessGroup(expected, source);
    }
  });
}

export function captureDarwinProcessIdentity(
  pid: number,
  source: unknown
): DarwinProcessIdentity {
  requireDarwinSource(source);
  const expectedPid = requirePid(pid);
  const result = callSource(() => source.captureProcess(expectedPid));
  const capture = normalizeCaptureResult(result);
  if (capture === null) throw new ProcessEvidenceError("native process evidence is malformed");
  if (capture.status === "gone") throw new ProcessEvidenceError("process evidence is absent", "process_gone");
  return capture.identity;
}

export function observeDarwinProcessIdentity(
  expected: unknown,
  source: unknown
): ProcessIdentityState {
  requireDarwinSource(source);
  const normalizedExpected = normalizeDarwinProcessIdentity(expected);
  if (normalizedExpected === null) return "unverifiable";

  try {
    const observed = captureDarwinProcessIdentity(normalizedExpected.pid, source);
    return isSameDarwinProcessIdentity(normalizedExpected, observed) ? "same" : "pid_reused";
  } catch (error) {
    return error instanceof ProcessEvidenceError && error.kind === "process_gone" ? "gone" : "unverifiable";
  }
}

export function inspectDarwinProcessGroup(
  expected: unknown,
  source: unknown
): ProcessGroupState {
  requireDarwinSource(source);
  const normalizedExpected = normalizeDarwinProcessIdentity(expected);
  if (normalizedExpected === null) return "unverifiable";

  const inventory = readStableInventory(source, normalizedExpected);
  if (inventory === null) return "unverifiable";
  return inventory.length > 0 ? "present" : "empty";
}

export function serializeDarwinProcessIdentity(value: unknown): string {
  const identity = normalizeDarwinProcessIdentity(value);
  if (identity === null) throw new ProcessEvidenceError("Darwin process identity is malformed");
  return JSON.stringify({
    platform: identity.platform,
    formatVersion: identity.formatVersion,
    bootSessionToken: identity.bootSessionToken,
    pid: identity.pid,
    processStartMicros: identity.processStartMicros,
    ppid: identity.ppid,
    pgrp: identity.pgrp,
    session: identity.session
  });
}

export function parseDarwinProcessIdentity(value: unknown): DarwinProcessIdentity {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_IDENTITY_JSON_LENGTH) {
    throw new ProcessEvidenceError("Darwin process identity is malformed");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new ProcessEvidenceError("Darwin process identity is malformed");
  }
  const identity = normalizeDarwinProcessIdentity(parsed);
  if (identity === null || serializeDarwinProcessIdentity(identity) !== value) {
    throw new ProcessEvidenceError("Darwin process identity is malformed");
  }
  return identity;
}

export function isSameDarwinProcessIdentity(expected: unknown, observed: unknown): boolean {
  const left = normalizeDarwinProcessIdentity(expected);
  const right = normalizeDarwinProcessIdentity(observed);
  if (left === null || right === null) return false;
  return (
    left.platform === right.platform &&
    left.formatVersion === right.formatVersion &&
    left.bootSessionToken === right.bootSessionToken &&
    left.pid === right.pid &&
    left.processStartMicros === right.processStartMicros &&
    left.ppid === right.ppid &&
    left.pgrp === right.pgrp &&
    left.session === right.session
  );
}

export function loadSourceBuiltDarwinProcessEvidenceSource(): DarwinProcessEvidenceSource {
  if (process.platform !== "darwin") {
    throw new ProcessEvidenceError("Darwin process evidence is unavailable on this platform");
  }
  const require = createRequire(import.meta.url);
  const candidates = [
    new URL("../build/Release/darwin_process_evidence.node", import.meta.url),
    new URL("../../build/Release/darwin_process_evidence.node", import.meta.url)
  ];
  const moduleUrl = candidates.find((candidate) => existsSync(candidate));
  if (moduleUrl === undefined) throw new ProcessEvidenceError("source-built Darwin process evidence is unavailable");
  let source: unknown;
  try {
    source = require(fileURLToPath(moduleUrl)) as unknown;
  } catch {
    throw new ProcessEvidenceError("source-built Darwin process evidence is unavailable");
  }
  requireDarwinSource(source);
  return source;
}

type NormalizedCapture =
  | { readonly status: "gone" }
  | { readonly status: "ok"; readonly identity: DarwinProcessIdentity };

function normalizeCaptureResult(value: unknown): NormalizedCapture | null {
  const record = exactRecord(value, ["status"]);
  if (record?.status === "gone") return Object.freeze({ status: "gone" });
  const ok = exactRecord(value, ["status", "process"]);
  if (ok?.status !== "ok") return null;
  const identity = normalizeNativeProcessRecord(ok.process);
  return identity === null ? null : Object.freeze({ status: "ok", identity });
}

function readStableInventory(
  source: DarwinProcessEvidenceSource,
  expected: DarwinProcessIdentity
): readonly DarwinProcessIdentity[] | null {
  for (let attempt = 0; attempt < MAX_INVENTORY_ATTEMPTS; attempt += 1) {
    const value = callSource(() => source.listProcesses(expected.pgrp, expected.session));
    if (value === null) continue;
    const inventory = normalizeInventory(value);
    if (inventory === null) continue;
    if (inventory.some((identity) => identity.pgrp !== expected.pgrp || identity.session !== expected.session)) continue;
    return Object.freeze(inventory);
  }
  return null;
}

function normalizeInventory(value: unknown): DarwinProcessIdentity[] | null {
  const record = exactRecord(value, ["status", "complete", "processes"]);
  if (record?.status !== "ok" || record.complete !== true || !Array.isArray(record.processes)) return null;
  const inventory: DarwinProcessIdentity[] = [];
  let previousPid = 0;
  let bootSessionToken: string | null = null;

  for (const value of record.processes) {
    const identity = normalizeNativeProcessRecord(value);
    if (identity === null || identity.pid <= previousPid) return null;
    if (bootSessionToken !== null && identity.bootSessionToken !== bootSessionToken) return null;
    bootSessionToken = identity.bootSessionToken;
    previousPid = identity.pid;
    inventory.push(identity);
  }
  return inventory;
}

function normalizeNativeProcessRecord(value: unknown): DarwinProcessIdentity | null {
  const record = exactRecord(value, [
    "bootSessionToken",
    "pid",
    "processStartMicros",
    "ppid",
    "pgrp",
    "session"
  ]);
  if (record === null) return null;
  return normalizeIdentityFields({
    platform: "darwin",
    formatVersion: DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION,
    bootSessionToken: record.bootSessionToken,
    pid: record.pid,
    processStartMicros: record.processStartMicros,
    ppid: record.ppid,
    pgrp: record.pgrp,
    session: record.session
  });
}

function normalizeDarwinProcessIdentity(value: unknown): DarwinProcessIdentity | null {
  const record = exactRecord(value, [
    "platform",
    "formatVersion",
    "bootSessionToken",
    "pid",
    "processStartMicros",
    "ppid",
    "pgrp",
    "session"
  ]);
  if (record === null || record.platform !== "darwin" || record.formatVersion !== DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION) {
    return null;
  }
  return normalizeIdentityFields(record);
}

function normalizeIdentityFields(value: Record<string, unknown>): DarwinProcessIdentity | null {
  if (
    !isCanonicalUint64(value.bootSessionToken) ||
    !isCanonicalUint64(value.processStartMicros) ||
    !isPid(value.pid) ||
    !isProcessTopologyId(value.ppid) ||
    !isProcessTopologyId(value.pgrp) ||
    !isProcessTopologyId(value.session)
  ) {
    return null;
  }
  return Object.freeze({
    platform: "darwin",
    formatVersion: DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION,
    bootSessionToken: value.bootSessionToken as string,
    pid: value.pid as number,
    processStartMicros: value.processStartMicros as string,
    ppid: value.ppid as number,
    pgrp: value.pgrp as number,
    session: value.session as number
  });
}

function exactRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== expectedKeys.length || Object.getOwnPropertySymbols(value).length !== 0) return null;
    const record: Record<string, unknown> = Object.create(null);
    for (const key of expectedKeys) {
      if (!names.includes(key)) return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) return null;
      record[key] = descriptor.value;
    }
    return record;
  } catch {
    return null;
  }
}

function callSource<T>(read: () => T): T | null {
  try {
    return read();
  } catch {
    return null;
  }
}

function requireDarwinSource(value: unknown): asserts value is DarwinProcessEvidenceSource {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as DarwinProcessEvidenceSource).captureProcess !== "function" ||
    typeof (value as DarwinProcessEvidenceSource).listProcesses !== "function"
  ) {
    throw new ProcessEvidenceError("Darwin process evidence source is invalid");
  }
}

function requirePid(value: unknown): number {
  if (!isPid(value)) throw new ProcessEvidenceError("pid must be a positive integer in range");
  return value;
}

function isPid(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value <= MAX_PID;
}

function isProcessTopologyId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= MAX_PID;
}

function isCanonicalUint64(value: unknown): value is string {
  if (typeof value !== "string" || !CANONICAL_DECIMAL_PATTERN.test(value)) return false;
  try {
    const parsed = BigInt(value);
    return parsed > 0n && parsed <= MAX_UINT64;
  } catch {
    return false;
  }
}
