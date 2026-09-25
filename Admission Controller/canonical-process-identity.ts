import {
  parseDarwinProcessIdentity,
  serializeDarwinProcessIdentity,
  type DarwinProcessIdentity
} from "./darwin-process-evidence.js";
import {
  parseProcessIdentity,
  ProcessEvidenceError,
  serializeProcessIdentity,
  type ProcessEvidencePlatform,
  type ProcessIdentity
} from "./process-evidence.js";

export type PlatformProcessIdentity = ProcessIdentity | DarwinProcessIdentity;

export interface PlatformProcessIdentityEnvelope {
  readonly platform: ProcessEvidencePlatform;
  readonly identity: PlatformProcessIdentity;
}

export const PLATFORM_PROCESS_IDENTITY_KEYS: Readonly<
  Record<ProcessEvidencePlatform, readonly string[]>
> = Object.freeze({
  linux: Object.freeze(["bootId", "pid", "startTimeTicks", "pidNamespaceInode", "ppid", "pgrp", "session"]),
  darwin: Object.freeze([
    "platform",
    "formatVersion",
    "bootSessionToken",
    "pid",
    "processStartMicros",
    "ppid",
    "pgrp",
    "session"
  ])
});

export function serializePlatformProcessIdentity(
  identity: unknown,
  platform: ProcessEvidencePlatform
): string {
  if (platform === "darwin") return serializeDarwinProcessIdentity(identity);
  if (platform === "linux") return serializeProcessIdentity(identity, "linux");
  throw new ProcessEvidenceError("process evidence platform is invalid");
}

export function parsePlatformProcessIdentity(
  value: unknown,
  expectedPlatform: ProcessEvidencePlatform
): PlatformProcessIdentity | null {
  try {
    if (expectedPlatform === "darwin") return parseDarwinProcessIdentity(value);
    if (expectedPlatform === "linux") return parseProcessIdentity(value, "linux");
    return null;
  } catch {
    return null;
  }
}

export function parsePlatformProcessIdentityEnvelope(value: unknown): PlatformProcessIdentityEnvelope | null {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) as unknown : value;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(parsed, "platform");
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor) ||
      (descriptor.value !== "linux" && descriptor.value !== "darwin")
    ) {
      return null;
    }
    const platform = descriptor.value;
    const canonical = typeof value === "string" ? value : JSON.stringify(parsed) as unknown;
    if (typeof canonical !== "string") return null;
    const identity = parsePlatformProcessIdentity(canonical, platform);
    if (identity === null) return null;
    return Object.freeze({ platform, identity });
  } catch {
    return null;
  }
}

export function normalizePlatformProcessIdentity(
  value: unknown,
  platform: ProcessEvidencePlatform
): PlatformProcessIdentity | null {
  try {
    return parsePlatformProcessIdentity(serializePlatformProcessIdentity(value, platform), platform);
  } catch {
    return null;
  }
}
