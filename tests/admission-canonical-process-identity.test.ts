import { describe, expect, it } from "vitest";
import {
  normalizePlatformProcessIdentity,
  parsePlatformProcessIdentity,
  parsePlatformProcessIdentityEnvelope,
  PLATFORM_PROCESS_IDENTITY_KEYS,
  serializePlatformProcessIdentity,
  type PlatformProcessIdentity
} from "../Admission Controller/canonical-process-identity.js";
import {
  DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION,
  type DarwinProcessIdentity
} from "../Admission Controller/darwin-process-evidence.js";
import {
  serializeProcessIdentity,
  type ProcessIdentity
} from "../Admission Controller/process-evidence.js";

const linux: ProcessIdentity = {
  bootId: "f4bca3da-9bd5-4f2e-89b8-5e12e5ee8f31",
  pid: 4_182,
  startTimeTicks: "1700000000123456",
  pidNamespaceInode: 4_026_531_836,
  ppid: 3_711,
  pgrp: 4_182,
  session: 4_182
};

const darwin: DarwinProcessIdentity = {
  platform: "darwin",
  formatVersion: DARWIN_PROCESS_EVIDENCE_FORMAT_VERSION,
  bootSessionToken: "1800000000000000000",
  pid: 4_182,
  processStartMicros: "1700000000123456",
  ppid: 3_711,
  pgrp: 4_182,
  session: 4_182
};

describe("canonical platform process identity codec", () => {
  it("round-trips exact Linux and Darwin canonical JSON", () => {
    const linuxJson = serializePlatformProcessIdentity(linux, "linux");
    const darwinJson = serializePlatformProcessIdentity(darwin, "darwin");

    expect(parsePlatformProcessIdentity(linuxJson, "linux")).toEqual(linux);
    expect(parsePlatformProcessIdentity(darwinJson, "darwin")).toEqual(darwin);
    expect(parsePlatformProcessIdentityEnvelope(linuxJson)).toEqual({ platform: "linux", identity: linux });
    expect(parsePlatformProcessIdentityEnvelope(darwinJson)).toEqual({ platform: "darwin", identity: darwin });
    expect(linuxJson).toBe(serializeProcessIdentity(linux, "linux"));
  });

  it("rejects cross-platform, malformed, and noncanonical evidence", () => {
    const linuxJson = serializePlatformProcessIdentity(linux, "linux");
    const darwinJson = serializePlatformProcessIdentity(darwin, "darwin");

    expect(parsePlatformProcessIdentity(linuxJson, "darwin")).toBeNull();
    expect(parsePlatformProcessIdentity(darwinJson, "linux")).toBeNull();
    expect(parsePlatformProcessIdentityEnvelope(serializeProcessIdentity(linux, "darwin"))).toBeNull();
    expect(parsePlatformProcessIdentity(` ${darwinJson}`, "darwin")).toBeNull();
    expect(parsePlatformProcessIdentity(JSON.stringify({ ...darwin, extra: true }), "darwin")).toBeNull();
    expect(() => serializePlatformProcessIdentity(linux, "darwin")).toThrow(/malformed|invalid/i);
    expect(() => serializePlatformProcessIdentity(darwin, "linux")).toThrow(/malformed|invalid/i);
  });

  it("normalizes raw adapter identities only for their selected platform", () => {
    expect(normalizePlatformProcessIdentity(linux, "linux")).toEqual(linux);
    expect(normalizePlatformProcessIdentity(darwin, "darwin")).toEqual(darwin);
    expect(normalizePlatformProcessIdentity(linux, "darwin")).toBeNull();
    expect(normalizePlatformProcessIdentity(darwin, "linux")).toBeNull();
    expect(normalizePlatformProcessIdentity({ ...darwin, pid: 0 }, "darwin")).toBeNull();
  });

  it("publishes exact input keys for platform-neutral durable normalization", () => {
    expect(PLATFORM_PROCESS_IDENTITY_KEYS).toEqual({
      linux: ["bootId", "pid", "startTimeTicks", "pidNamespaceInode", "ppid", "pgrp", "session"],
      darwin: [
        "platform",
        "formatVersion",
        "bootSessionToken",
        "pid",
        "processStartMicros",
        "ppid",
        "pgrp",
        "session"
      ]
    });
  });

  it("keeps platform identity encodings distinct", () => {
    const identities: readonly PlatformProcessIdentity[] = [linux, darwin];
    expect(serializePlatformProcessIdentity(identities[0]!, "linux")).not.toBe(
      serializePlatformProcessIdentity(identities[1]!, "darwin")
    );
  });
});
