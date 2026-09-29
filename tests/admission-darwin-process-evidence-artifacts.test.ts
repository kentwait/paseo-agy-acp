import { describe, expect, it } from "vitest";
import {
  createHostProcessEvidence,
  DarwinProcessEvidenceArtifactError,
  loadPrebuiltDarwinProcessEvidenceSource,
  resolveDarwinProcessEvidenceArtifact,
  SUPPORTED_DARWIN_ARCHITECTURES,
  type DarwinProcessEvidenceArtifactLoadOptions
} from "../Admission Controller/darwin-process-evidence-artifacts.js";
import type { DarwinNativeProcessRecord } from "../Admission Controller/darwin-process-evidence.js";

const PROCESS_START_MICROS = "1700000000123456";
const BOOT_SESSION_TOKEN = "1800000000000000000";

function nativeRecord(overrides: Partial<DarwinNativeProcessRecord> = {}): DarwinNativeProcessRecord {
  return {
    bootSessionToken: BOOT_SESSION_TOKEN,
    pid: process.pid,
    processStartMicros: PROCESS_START_MICROS,
    ppid: process.ppid,
    pgrp: process.pid,
    session: process.pid,
    ...overrides
  };
}

function nativeSource(record: DarwinNativeProcessRecord = nativeRecord()): unknown {
  return {
    captureProcess(pid: number): unknown {
      return pid === record.pid ? { status: "ok", process: record } : { status: "gone" };
    },
    listProcesses(): unknown {
      return { status: "ok", complete: true, processes: [record] };
    }
  };
}

function captureError(options: DarwinProcessEvidenceArtifactLoadOptions): DarwinProcessEvidenceArtifactError {
  try {
    loadPrebuiltDarwinProcessEvidenceSource(options);
  } catch (error) {
    if (error instanceof DarwinProcessEvidenceArtifactError) return error;
    throw error;
  }
  throw new Error("expected Darwin artifact loading to fail");
}

describe("packaged Darwin process evidence artifacts", () => {
  it("selects only the reviewed target for the actual Darwin architecture", () => {
    expect(SUPPORTED_DARWIN_ARCHITECTURES).toEqual(["arm64", "x64"]);
    expect(resolveDarwinProcessEvidenceArtifact("darwin", "arm64")).toMatchObject({
      platform: "darwin",
      architecture: "arm64",
      relativePath: "prebuilds/darwin-arm64/darwin_process_evidence.node"
    });
    expect(resolveDarwinProcessEvidenceArtifact("darwin", "x64")).toMatchObject({
      platform: "darwin",
      architecture: "x64",
      relativePath: "prebuilds/darwin-x64/darwin_process_evidence.node"
    });
  });

  it("loads the host-matching prebuild without falling back to another architecture or source build", () => {
    const loadedPaths: string[] = [];
    const source = nativeSource();
    const loaded = loadPrebuiltDarwinProcessEvidenceSource({
      platform: "darwin",
      architecture: "x64",
      artifactExists: (artifactPath) => artifactPath.endsWith("prebuilds/darwin-x64/darwin_process_evidence.node"),
      loadArtifact: (artifactPath) => {
        loadedPaths.push(artifactPath);
        return source;
      }
    });

    expect(loaded).toBe(source);
    expect(loadedPaths).toHaveLength(1);
    expect(loadedPaths[0]).toMatch(/prebuilds\/darwin-x64\/darwin_process_evidence\.node$/);
  });

  it("reports unsupported platforms, unsupported architectures, and missing artifacts with remediation", () => {
    const unsupportedPlatform = captureError({ platform: "linux", architecture: "x64" });
    expect(unsupportedPlatform).toMatchObject({
      code: "unsupported_platform",
      expectedPlatform: "darwin",
      actualPlatform: "linux",
      actualArchitecture: "x64"
    });
    expect(unsupportedPlatform.message).toMatch(/expected platform=darwin architecture=arm64 or x64.*actual platform=linux architecture=x64/i);
    expect(unsupportedPlatform.message).toMatch(/supported macOS/i);

    const unsupportedArchitecture = captureError({ platform: "darwin", architecture: "ppc64" });
    expect(unsupportedArchitecture).toMatchObject({
      code: "unsupported_architecture",
      expectedPlatform: "darwin",
      actualPlatform: "darwin",
      actualArchitecture: "ppc64"
    });
    expect(unsupportedArchitecture.message).toMatch(/actual platform=darwin architecture=ppc64/i);
    expect(unsupportedArchitecture.message).toMatch(/reinstall/i);

    let loadCalled = false;
    const missing = captureError({
      platform: "darwin",
      architecture: "arm64",
      artifactExists: () => false,
      loadArtifact: () => {
        loadCalled = true;
        return nativeSource();
      }
    });
    expect(loadCalled).toBe(false);
    expect(missing).toMatchObject({ code: "missing", actualPlatform: "darwin", actualArchitecture: "arm64" });
    expect(missing.artifactPath).toMatch(/prebuilds\/darwin-arm64\/darwin_process_evidence\.node$/);
    expect(missing.message).toMatch(/missing/i);
    expect(missing.message).toMatch(/npm run build:native/i);
  });

  it("reports unreadable and architecture-mismatched artifacts with expected and actual targets", () => {
    const unreadable = captureError({
      platform: "darwin",
      architecture: "arm64",
      artifactExists: () => true,
      loadArtifact: () => {
        throw Object.assign(new Error("permission denied"), { code: "EACCES" });
      }
    });
    expect(unreadable).toMatchObject({ code: "load_failed", actualPlatform: "darwin", actualArchitecture: "arm64" });
    expect(unreadable.message).toMatch(/could not be read or loaded/i);
    expect(unreadable.message).toMatch(/expected platform=darwin architecture=arm64.*actual platform=darwin architecture=arm64/i);
    expect(unreadable.message).toMatch(/reinstall/i);

    const mismatched = captureError({
      platform: "darwin",
      architecture: "arm64",
      artifactExists: () => true,
      loadArtifact: () => {
        throw new Error("mach-o file, but is an incompatible architecture (have 'x86_64', need 'arm64')");
      }
    });
    expect(mismatched).toMatchObject({
      code: "architecture_mismatch",
      expectedPlatform: "darwin",
      expectedArchitecture: "arm64",
      actualPlatform: "darwin",
      actualArchitecture: "x64"
    });
    expect(mismatched.message).toMatch(/actual platform=darwin architecture=x64/i);
    expect(mismatched.message).toMatch(/reinstall/i);
  });

  it("rejects an artifact whose native exports are invalid", () => {
    const invalid = captureError({
      platform: "darwin",
      architecture: "x64",
      artifactExists: () => true,
      loadArtifact: () => ({ captureProcess() {} })
    });
    expect(invalid).toMatchObject({ code: "invalid_exports", actualArchitecture: "x64" });
    expect(invalid.message).toMatch(/invalid native exports/i);
  });

  it("selects Linux without artifact access and Darwin with the matching prebuild", () => {
    let artifactAccess = false;
    const linux = createHostProcessEvidence({
      platform: "linux",
      architecture: "x64",
      artifactExists: () => {
        artifactAccess = true;
        return false;
      }
    });
    expect(linux.platform).toBe("linux");
    expect(artifactAccess).toBe(false);

    const darwin = createHostProcessEvidence({
      platform: "darwin",
      architecture: "arm64",
      artifactExists: () => true,
      loadArtifact: () => nativeSource()
    });
    expect(darwin.platform).toBe("darwin");
    expect(darwin.capture(process.pid)).toMatchObject({
      platform: "darwin",
      formatVersion: 1,
      pid: process.pid
    });
  });

  it.skipIf(
    process.platform !== "darwin" || !SUPPORTED_DARWIN_ARCHITECTURES.includes(process.arch as "arm64" | "x64")
  )("loads the checked-in artifact for the current host", () => {
    const source = loadPrebuiltDarwinProcessEvidenceSource();
    const adapter = createHostProcessEvidence();
    const identity = adapter.capture(process.pid);
    expect(source).toBeDefined();
    expect(identity).toMatchObject({ platform: "darwin", pid: process.pid });
  });
});
