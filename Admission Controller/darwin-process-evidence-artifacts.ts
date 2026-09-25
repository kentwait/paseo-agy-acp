import { lstatSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { PlatformProcessIdentity } from "./canonical-process-identity.js";
import {
  createDarwinProcessEvidence,
  type DarwinProcessEvidenceSource
} from "./darwin-process-evidence.js";
import {
  createLinuxProcessEvidence,
  type ProcessEvidence
} from "./process-evidence.js";

export const DARWIN_NATIVE_ARTIFACT_FILENAME = "darwin_process_evidence.node";
export const SUPPORTED_DARWIN_ARCHITECTURES = ["arm64", "x64"] as const;

export type SupportedDarwinArchitecture = (typeof SUPPORTED_DARWIN_ARCHITECTURES)[number];

export type DarwinProcessEvidenceArtifactErrorCode =
  | "unsupported_platform"
  | "unsupported_architecture"
  | "missing"
  | "load_failed"
  | "architecture_mismatch"
  | "invalid_exports";

export interface DarwinProcessEvidenceArtifactTarget {
  readonly platform: "darwin";
  readonly architecture: SupportedDarwinArchitecture;
  readonly relativePath: string;
  readonly path: string;
}

export interface DarwinProcessEvidenceArtifactLoadOptions {
  readonly platform?: string;
  readonly architecture?: string;
  readonly artifactExists?: (artifactPath: string) => boolean;
  readonly loadArtifact?: (artifactPath: string) => unknown;
}

interface DarwinProcessEvidenceArtifactErrorInput {
  readonly code: DarwinProcessEvidenceArtifactErrorCode;
  readonly expectedPlatform: string;
  readonly expectedArchitecture: string;
  readonly actualPlatform: string;
  readonly actualArchitecture: string;
  readonly artifactPath?: string;
}

export class DarwinProcessEvidenceArtifactError extends Error {
  readonly code: DarwinProcessEvidenceArtifactErrorCode;
  readonly expectedPlatform: string;
  readonly expectedArchitecture: string;
  readonly actualPlatform: string;
  readonly actualArchitecture: string;
  readonly artifactPath?: string;

  constructor(input: DarwinProcessEvidenceArtifactErrorInput) {
    super(formatArtifactError(input));
    this.name = "DarwinProcessEvidenceArtifactError";
    this.code = input.code;
    this.expectedPlatform = input.expectedPlatform;
    this.expectedArchitecture = input.expectedArchitecture;
    this.actualPlatform = input.actualPlatform;
    this.actualArchitecture = input.actualArchitecture;
    this.artifactPath = input.artifactPath;
  }
}

export function resolveDarwinProcessEvidenceArtifact(
  platform: string = process.platform,
  architecture: string = process.arch
): DarwinProcessEvidenceArtifactTarget {
  if (platform !== "darwin") {
    throw new DarwinProcessEvidenceArtifactError({
      code: "unsupported_platform",
      expectedPlatform: "darwin",
      expectedArchitecture: "arm64 or x64",
      actualPlatform: platform,
      actualArchitecture: architecture
    });
  }
  if (!isSupportedDarwinArchitecture(architecture)) {
    throw new DarwinProcessEvidenceArtifactError({
      code: "unsupported_architecture",
      expectedPlatform: "darwin",
      expectedArchitecture: "arm64 or x64",
      actualPlatform: platform,
      actualArchitecture: architecture
    });
  }

  const relativePath = `prebuilds/darwin-${architecture}/${DARWIN_NATIVE_ARTIFACT_FILENAME}`;
  return Object.freeze({
    platform: "darwin",
    architecture,
    relativePath,
    path: path.join(packageRoot(), ...relativePath.split("/"))
  });
}

export function loadPrebuiltDarwinProcessEvidenceSource(
  options: DarwinProcessEvidenceArtifactLoadOptions = {}
): DarwinProcessEvidenceSource {
  const platform = options.platform ?? process.platform;
  const architecture = options.architecture ?? process.arch;
  const target = resolveDarwinProcessEvidenceArtifact(platform, architecture);
  const artifactExists = options.artifactExists ?? defaultArtifactExists;

  let exists: boolean;
  try {
    exists = artifactExists(target.path);
  } catch {
    throw artifactError("load_failed", target, platform, architecture);
  }
  if (exists !== true) throw artifactError("missing", target, platform, architecture);

  let source: unknown;
  try {
    source = (options.loadArtifact ?? defaultArtifactLoader)(target.path);
  } catch (error) {
    const actualArchitecture = architectureFromLoadError(error);
    throw artifactError(
      actualArchitecture === null ? "load_failed" : "architecture_mismatch",
      target,
      platform,
      actualArchitecture ?? architecture
    );
  }
  if (!isDarwinProcessEvidenceSource(source)) {
    throw artifactError("invalid_exports", target, platform, architecture);
  }
  return source;
}

export function createHostProcessEvidence(
  options: DarwinProcessEvidenceArtifactLoadOptions = {}
): ProcessEvidence<PlatformProcessIdentity> {
  const platform = options.platform ?? process.platform;
  if (platform === "linux") return createLinuxProcessEvidence();
  return createDarwinProcessEvidence(loadPrebuiltDarwinProcessEvidenceSource({ ...options, platform }));
}

export function isSupportedDarwinArchitecture(value: string): value is SupportedDarwinArchitecture {
  return (SUPPORTED_DARWIN_ARCHITECTURES as readonly string[]).includes(value);
}

function packageRoot(): string {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  return path.basename(path.dirname(moduleDirectory)) === "dist"
    ? path.dirname(path.dirname(moduleDirectory))
    : path.dirname(moduleDirectory);
}

function defaultArtifactExists(artifactPath: string): boolean {
  try {
    const stat = lstatSync(artifactPath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error("artifact is not a regular file");
    }
    return true;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return false;
    }
    throw error;
  }
}

function defaultArtifactLoader(artifactPath: string): unknown {
  const require = createRequire(import.meta.url);
  return require(artifactPath) as unknown;
}

function isDarwinProcessEvidenceSource(value: unknown): value is DarwinProcessEvidenceSource {
  if (typeof value !== "object" || value === null) return false;
  try {
    return (
      typeof (value as Record<string, unknown>).captureProcess === "function" &&
      typeof (value as Record<string, unknown>).listProcesses === "function"
    );
  } catch {
    return false;
  }
}

function architectureFromLoadError(error: unknown): SupportedDarwinArchitecture | null {
  if (!(error instanceof Error)) return null;
  const match = /incompatible architecture.*?have\s+['"]?([^'"\s)]+)/i.exec(error.message);
  if (match === null) return null;
  const architecture = match[1]?.toLowerCase();
  if (architecture === "x86_64" || architecture === "x64") return "x64";
  if (architecture === "arm64" || architecture === "aarch64") return "arm64";
  return null;
}

function artifactError(
  code: DarwinProcessEvidenceArtifactErrorCode,
  target: DarwinProcessEvidenceArtifactTarget,
  actualPlatform: string,
  actualArchitecture: string
): DarwinProcessEvidenceArtifactError {
  return new DarwinProcessEvidenceArtifactError({
    code,
    expectedPlatform: target.platform,
    expectedArchitecture: target.architecture,
    actualPlatform,
    actualArchitecture,
    artifactPath: target.path
  });
}

function formatArtifactError(input: DarwinProcessEvidenceArtifactErrorInput): string {
  const target = `expected platform=${input.expectedPlatform} architecture=${input.expectedArchitecture}`;
  const actual = `actual platform=${input.actualPlatform} architecture=${input.actualArchitecture}`;
  const remediation = "Reinstall paseo-agy-acp on a supported macOS host. Contributors can run npm run build:native from a source checkout.";
  if (input.code === "unsupported_platform" || input.code === "unsupported_architecture") {
    return `Darwin process evidence requires ${target}; ${actual}. ${remediation}`;
  }
  const artifact = input.artifactPath === undefined ? "" : ` Artifact: ${input.artifactPath}.`;
  if (input.code === "missing") {
    return `Darwin process evidence prebuild is missing for ${target}; ${actual}.${artifact} ${remediation}`;
  }
  if (input.code === "architecture_mismatch") {
    return `Darwin process evidence artifact architecture does not match ${target}; ${actual}.${artifact} ${remediation}`;
  }
  if (input.code === "invalid_exports") {
    return `Darwin process evidence artifact has invalid native exports for ${target}; ${actual}.${artifact} ${remediation}`;
  }
  return `Darwin process evidence artifact could not be read or loaded for ${target}; ${actual}.${artifact} ${remediation}`;
}
