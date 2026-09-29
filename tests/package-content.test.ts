import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const REVIEWED_NATIVE_ARTIFACTS = [
  "prebuilds/darwin-arm64/darwin_process_evidence.node",
  "prebuilds/darwin-x64/darwin_process_evidence.node"
] as const;
const DARWIN_MACH_O_CPU_TYPES = {
  "darwin-arm64": 0x0100_000c,
  "darwin-x64": 0x0100_0007
} as const;

describe("published package content", () => {
  it("contains the P3 CLI and self-owned assets without kernel artifacts", () => {
    const manifest = JSON.parse(readFileSync(path.join(repositoryRoot, "package.json"), "utf8")) as {
      bin?: Record<string, string>;
    };
    expect(manifest.bin?.["agy-acp-prepare-official-kernel-compat"]).toBe(
      "scripts/prepare-official-kernel-compat.mjs"
    );

    const packedPaths = npmPackDryRunPaths();
    expect(packedPaths).toEqual(expect.arrayContaining([
      ...REVIEWED_NATIVE_ARTIFACTS,
      "scripts/prepare-official-kernel-compat.mjs",
      "assets/official-kernel-compat/rc01/paseo_model_compat.py",
      "dist/ACP Connector/official-kernel/kernel-compat-lifecycle.js",
      "dist/ACP Connector/official-kernel/kernel-compat-pins.js",
      "dist/ACP Connector/official-kernel/kernel-compat-rc01-recipe.js"
    ]));
    for (const artifact of REVIEWED_NATIVE_ARTIFACTS) {
      const artifactPath = path.join(repositoryRoot, artifact);
      const stat = lstatSync(artifactPath);
      expect(stat.isFile()).toBe(true);
      expect(stat.isSymbolicLink()).toBe(false);
      const artifactBytes = readFileSync(artifactPath);
      expect(artifactBytes.length).toBeGreaterThanOrEqual(16);
      expect(artifactBytes.readUInt32LE(0)).toBe(0xfeed_facf);
      expect(artifactBytes.readUInt32LE(4)).toBe(
        artifact.includes("darwin-arm64") ? DARWIN_MACH_O_CPU_TYPES["darwin-arm64"] : DARWIN_MACH_O_CPU_TYPES["darwin-x64"]
      );
      expect(artifactBytes.readUInt32LE(12)).toBe(8);
    }

    const prohibited = packedPaths.filter(isProhibitedPublishedPath);
    expect(prohibited).toEqual([]);

    const allowed = packedPaths.filter((entry) => !isExpectedPublishedPath(entry));
    expect(allowed).toEqual([]);
  });

  it("rejects unreviewed native, state, credential, build, receipt, and temporary content", () => {
    const rejected = [
      "prebuilds/darwin-aarch64/darwin_process_evidence.node",
      "prebuilds/darwin-arm64/unreviewed.node",
      "native/darwin-process-evidence.cc",
      "binding.gyp",
      "build/Release/darwin_process_evidence.node",
      "runtime.sqlite",
      "runtime.sqlite-wal",
      "runtime.sqlite-shm",
      "admission.key",
      ".env",
      "credentials.json",
      "docs/receipt.json",
      "tmp/addon.node",
      "assets/proprietary-kernel.par"
    ];
    expect(rejected.filter(isProhibitedPublishedPath)).toEqual(rejected);
    expect(rejected.filter(isExpectedPublishedPath)).toEqual([]);
  });
});

function npmPackDryRunPaths(): string[] {
  const result = spawnSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, npm_config_color: "false" }
  });
  expect(result.status).toBe(0);
  const payload = JSON.parse(result.stdout) as Array<{ files?: Array<{ path: string }> }>;
  expect(payload).toHaveLength(1);
  expect(payload[0].files).toBeDefined();
  return payload[0].files?.map((file) => file.path).sort() ?? [];
}

function isExpectedPublishedPath(entry: string): boolean {
  return (REVIEWED_NATIVE_ARTIFACTS as readonly string[]).includes(entry) ||
    entry === "package.json" ||
    entry === "README.md" ||
    entry === "README.zh-CN.md" ||
    entry === "CHANGELOG.md" ||
    entry === "LICENSE" ||
    entry === "scripts/prepare-admission-state-dir.mjs" ||
    entry === "scripts/prepare-official-kernel-compat.mjs" ||
    entry === "assets/official-kernel-compat/rc01/paseo_model_compat.py" ||
    /^dist\/(?:ACP Connector|Admission Controller)\/.+\.(?:js|d\.ts|js\.map)$/.test(entry);
}

function isProhibitedPublishedPath(entry: string): boolean {
  return (
    ((/\.node$/i.test(entry) || /^native\//i.test(entry) || /^build\//i.test(entry)) &&
      !(REVIEWED_NATIVE_ARTIFACTS as readonly string[]).includes(entry)) ||
    /^binding\.gyp$/i.test(entry) ||
    /^node_modules\//i.test(entry) ||
    /(?:\.sqlite(?:-wal|-shm)?|\.db(?:-wal|-shm)?)$/i.test(entry) ||
    /(^|\/)admission\.key$/i.test(entry) ||
    /(^|\/)\.env(?:\.|$)/i.test(entry) ||
    /(^|\/)[^/]*(?:credential|secret|token)[^/]*$/i.test(entry) ||
    /(^|\/)receipt(?:\.json)?$/i.test(entry) ||
    /(^|\/)(?:tmp|temp)(?:\/|$)/i.test(entry) ||
    /(^|\/)[^/]*\.par$/i.test(entry) ||
    /(^|\/)[^/]*\.elf$/i.test(entry) ||
    /(^|\/)localharness_external(?:\/|$)/i.test(entry) ||
    /(^|\/)[^/]*\.runfiles(?:\/|$)/i.test(entry) ||
    /(^|\/)[^/]*probe[^/]*$/i.test(entry) ||
    /(^|\/)[^/]*proprietary[^/]*$/i.test(entry)
  );
}
