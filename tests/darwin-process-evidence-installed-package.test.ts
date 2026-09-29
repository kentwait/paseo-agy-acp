import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const helperPath = path.join(repositoryRoot, "tests/helpers/installed-admission-package-smoke.mjs");
const packageName = "paseo-agy-acp";

interface InstalledSmokeResult {
  nodeVersion: string;
  platform: string;
  architecture: string;
  napiVersion: number;
  artifact: { relativePath: string } | null;
  identity: { pid: number; platform?: string };
  schemaVersion?: number;
  queuedOwners?: Array<{ requestId: string; platform: string }>;
}

describe("installed package Darwin process evidence", () => {
  it("loads the packaged host artifact and opens a fresh schema v4 account pool", () => {
    const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), "paseo-installed-package-test-"));
    try {
      const packDirectory = path.join(temporaryRoot, "pack");
      const installDirectory = path.join(temporaryRoot, "install");
      mkdirSync(packDirectory);
      mkdirSync(installDirectory);

      const packed = spawnSync("npm", ["pack", "--json", "--pack-destination", packDirectory], {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: { ...process.env, npm_config_color: "false" },
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024
      });
      expectCommandSuccess(packed, "npm pack");
      const packPayload = JSON.parse(packed.stdout) as Array<{ filename: string }>;
      expect(packPayload).toHaveLength(1);
      const tarball = path.join(packDirectory, packPayload[0]!.filename);

      const installed = spawnSync("npm", ["install", "--no-audit", "--no-fund", tarball], {
        cwd: installDirectory,
        encoding: "utf8",
        env: { ...process.env, npm_config_color: "false", npm_config_ignore_scripts: "false" },
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024
      });
      expectCommandSuccess(installed, "npm install");

      const installedRoot = path.join(installDirectory, "node_modules", packageName);
      expect(JSON.parse(readFileSync(path.join(installedRoot, "package.json"), "utf8")) as { name: string }).toMatchObject({
        name: packageName
      });
      for (const artifact of [
        "prebuilds/darwin-arm64/darwin_process_evidence.node",
        "prebuilds/darwin-x64/darwin_process_evidence.node"
      ]) {
        expect(existsSync(path.join(installedRoot, artifact))).toBe(true);
      }
      for (const sourceArtifact of ["binding.gyp", "native", "build"]) {
        expect(existsSync(path.join(installedRoot, sourceArtifact))).toBe(false);
      }

      const smoke = spawnSync(process.execPath, [helperPath], {
        cwd: installedRoot,
        encoding: "utf8",
        env: { ...process.env, PASEO_AGY_ACP_INSTALLED_ROOT: installedRoot },
        timeout: 30_000,
        maxBuffer: 10 * 1024 * 1024
      });
      expectCommandSuccess(smoke, "installed package smoke");
      const result = JSON.parse(smoke.stdout.trim()) as InstalledSmokeResult;
      expect(result.napiVersion).toBeGreaterThanOrEqual(8);
      expect(result.architecture).toBe(process.arch);
      expect(result.schemaVersion).toBe(4);
      expect(result.queuedOwners).toHaveLength(1);
      expect(result.nodeVersion).toBe(process.version);
      expect(result.identity.pid).toBe(smoke.pid);

      if (process.platform === "darwin") {
        expect(result.platform).toBe("darwin");
        expect(result.identity.platform).toBe("darwin");
        expect(result.queuedOwners?.[0]?.platform).toBe("darwin");
        expect(result.artifact?.relativePath).toBe(`prebuilds/darwin-${process.arch}/darwin_process_evidence.node`);
      } else if (process.platform === "linux") {
        expect(result.platform).toBe("linux");
        expect(result.identity.platform).toBeUndefined();
        expect(result.queuedOwners?.[0]?.platform).toBe("linux");
        expect(result.artifact).toBeNull();
      } else {
        throw new Error(`unsupported installed-test platform ${process.platform}`);
      }

      const additionalNodeExecutables = process.env.PASEO_AGY_ACP_TEST_NODE_EXECUTABLES;
      if (additionalNodeExecutables !== undefined) {
        const observedNodeMajors = new Set([Number(process.versions.node.split(".")[0])]);
        const parsed = JSON.parse(additionalNodeExecutables) as unknown;
        if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== "string")) {
          throw new Error("PASEO_AGY_ACP_TEST_NODE_EXECUTABLES must be a JSON string array");
        }
        for (const executable of parsed) {
          expect(existsSync(executable)).toBe(true);
          const nativeSmoke = spawnSync(executable, [helperPath], {
            cwd: installedRoot,
            encoding: "utf8",
            env: {
              ...process.env,
              PASEO_AGY_ACP_INSTALLED_ROOT: installedRoot,
              PASEO_AGY_ACP_NATIVE_ONLY: "1"
            },
            timeout: 30_000,
            maxBuffer: 10 * 1024 * 1024
          });
          expectCommandSuccess(nativeSmoke, `installed native artifact smoke with ${executable}`);
          const nativeResult = JSON.parse(nativeSmoke.stdout.trim()) as InstalledSmokeResult;
          observedNodeMajors.add(Number(nativeResult.nodeVersion.slice(1).split(".")[0]));
          expect(nativeResult.nodeVersion).toMatch(/^v\d+\./);
          expect(nativeResult.platform).toBe(result.platform);
          expect(nativeResult.architecture).toBe(process.arch);
          expect(nativeResult.napiVersion).toBeGreaterThanOrEqual(8);
          expect(nativeResult.identity.pid).toBe(nativeSmoke.pid);
          expect(nativeResult.artifact?.relativePath).toBe(result.artifact?.relativePath);
        }
        expect(observedNodeMajors.has(22)).toBe(true);
        expect(observedNodeMajors.has(24)).toBe(true);
      }
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  }, 180_000);
});

function expectCommandSuccess(
  result: ReturnType<typeof spawnSync>,
  command: string
): void {
  expect(result.status, `${command} failed:\n${result.stderr}`).toBe(0);
}
