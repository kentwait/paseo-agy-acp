import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const packageRoot = process.env.PASEO_AGY_ACP_INSTALLED_ROOT;
if (packageRoot === undefined) throw new Error("installed package root is required");

const hostModule = await import(pathToFileURL(path.join(packageRoot, "dist/Admission Controller/darwin-process-evidence-artifacts.js")).href);
const processEvidence = hostModule.createHostProcessEvidence();
const identity = processEvidence.capture(process.pid);
const artifact = process.platform === "darwin"
  ? hostModule.resolveDarwinProcessEvidenceArtifact()
  : null;
const base = {
  nodeVersion: process.version,
  platform: processEvidence.platform,
  architecture: process.arch,
  napiVersion: Number(process.versions.napi),
  artifact,
  identity
};

if (process.env.PASEO_AGY_ACP_NATIVE_ONLY === "1") {
  process.stdout.write(`${JSON.stringify(base)}\n`);
} else {
  const controllerModule = await import(pathToFileURL(path.join(packageRoot, "dist/Admission Controller/controller.js")).href);
  const policy = Object.freeze({
    maxActiveTurns: 3,
    maxConcurrentStarts: 1,
    minStartIntervalMs: 2_000,
    queueTimeoutMs: 30 * 60_000,
    capacityCooldownMs: 30_000
  });
  const stateDir = mkdtempSync(path.join(os.tmpdir(), "paseo-installed-admission-"));
  const controller = new controllerModule.AdmissionController({
    databasePath: path.join(stateDir, "runtime.sqlite"),
    policy,
    encryptionKey: Buffer.alloc(32, 131),
    contentFingerprintKey: Buffer.alloc(32, 132),
    processEvidence
  });

  try {
    controller.claimDurablePolicy(policy, randomUUID(), Date.now());
    controller.enqueue({
      requestId: randomUUID(),
      sessionId: randomUUID(),
      agentId: randomUUID(),
      fingerprint: randomUUID(),
      provider: "antigravity",
      model: "installed-package-test",
      now: Date.now()
    });
    const owners = controller.listRecoverableQueuedOwners();
    process.stdout.write(`${JSON.stringify({
      ...base,
      schemaVersion: controller.schemaVersion,
      queuedOwners: owners.map((owner) => ({
        requestId: owner.requestId,
        platform: owner.owner.platform ?? "linux"
      }))
    })}\n`);
  } finally {
    controller.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
}
