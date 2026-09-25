import { spawnSync } from "node:child_process";
import { copyFileSync, lstatSync, mkdirSync, renameSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const architectureArgument = process.argv[2];
if (process.platform !== "darwin") throw new Error("Darwin prebuilds can only be built on macOS");
if (architectureArgument !== "--arch=arm64" && architectureArgument !== "--arch=x64") {
  throw new Error("Darwin prebuild architecture must be --arch=arm64 or --arch=x64");
}

const architecture = architectureArgument.slice("--arch=".length);
const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const nodeGyp = path.join(repositoryRoot, "node_modules/node-gyp/bin/node-gyp.js");
const result = spawnSync(process.execPath, [nodeGyp, "rebuild", architectureArgument], {
  cwd: repositoryRoot,
  stdio: "inherit"
});
if (result.error !== undefined) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);

const source = path.join(repositoryRoot, "build/Release/darwin_process_evidence.node");
const sourceStat = lstatSync(source);
if (sourceStat.isSymbolicLink() || !sourceStat.isFile()) {
  throw new Error("node-gyp did not produce a regular Darwin artifact");
}

const targetDirectory = path.join(repositoryRoot, "prebuilds", `darwin-${architecture}`);
const target = path.join(targetDirectory, "darwin_process_evidence.node");
const staging = `${target}.staging`;
mkdirSync(targetDirectory, { recursive: true });
rmSync(staging, { force: true });
copyFileSync(source, staging);
renameSync(staging, target);
