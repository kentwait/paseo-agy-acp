import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

if (process.platform !== "darwin") process.exit(0);

const nodeGyp = fileURLToPath(new URL("../node_modules/node-gyp/bin/node-gyp.js", import.meta.url));
const result = spawnSync(process.execPath, [nodeGyp, "rebuild"], {
  cwd: fileURLToPath(new URL("..", import.meta.url)),
  stdio: "inherit"
});

if (result.error !== undefined) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
