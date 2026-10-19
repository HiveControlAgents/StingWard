#!/usr/bin/env node
// Wrapper para `npx stingward`: roda a CLI em Python que vem dentro do pacote.
const { spawnSync } = require("child_process");
const path = require("path");

const root = path.join(__dirname, "..");
const env = { ...process.env, PYTHONPATH: [root, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter) };
for (const py of process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"]) {
  const r = spawnSync(py, ["-m", "stingward", ...process.argv.slice(2)], { stdio: "inherit", env });
  if (!r.error) process.exit(r.status === null ? 1 : r.status);
}
console.error("stingward precisa de Python 3.9+ instalado (https://www.python.org/downloads/).");
process.exit(2);
