#!/usr/bin/env node
// Wrapper para `npx stingward`: roda a CLI em Python que vem dentro do pacote.
const { spawnSync } = require("child_process");
const path = require("path");

const root = path.join(__dirname, "..");
// -I: um projeto auditado com uma pasta stingward/ (ou um json.py) não substitui o código do pacote.
const boot = "import sys; sys.path.insert(0, sys.argv.pop(1)); from stingward.cli import main; sys.exit(main(sys.argv[1:]))";
for (const py of process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"]) {
  const r = spawnSync(py, ["-I", "-c", boot, root, ...process.argv.slice(2)], { stdio: "inherit" });
  if (!r.error) process.exit(r.status === null ? 1 : r.status);
}
console.error("stingward precisa de Python 3.9+ instalado (https://www.python.org/downloads/).");
process.exit(2);
