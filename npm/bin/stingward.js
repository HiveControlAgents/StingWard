#!/usr/bin/env node
// Wrapper para `npx stingward`: roda a CLI em Python que vem dentro do pacote.
const { spawnSync } = require("child_process");
const os = require("os");
const path = require("path");

const root = path.join(__dirname, "..");
// -I: um projeto auditado com uma pasta stingward/ (ou um json.py) não substitui o código do pacote.
const boot = "import sys; sys.path.insert(0, sys.argv.pop(1)); from stingward.cli import main; sys.exit(main(sys.argv[1:]))";
// Pergunta a versão antes, com código que até o Python 2 entende (e sem -I, que ele não conhece): um Python velho
// não chega a rodar o pacote e quebrar com código 1, que quer dizer "achou problema". -E -s: nada do ambiente.
const probe = "import sys; sys.stdout.write('%d.%d' % sys.version_info[:2])";

// No Windows, `py -3` é o lançador oficial e escolhe o Python 3 mais novo; `py` sozinho pode abrir um Python 2.
function candidates(platform) {
  return platform === "win32" ? [["py", "-3"], ["python"], ["python3"]] : [["python3"], ["python"]];
}

function main(args) {
  const old = [];
  for (const [cmd, ...pre] of candidates(process.platform)) {
    // O "python" falso da Microsoft Store e os shims quebrados não respondem uma versão: passa para o próximo.
    const v = spawnSync(cmd, [...pre, "-E", "-s", "-c", probe], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const m = !v.error && v.status === 0 && /^(\d+)\.(\d+)$/.exec(String(v.stdout).trim());
    if (!m) continue;
    if (Number(m[1]) < 3 || (Number(m[1]) === 3 && Number(m[2]) < 9)) {
      old.push(`${[cmd, ...pre].join(" ")} = ${m[0]}`);
      continue;
    }
    const r = spawnSync(cmd, [...pre, "-I", "-c", boot, root, ...args], { stdio: "inherit" });
    if (r.error) continue;
    if (r.signal) {
      // Morto por sinal (Ctrl-C, kill): sai do mesmo jeito, nunca com 1.
      process.kill(process.pid, r.signal);
      process.exit(128 + (os.constants.signals[r.signal] || 0));
    }
    process.exit(r.status);
  }
  console.error("stingward precisa de Python 3.9+ / stingward needs Python 3.9+: https://www.python.org/downloads/");
  if (old.length) console.error(`Encontrado / found: ${old.join(", ")}`);
  process.exit(2);
}

module.exports = { candidates };
if (require.main === module) main(process.argv.slice(2));
