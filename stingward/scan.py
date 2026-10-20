"""Motor: lista os arquivos, roda as verificações e aplica o .stingwardignore."""
from __future__ import annotations

import fnmatch
import os
import re

from . import gitsafe
from .checks import TESTISH, agents, app, code, deps, secrets
from .model import SEV_RANK, Context

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".next", ".nuxt", ".svelte-kit", ".turbo",
             "dist", "build", "out", "coverage", ".cache", "target", "vendor", ".pytest_cache", ".mypy_cache", ".tox",
             ".idea", ".gradle", "Pods", ".terraform", ".vercel", ".netlify", ".expo", ".parcel-cache"}
# Numa skill ou servidor MCP, o que roda costuma ser o build: dist/, build/, out/, vendor/.
SKILL_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox"}
MAX_BYTES = 2_000_000
SKILL_MAX_BYTES = 10_000_000
LOCK_MAX_BYTES = 64_000_000
_LOCKFILE = re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|"
                       r"poetry\.lock|uv\.lock|pdm\.lock|Pipfile\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock)$")
_CODE_EXT = re.compile(r"\.(js|mjs|cjs|ts|py|sh|bash|ps1|rb|php|go|rs|json|md|toml|ya?ml)$", re.I)

_TESTISH = TESTISH

# Severidade máxima de cada regra em código de teste e exemplo, por modo. Numa skill, payload em tests/ costuma ser
# exemplo, mas o autor escolhe o nome da pasta: baixa só até médio. Falha de código (injeção, XSS) em teste de skill
# não roda na máquina de quem instala, então vai a baixo.
_CODE_RULES = ("COD", "APP009", "APP012", "APP013", "APP014")
_TEST_DOWNGRADE = {"project": {"low": ("APP", "SKL001", "COD")},
                   "skill": {"medium": ("SKL002", "SKL004", "SKL005", "SKL007", "SKL008"), "low": _CODE_RULES},
                   "agents": {}}

CHECKS = {"deps": deps.check, "secrets": secrets.check, "app": app.check, "code": code.check, "agents": agents.check}


def list_files(root: str, max_files: int = 50_000, mode: str = "project"):
    out = []
    skip = SKILL_SKIP_DIRS if mode == "skill" else SKIP_DIRS
    limit = SKILL_MAX_BYTES if mode == "skill" else MAX_BYTES
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in skip)
        for f in sorted(files):
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            if st.st_size > (LOCK_MAX_BYTES if _LOCKFILE.search(rel) else limit):
                continue
            # Byte nulo indica binário, mas não basta para pular código: um "/*\0*/" no topo esconderia o arquivo.
            if not _CODE_EXT.search(rel):
                try:
                    with open(p, "rb") as fh:
                        if b"\0" in fh.read(4096):
                            continue
                except OSError:
                    continue
            out.append(rel)
            if len(out) >= max_files:
                return out
    return out


def git_tracked(root: str):
    """Arquivos versionados, relativos a root. Funciona numa subpasta do repositório, worktree ou submódulo."""
    r = gitsafe.run(root, "ls-files", "-z")
    if r is None or r.returncode != 0:
        return None
    return {p for p in r.stdout.decode("utf-8", "replace").split("\0") if p}


def load_ignore(root: str):
    """Linhas do .stingwardignore: `REGRA`, `caminho/glob` ou `REGRA caminho/glob`."""
    rules = []
    try:
        with open(os.path.join(root, ".stingwardignore"), encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    rules.append((parts[0], parts[1]))
                elif parts[0][:3].isalpha() and parts[0][:3].isupper() and parts[0][3:].isdigit():
                    rules.append((parts[0], "*"))
                else:
                    rules.append(("*", parts[0]))
    except OSError:
        pass
    return rules


def _ignored(f, rules):
    return any((r == "*" or r == f.rule) and (g == "*" or fnmatch.fnmatch(f.file, g) or f.file.startswith(g.rstrip("/") + "/"))
               for r, g in rules)


def run(root: str, mode: str = "project", offline: bool = False, only=None, files=None):
    root = os.path.abspath(root)
    ctx = Context(root=root, files=files if files is not None else list_files(root, mode=mode), offline=offline, mode=mode)
    ctx.git_tracked = git_tracked(root) if mode != "agents" else None
    findings = []
    for name, fn in CHECKS.items():
        if only and name not in only:
            continue
        findings.extend(fn(ctx))
    for f in findings:
        # Código de teste e exemplos costuma ter problema de propósito: continua no relatório, mas baixo.
        if not _TESTISH.search(f.file):
            continue
        for floor, prefixes in _TEST_DOWNGRADE[mode].items():
            if f.rule.startswith(prefixes) and SEV_RANK[f.severity] > SEV_RANK[floor]:
                f.severity = floor
    rules = load_ignore(root) if mode == "project" else []
    uniq, seen = [], set()
    # O mesmo token no config do MCP vira AGT004, que explica melhor; os outros segredos do arquivo continuam.
    agt004 = {(f.file, f.line) for f in findings if f.rule == "AGT004"}
    for f in findings:
        if f.key() in seen or _ignored(f, rules):
            continue
        if f.rule == "SEC001" and (f.file, f.line) in agt004:
            continue
        seen.add(f.key())
        uniq.append(f)
    uniq.sort(key=lambda f: (-SEV_RANK[f.severity], "kev" not in f.tags, f.rule, f.file, f.line or 0))
    return ctx, uniq
