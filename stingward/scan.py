"""Motor: lista os arquivos, roda as verificações e aplica o .stingwardignore."""
from __future__ import annotations

import fnmatch
import os
import re

from . import gitsafe, review
from .checks import TESTISH, agents, app, code, deps, is_text_source, secrets
from .model import SEV_RANK, TEXT_BOMS, Context, decode_text

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".next", ".nuxt", ".svelte-kit", ".turbo",
             "dist", "build", "out", "coverage", ".cache", "target", "vendor", ".pytest_cache", ".mypy_cache", ".tox",
             ".idea", ".gradle", "Pods", ".terraform", ".vercel", ".netlify", ".expo", ".parcel-cache"}
# Numa skill ou servidor MCP, o que roda costuma ser o build: dist/, build/, out/, vendor/.
SKILL_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox"}
MAX_FILES = 50_000
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


def _walk(root: str, skip):
    """(pasta, arquivos) na ordem do os.walk, sem descer em link simbólico nem nas pastas de skip.

    Sem recursão: no Python até 3.11 o os.walk é recursivo, e uma skill com mil pastas aninhadas derrubava a
    varredura com RecursionError."""
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            continue
        dirs, files = [], []
        for e in entries:
            try:
                is_dir = e.is_dir()
            except OSError:
                is_dir = False
            (dirs if is_dir else files).append(e.name)
        yield d, sorted(files)
        for name in sorted((x for x in dirs if x not in skip), reverse=True):
            p = os.path.join(d, name)
            if not os.path.islink(p):
                stack.append(p)


def list_files(root: str, max_files: int = MAX_FILES, mode: str = "project", too_big=None):
    """Arquivos a auditar, relativos a root. too_big, se for uma lista, recebe os de código e texto que passaram
    do limite de tamanho: a auditoria não os cobre, e quem lê o relatório precisa saber."""
    out = []
    skip = SKILL_SKIP_DIRS if mode == "skill" else SKIP_DIRS
    limit = SKILL_MAX_BYTES if mode == "skill" else MAX_BYTES
    for d, files in _walk(root, skip):
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            if st.st_size > (LOCK_MAX_BYTES if _LOCKFILE.search(rel) else limit):
                if too_big is not None and is_text_source(rel, mode):
                    too_big.append(rel)
                continue
            # Byte nulo indica binário, mas não basta para pular código: um "/*\0*/" no topo esconderia o arquivo.
            # Texto em UTF-16 (com BOM) tem um nulo a cada letra ASCII e é texto.
            if not _CODE_EXT.search(rel):
                try:
                    with open(p, "rb") as fh:
                        head = fh.read(4096)
                    if b"\0" in head and not head.startswith(TEXT_BOMS):
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
        # Comentário em Latin-1, BOM no início ou UTF-16 (echo REGRA > .stingwardignore no PowerShell) não podem
        # derrubar a varredura nem anular as linhas.
        with open(os.path.join(root, ".stingwardignore"), "rb") as fh:
            for line in decode_text(fh.read()).split("\n"):
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
    too_big, truncated = [], False
    if files is None:
        # Um a mais que o limite só para saber se havia mais: parar calado deixaria parte do código fora sem aviso.
        files = list_files(root, max_files=MAX_FILES + 1, mode=mode, too_big=too_big)
        truncated = len(files) > MAX_FILES
        files = files[:MAX_FILES]
    ctx = Context(root=root, files=files, offline=offline, mode=mode, too_big=too_big, truncated=truncated)
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
    return ctx, review.assign(ctx, uniq)
