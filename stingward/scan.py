"""Motor: lista os arquivos, roda as verificações e aplica o .stingwardignore."""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess

from .checks import agents, app, deps, secrets
from .model import SEV_RANK, Context

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".next", ".nuxt", ".svelte-kit", ".turbo",
             "dist", "build", "out", "coverage", ".cache", "target", "vendor", ".pytest_cache", ".mypy_cache", ".tox",
             ".idea", ".gradle", "Pods", ".terraform", ".vercel", ".netlify", ".expo", ".parcel-cache"}
MAX_BYTES = 2_000_000

_TESTISH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|examples?|mocks?)(/|$)|[._-](test|spec)\.")

CHECKS = {"deps": deps.check, "secrets": secrets.check, "app": app.check, "agents": agents.check}


def list_files(root: str, max_files: int = 50_000):
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not (x.startswith(".") and x in (".DS_Store",)))
        for f in sorted(files):
            p = os.path.join(d, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or os.path.islink(p) or st.st_size > MAX_BYTES:
                continue
            try:
                with open(p, "rb") as fh:
                    if b"\0" in fh.read(4096):
                        continue
            except OSError:
                continue
            out.append(os.path.relpath(p, root).replace(os.sep, "/"))
            if len(out) >= max_files:
                return out
    return out


def git_tracked(root: str):
    if not os.path.isdir(os.path.join(root, ".git")):
        return None
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
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
    ctx = Context(root=root, files=files if files is not None else list_files(root), offline=offline, mode=mode)
    ctx.git_tracked = git_tracked(root) if mode != "agents" else None
    findings = []
    for name, fn in CHECKS.items():
        if only and name not in only:
            continue
        findings.extend(fn(ctx))
    for f in findings:
        # Código de teste e exemplos costuma ter problema de propósito: continua no relatório, mas baixo.
        if mode == "project" and f.rule.startswith(("APP", "SKL001")) and _TESTISH.search(f.file):
            f.severity = "low"
    rules = load_ignore(root) if mode == "project" else []
    uniq, seen = [], set()
    agt004_files = {f.file for f in findings if f.rule == "AGT004"}
    for f in findings:
        if f.key() in seen or _ignored(f, rules):
            continue
        if f.rule == "SEC001" and f.file in agt004_files:
            continue
        seen.add(f.key())
        uniq.append(f)
    uniq.sort(key=lambda f: (-SEV_RANK[f.severity], "kev" not in f.tags, f.rule, f.file, f.line or 0))
    return ctx, uniq
