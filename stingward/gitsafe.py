"""git só no repositório que nós achamos, nunca no que o git descobriria sozinho na pasta auditada.

Uma pasta de skill pode imitar um repositório "bare" (HEAD, config, objects/) com core.fsmonitor apontando para um
comando: deixar o git procurar o repositório a partir dali executaria esse comando. Por isso o git recebe --git-dir e
--work-tree explícitos e as opções que executam programas desligadas na linha de comando, que vence a config do repo.
"""
from __future__ import annotations

import os
import re
import subprocess

_SAFE = ["-c", "core.fsmonitor=false", "-c", "safe.bareRepository=explicit", "-c", f"core.hooksPath={os.devnull}"]
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def top(root: str):
    """Pasta mais próxima, de root para cima, que tem um .git (pasta, ou arquivo de worktree/submódulo)."""
    d = os.path.abspath(root)
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def prefix(root: str) -> str:
    """root relativo à raiz do repositório, com barra no fim ("app/"); vazio fora de repositório."""
    t = top(root)
    if t is None:
        return ""
    rel = os.path.relpath(os.path.abspath(root), t).replace(os.sep, "/")
    return "" if rel == "." else rel + "/"


def run(root: str, *args: str, timeout: int = 30):
    """Roda git com cwd em root contra o repositório de top(root). None se não houver repositório ou git."""
    t = top(root)
    if t is None:
        return None
    cmd = ["git", "-C", os.path.abspath(root), *_SAFE, f"--git-dir={os.path.join(t, '.git')}", f"--work-tree={t}", *args]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def head(root: str):
    """Commit atual do repositório de root, ou None. Só rev-parse: status e log podem rodar filtros e o gpg da config do repo."""
    r = run(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", timeout=10)
    if r is None or r.returncode != 0:
        return None
    sha = r.stdout.decode("ascii", "replace").strip()
    return sha if _SHA.fullmatch(sha) else None
