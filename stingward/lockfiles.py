"""Leitura de lockfiles e manifestos. Devolve (ecossistema OSV, nome, versão, arquivo, linha)."""
from __future__ import annotations

import json
import re
from pathlib import Path

LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock",
    "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock",
}


def is_dependency_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name in LOCKFILES or name == "package.json" or re.fullmatch(r"requirements[\w.-]*\.txt", name) is not None


def parse(root: Path, rel: str):
    name = rel.rsplit("/", 1)[-1]
    try:
        text = (root / rel).read_text("utf-8", errors="replace")
    except OSError:
        return []
    fn = _PARSERS.get(name)
    if fn is None and re.fullmatch(r"requirements[\w.-]*\.txt", name):
        fn = _requirements
    if fn is None:
        return []
    try:
        return [(e, n, v, rel, ln) for e, n, v, ln in fn(text) if n and v]
    except (ValueError, KeyError, TypeError, AttributeError):
        return []


def _line_finder(text):
    lines = text.splitlines()

    def find(needle, start=0):
        for i in range(start, len(lines)):
            if needle in lines[i]:
                return i + 1
        return None
    return find


def _npm_lock(text):
    d = json.loads(text)
    find = _line_finder(text)
    pkgs = d.get("packages")
    if pkgs:
        for path, info in pkgs.items():
            if not path or info.get("link") or "version" not in info:
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            yield "npm", name, info["version"], find(f'"{path}"')
        return

    def walk(deps):
        for name, info in (deps or {}).items():
            if isinstance(info, dict) and "version" in info and not str(info["version"]).startswith(("file:", "git", "http")):
                yield "npm", name, info["version"], find(f'"{name}"')
                yield from walk(info.get("dependencies"))
    yield from walk(d.get("dependencies"))


def _yarn_lock(text):
    current = []
    for i, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            current = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                name = spec[:spec.rindex("@")] if spec.rfind("@") > 0 else spec
                if name and not name.startswith("__") and name not in current:
                    current.append((name, i))
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and current:
            for name, ln in current[:1]:
                yield "npm", name, m.group(1), ln
            current = []


def _pnpm_lock(text):
    in_packages = False
    seen = set()
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = True
            continue
        if line and not line.startswith(" "):
            in_packages = False
        if not in_packages:
            continue
        m = re.match(r"^  '?/?(@?[^@\s/']+(?:/[^@\s/']+)?)[@/](\d[^:(\s']*)", line)
        if m and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            yield "npm", m.group(1), m.group(2), i


def _bun_lock(text):
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s+"[^"]+":\s*\["(@?[^@"]+)@(\d[^"]*)"', line)
        if m:
            yield "npm", m.group(1), m.group(2), i


def _package_json(text):
    """Só versões exatas: faixas (^1.2) não dá para auditar sem lockfile."""
    d = json.loads(text)
    find = _line_finder(text)
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (d.get(sec) or {}).items():
            if isinstance(spec, str) and re.fullmatch(r"=?\d+\.\d+\.\d+[\w.\-+]*", spec):
                yield "npm", name, spec.lstrip("="), find(f'"{name}"')


def _requirements(text):
    for i, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            yield "PyPI", m.group(1), m.group(2), i


def _toml_packages(eco):
    def parse(text):
        name = ver = None
        start = 0
        for i, line in enumerate(text.splitlines() + ["[[package]]"], 1):
            if line.strip() == "[[package]]":
                if name and ver:
                    yield eco, name, ver, start
                name = ver = None
                start = i
                continue
            m = re.match(r'^(name|version)\s*=\s*"([^"]+)"', line)
            if m and start:
                if m.group(1) == "name" and name is None:
                    name = m.group(2)
                elif m.group(1) == "version" and ver is None:
                    ver = m.group(2)
    return parse


def _pipfile_lock(text):
    d = json.loads(text)
    find = _line_finder(text)
    for sec in ("default", "develop"):
        for name, info in (d.get(sec) or {}).items():
            v = (info or {}).get("version", "")
            if v.startswith("=="):
                yield "PyPI", name, v[2:], find(f'"{name}"')


def _go_mod(text):
    in_block = False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v\d[^\s]*)$", s) if (in_block or s.startswith("require ")) else None
        if m:
            yield "Go", m.group(1), m.group(2), i


def _gemfile_lock(text):
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)\s]+)\)$", line)
        if m:
            yield "RubyGems", m.group(1), m.group(2).split("-")[0], i


def _composer_lock(text):
    d = json.loads(text)
    find = _line_finder(text)
    for sec in ("packages", "packages-dev"):
        for p in d.get(sec) or []:
            yield "Packagist", p.get("name"), str(p.get("version", "")).lstrip("v"), find(f'"name": "{p.get("name")}"')


_PARSERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "bun.lock": _bun_lock,
    "package.json": _package_json,
    "requirements.txt": _requirements,
    "poetry.lock": _toml_packages("PyPI"),
    "uv.lock": _toml_packages("PyPI"),
    "pdm.lock": _toml_packages("PyPI"),
    "Pipfile.lock": _pipfile_lock,
    "go.mod": _go_mod,
    "Cargo.lock": _toml_packages("crates.io"),
    "Gemfile.lock": _gemfile_lock,
    "composer.lock": _composer_lock,
}


def open_ranges(root: Path, rel: str):
    """Manifesto sem lockfile ao lado: quantas dependências têm versão aberta."""
    name = rel.rsplit("/", 1)[-1]
    try:
        text = (root / rel).read_text("utf-8", errors="replace")
    except OSError:
        return 0
    if name == "package.json":
        try:
            d = json.loads(text)
        except ValueError:
            return 0
        return sum(1 for sec in ("dependencies", "devDependencies") for spec in (d.get(sec) or {}).values()
                   if isinstance(spec, str) and not re.fullmatch(r"=?\d+\.\d+\.\d+[\w.\-+]*", spec)
                   and not spec.startswith(("file:", "link:", "workspace:")))
    if name.startswith("requirements"):
        n = 0
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("-") and re.match(r"^[A-Za-z0-9]", line) and "==" not in line:
                n += 1
        return n
    return 0
