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

# nome==versão exata; "3.2.*" e afins não passam (é faixa, não versão)
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)(?=[\s;,\\]|$)")
_EXACT = re.compile(r"=?\d+\.\d+\.\d+[\w.\-+]*")
_YARN_LOCAL = ("workspace:", "link:", "portal:", "file:")


def is_dependency_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name in LOCKFILES or name == "package.json" or re.fullmatch(r"requirements[\w.-]*\.txt", name) is not None


def parse(root: Path, rel: str):
    name = rel.rsplit("/", 1)[-1]
    text = _read(root, rel)
    if text is None:
        return []
    fn = _PARSERS.get(name)
    if fn is None and re.fullmatch(r"requirements[\w.-]*\.txt", name):
        fn = _requirements
    if fn is None:
        return []
    try:
        return [(e, n, v, rel, ln) for e, n, v, ln in fn(text) if n and v]
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return []


def _read(root, rel):
    try:
        return (root / rel).read_text("utf-8-sig", errors="replace")
    except OSError:
        return None


def _lines(text):
    """Linhas contadas só por \\n: splitlines() também quebra em \\f, \\v, \\x1c, U+2028... e desalinha a numeração."""
    return [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]


def _line_finder(text):
    """Linha da agulha, buscando a partir da última achada: o JSON lista os pacotes na ordem em que são
    pedidos, então o arquivo é lido uma vez só (buscar do topo a cada pacote é quadrático)."""
    pos, line = 0, 1

    def find(needle):
        nonlocal pos, line
        i = text.find(needle, pos)
        if i < 0:
            i = text.find(needle, 0, pos + len(needle))
            if i < 0:
                return None
            pos, line = 0, 1
        line += text.count("\n", pos, i)
        pos = i
        return line
    return find


def _npm_lock(text):
    d = json.loads(text)
    find = _line_finder(text)
    pkgs = d.get("packages")
    if pkgs:
        for path, info in pkgs.items():
            # Só o que está em node_modules/ vem do registro; "packages/app" é pasta de workspace.
            if "node_modules/" not in path or not isinstance(info, dict) or info.get("link") or "version" not in info:
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            yield "npm", name, info["version"], find(f'"{path}"')
        return

    def walk(deps):
        for key, info in (deps or {}).items():
            if isinstance(info, dict) and "version" in info:
                name, version = _npm_alias(key, str(info["version"]))
                if not version.startswith(("file:", "git", "http")):
                    yield "npm", name, version, find(f'"{key}"')
                    yield from walk(info.get("dependencies"))
    yield from walk(d.get("dependencies"))


def _npm_alias(name, version):
    """Alias do npm: "npm:nome-real@1.2.3" vira (nome-real, 1.2.3)."""
    if version.startswith("npm:"):
        real, _, ver = version[4:].rpartition("@")
        if real:
            return real, ver
    return name, version


def _yarn_lock(text):
    current = None
    for i, line in enumerate(_lines(text), 1):
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            names = [_yarn_name(spec.strip().strip('"')) for spec in line.rstrip().rstrip(":").split(",")]
            # Pacote local (workspace:, link:...) não vem do registro: a entrada toda fica de fora.
            current = None if None in names else next(((n, i) for n in names if n and not n.startswith("__")), None)
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and current:
            name, ln = current
            yield "npm", name, m.group(1), ln
            current = None


def _yarn_name(spec):
    """Nome do pacote numa chave "nome@faixa" do yarn.lock; None para pacote local."""
    at = spec.find("@", 1)
    if at < 0:
        return spec
    name, rng = spec[:at], spec[at + 1:]
    if rng.startswith(_YARN_LOCAL):
        return None
    if rng.startswith("npm:") and rng.find("@", 5) > 0:  # alias: apelido@npm:nome-real@faixa
        return rng[4:rng.index("@", 5)]
    return name  # inclui nome@patch:nome@npm%3A... (berry)


def _pnpm_lock(text):
    in_packages = False
    seen = set()
    for i, line in enumerate(_lines(text), 1):
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = True
            continue
        if line and not line.startswith(" "):
            in_packages = False
        if not in_packages:
            continue
        # /nome/1.0.0_peer@2 (v5), /nome@1.0.0(peer@2) (v6), nome@1.0.0 (v9); só escopo (@org/) leva barra no nome
        m = re.match(r"^  '?/?((?:@[^@\s/']+/)?[^@\s/']+)[@/](\d[^:(_\s']*)", line)
        if m and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            yield "npm", m.group(1), m.group(2), i


def _bun_lock(text):
    for i, line in enumerate(_lines(text), 1):
        m = re.match(r'^\s+"[^"]+":\s*\["(@?[^@"]+)@(\d[^"]*)"', line)
        if m:
            yield "npm", m.group(1), m.group(2), i


def _package_json(text):
    """Só versões exatas: faixas (^1.2) não dá para auditar sem lockfile."""
    d = json.loads(text)
    find = _line_finder(text)
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (d.get(sec) or {}).items():
            if isinstance(spec, str) and _EXACT.fullmatch(spec):
                yield "npm", name, spec.lstrip("="), find(f'"{name}"')


def _requirements(text):
    for i, line in enumerate(_lines(text), 1):
        m = _PIN.match(line.split("#", 1)[0].strip())
        if m:
            yield "PyPI", m.group(1), m.group(2), i


def _toml_packages(eco, local=None):
    """local(source) diz se o pacote é do próprio projeto (pasta, workspace) e não do registro."""
    def parse(text):
        pkg, start = {}, 0
        for i, line in enumerate(_lines(text) + ["[[package]]"], 1):
            if line.strip() == "[[package]]":
                if pkg.get("name") and pkg.get("version") and not (local and local(pkg.get("source"))):
                    yield eco, pkg["name"], pkg["version"], start
                pkg, start = {}, i
                continue
            m = re.match(r'^(name|version|source)\s*=\s*(?:"([^"]+)"|(\{.*))', line)
            if m and start:
                pkg.setdefault(m.group(1), m.group(2) or m.group(3))
    return parse


def _uv_local(source):
    return bool(source) and re.match(r"\{\s*(editable|virtual|path|directory)\s*=", source) is not None


def _pipfile_lock(text):
    d = json.loads(text)
    find = _line_finder(text)
    for sec in ("default", "develop"):
        for name, info in (d.get(sec) or {}).items():
            v = (info or {}).get("version", "")
            if v.startswith("=="):
                yield "PyPI", name, v[2:], find(f'"{name}"')


def _go_mod(text):
    reqs, repl = [], {}
    block = None
    for i, line in enumerate(_lines(text), 1):
        s = line.split("//", 1)[0].strip()
        m = re.match(r"^(require|replace)\s*\($", s)
        if m:
            block = m.group(1)
            continue
        if block and s == ")":
            block = None
            continue
        kind = block
        if kind is None:
            m = re.match(r"^(require|replace)\s+(.+)$", s)
            if not m:
                continue
            kind, s = m.groups()
        if kind == "require":
            m = re.match(r"^(\S+)\s+(v\d\S*)$", s)
            if m:
                reqs.append((m.group(1), m.group(2), i))
        else:
            m = re.match(r"^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$", s)
            if m:
                repl[m.group(1), m.group(2)] = (m.group(3), m.group(4), i)
    for mod, ver, ln in reqs:
        new = repl.get((mod, ver)) or repl.get((mod, None))
        if new is None:
            yield "Go", mod, ver, ln
        elif new[1]:  # sem versão do lado direito é caminho local (=> ../x): não vem de registro
            yield "Go", new[0], new[1], new[2]


def _gemfile_lock(text):
    section = None
    for i, line in enumerate(_lines(text), 1):
        if line and not line.startswith(" "):
            section = line.strip()  # GEM, PATH, GIT, PLATFORMS...
            continue
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)\s]+)\)$", line)
        if m and section == "GEM":  # PATH e GIT são gems locais ou de repositório, fora do RubyGems
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
    "uv.lock": _toml_packages("PyPI", _uv_local),
    "pdm.lock": _toml_packages("PyPI"),
    "Pipfile.lock": _pipfile_lock,
    "go.mod": _go_mod,
    "Cargo.lock": _toml_packages("crates.io", lambda source: source is None),  # sem source: crate do próprio projeto
    "Gemfile.lock": _gemfile_lock,
    "composer.lock": _composer_lock,
}


def open_ranges(root: Path, rel: str):
    """Manifesto sem lockfile ao lado: quantas dependências têm versão aberta."""
    name = rel.rsplit("/", 1)[-1]
    text = _read(root, rel)
    if text is None:
        return 0
    if name == "package.json":
        try:
            d = json.loads(text)
        except (ValueError, RecursionError):
            return 0
        if not isinstance(d, dict):
            return 0
        return sum(1 for sec in ("dependencies", "devDependencies") if isinstance(d.get(sec), dict)
                   for spec in d[sec].values()
                   if isinstance(spec, str) and not _EXACT.fullmatch(spec)
                   and not spec.startswith(("file:", "link:", "workspace:")))
    if name.startswith("requirements"):
        n = 0
        for line in _lines(text):
            line = line.split("#", 1)[0].strip()
            if re.match(r"^[A-Za-z0-9]", line) and not _PIN.match(line):
                n += 1
        return n
    return 0
