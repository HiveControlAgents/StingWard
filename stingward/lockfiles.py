"""Leitura de lockfiles e manifestos. Devolve (ecossistema OSV, nome, versão, arquivo, linha)."""
from __future__ import annotations

import bisect
import json
import posixpath
import re
from collections import namedtuple
from pathlib import Path

from .model import decode_text
from .vulndb import _vkey

LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock",
    "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock", "packages.lock.json",
}

# nome==versão exata; "3.2.*" e afins não passam (é faixa, não versão)
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)(?=[\s;,\\]|$)")
_EXACT = re.compile(r"=?\d+\.\d+\.\d+[\w.\-+]*")
_YARN_LOCAL = ("workspace:", "link:", "portal:", "file:", "exec:")
# Faixa que aponta para fora do registro: repositório git, atalho do GitHub ou tarball por URL.
_YARN_REMOTE = ("git", "github:", "gitlab:", "bitbucket:", "gist:", "http:", "https:", "ssh:")


def is_dependency_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name in LOCKFILES or name == "package.json" or is_requirements(rel)


def is_requirements(rel: str) -> bool:
    """requirements*.txt, *-requirements.txt (dev-requirements.txt, test_requirements.txt) ou um .txt numa pasta
    requirements/ (base.txt, production.txt...)."""
    parts = rel.split("/")
    return re.fullmatch(r"requirements[\w.-]*\.txt|[\w.-]*[-_]requirements\.txt", parts[-1]) is not None or \
        (len(parts) > 1 and parts[-2] == "requirements" and parts[-1].endswith(".txt"))


# -r/--requirement e -c/--constraint: o espaço depois de \s* não pode ser pego de novo pelo que vem depois
_REQ_INCLUDE = re.compile(r"(?:-r|-c|--requirement|--constraint)\s*(?:=\s*)?(\S+)")


def requirement_includes(root: Path, rel: str):
    """Arquivos que um requirements inclui com -r ou -c, relativos à raiz (o caminho é relativo ao arquivo).
    Quem chama confere se o arquivo existe no projeto; URL fica de fora."""
    base = posixpath.dirname(rel)
    out = []
    for line in _lines(_read(root, rel) or ""):
        m = _REQ_INCLUDE.match(line.split("#", 1)[0].strip())
        if m and "://" not in m.group(1):
            out.append(posixpath.normpath(posixpath.join(base, m.group(1))))
    return out


def parse(root: Path, rel: str, requirements=False):
    """requirements=True lê o arquivo como requirements qualquer que seja o nome (incluído por -r ou -c)."""
    name = rel.rsplit("/", 1)[-1]
    text = _read(root, rel)
    if text is None:
        return []
    fn = _requirements if requirements or is_requirements(rel) else _PARSERS.get(name)
    if fn is None:
        return []
    try:
        return [(e, n, v, rel, ln) for e, n, v, ln in fn(text) if n and v]
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return []


def _read(root, rel):
    """Texto do manifesto como o resto da auditoria o lê (decode_text): UTF-8, ou UTF-16/32 pelo BOM. O PowerShell 5
    grava pip freeze > requirements.txt em UTF-16, que em UTF-8 virava lixo e dava zero pacotes, calado."""
    try:
        return decode_text((root / rel).read_bytes())
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
            # Repositório git e tarball local também não, como no formato v1 abaixo.
            if str(info.get("resolved") or "").startswith(("git", "github:", "file:")):
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
    if rng.startswith(_YARN_LOCAL + _YARN_REMOTE) or ("/" in rng and ":" not in rng):  # "dono/repo" é o GitHub
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
    """local(pkg) diz se o pacote é do próprio projeto (pasta, workspace) ou de um repositório git, e não do
    registro. pkg tem as chaves name, version, source, git e path do pacote e "source.type" do [package.source]."""
    def parse(text):
        pkg, start, sub = {}, 0, ""
        for i, line in enumerate(_lines(text) + ["[[package]]"], 1):
            if line.strip() == "[[package]]":
                if pkg.get("name") and pkg.get("version") and not (local and local(pkg)):
                    yield eco, pkg["name"], pkg["version"], start
                pkg, start, sub = {}, i, ""
                continue
            if line.startswith("["):  # subtabela do pacote: só a [package.source] do Poetry interessa
                sub = "source." if line.strip() == "[package.source]" else None
                continue
            m = re.match(r'^(name|version|source|git|path|type)\s*=\s*(?:"([^"]+)"|(\{.*))', line)
            if m and start and sub is not None:
                pkg.setdefault(sub + m.group(1), m.group(2) or m.group(3))
    return parse


def _uv_local(pkg):
    source = pkg.get("source")
    return bool(source) and re.match(r"\{\s*(editable|virtual|path|directory|git)\s*=", source) is not None


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


def _nuget_lock(text):
    """packages.lock.json do NuGet: um bloco por framework alvo (net8.0, net8.0/linux-x64). "Project" é projeto
    da própria solução, não pacote do nuget.org."""
    d = json.loads(text)
    find = _line_finder(text)
    for deps in (d.get("dependencies") or {}).values():
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            if isinstance(info, dict) and info.get("type") != "Project" and isinstance(info.get("resolved"), str):
                yield "NuGet", name, info["resolved"], find(f'"{name}"')


_PARSERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "bun.lock": _bun_lock,
    "package.json": _package_json,
    "requirements.txt": _requirements,
    "poetry.lock": _toml_packages("PyPI", lambda pkg: pkg.get("source.type") in ("git", "directory", "file")),
    "uv.lock": _toml_packages("PyPI", _uv_local),
    "pdm.lock": _toml_packages("PyPI", lambda pkg: "git" in pkg or "path" in pkg),
    "Pipfile.lock": _pipfile_lock,
    "go.mod": _go_mod,
    # Sem source é crate do próprio projeto; "git+..." vem de um repositório, não do crates.io.
    "Cargo.lock": _toml_packages("crates.io", lambda pkg: not pkg.get("source") or pkg["source"].startswith("git+")),
    "Gemfile.lock": _gemfile_lock,
    "composer.lock": _composer_lock,
    "packages.lock.json": _nuget_lock,
}


# Linha com forma de requisito (nome, extras, depois versão, marcador ou nada). Frase de documento ("The system
# shall...") e URL não são versão aberta: *-requirements.txt pode ser texto de especificação.
_REQ_LINE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\]\s*)?(?:$|[<>=!~;@(,])")


def open_ranges(root: Path, rel: str, requirements=False):
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
    if requirements or is_requirements(rel):
        n = 0
        for line in _lines(text):
            line = line.split("#", 1)[0].strip()
            if _REQ_LINE.match(line) and not _PIN.match(line):
                n += 1
        return n
    return 0


# --------------------------------------------------------------------------- faixas de versão (manifesto sem lockfile)

class Range(namedtuple("Range", "eco name spec req floor upper inclusive prefix suffix file line")):
    """Dependência declarada como faixa. spec é a faixa e req o requisito, como estão escritos; floor é a menor
    versão aceita e upper o teto (inclusive diz se o próprio teto vale). prefix + faixa nova + suffix reescreve req."""
    __slots__ = ()

    @property
    def exact(self):
        """Faixa de uma versão só (Pillow (==10.0.0), "v1.2.3"): é versão fixada, assunto do DEP001."""
        return self.inclusive and self.upper is not None and _vkey(self.upper, self.eco) == _vkey(self.floor, self.eco)


def ranges(root: Path, rel: str, requirements=False):
    """Faixas com piso de requirements*.txt, package.json ou pyproject.toml. Quem chama decide se há lockfile."""
    name = rel.rsplit("/", 1)[-1]
    text = _read(root, rel)
    if text is None:
        return []
    try:
        if name == "package.json":
            return list(_npm_ranges(text, rel))
        if name == "pyproject.toml":
            out = [r for r in (_python_range(req, rel, ln) for req, ln in pyproject_requirements(text)) if r]
            out += [r for r in (_poetry_range(*item, rel) for item in poetry_requirements(text)) if r]
            return sorted(out, key=lambda r: r.line)
        if requirements or is_requirements(rel):
            items = _requirement_lines(text)
        else:
            return []
        return [r for r in (_python_range(req, rel, ln) for req, ln in items) if r]
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return []


def in_range(r: Range, version: str) -> bool:
    k = _vkey(version, r.eco)
    if k < _vkey(r.floor, r.eco):
        return False
    if r.upper is None:
        return True
    u = _vkey(r.upper, r.eco)
    return k < u or (r.inclusive and k == u)


def raised(r: Range, version: str) -> str:
    """O requisito com o piso trocado por version. O teto fica se version cabe nele; se não cabe, a faixa abre."""
    inside = r.upper is not None and in_range(r, version)
    if r.eco == "npm":
        p = _npm_parts(version)
        if r.upper is None or p is None or p[0] is None:
            spec = ">=" + version
        elif not inside:
            spec = "^" + version
        elif not r.inclusive and _vkey(r.upper, "npm") == _vkey(_caret_upper(*p[:3]), "npm"):
            spec = "^" + version
        elif not r.inclusive and _vkey(r.upper, "npm") == _vkey(_tilde_upper(*p[:2]), "npm"):
            spec = "~" + version
        else:
            spec = f">={version} {'<=' if r.inclusive else '<'}{r.upper}"
    else:
        spec = ">=" + version + (f",{'<=' if r.inclusive else '<'}{r.upper}" if inside else "")
    return r.prefix + spec + r.suffix


# Pedaços de letras e números separados por um só -+_. (1.0.0rc1, 1.2.3-beta.1, 1.0+local). Cada separador abre um
# pedaço novo, então o texto só se divide de um jeito: "(?:[-+_.]?[A-Za-z0-9]+)*" dividia "1aaaa...*" de 2^n jeitos.
_VERSION = re.compile(r"v?\d[A-Za-z0-9]*(?:[-+_.][A-Za-z0-9]+)*")


def _release(v):
    m = re.match(r"v?(\d+(?:\.\d+)*)", v)
    return [int(x) for x in m.group(1).split(".")] if m else []


def _pick(lows, excl, highs, skip=(), eco=None):
    """(piso, teto, teto_inclusivo) a partir dos limites da faixa. None se o piso não é uma versão certa
    (só >X, ou o piso tirado por !=), se ele é 0 (aceita tudo) ou se a faixa é vazia. eco escolhe a ordem das
    versões (PEP 440 no PyPI: 1.0-1 é 1.0.post1, depois da 1.0)."""
    if not lows or not all(_VERSION.fullmatch(v) for v in lows + excl + [h for h, _ in highs]):
        return None

    def key(v):
        return _vkey(v, eco)
    floor = max(lows, key=key)
    k, parts = key(floor), _release(floor)
    if not any(parts) or any(key(v) >= k for v in excl):
        return None
    for v in skip:
        if v.endswith(".*"):
            base = _release(v[:-2])
            if base and (parts + [0] * len(base))[:len(base)] == base:
                return None
        elif _VERSION.fullmatch(v) and key(v) == k:
            return None
    if not highs:
        return floor, None, False
    upper, inclusive = min(highs, key=lambda h: (key(h[0]), h[1]))
    u = key(upper)
    if u < k or (u == k and not inclusive):
        return None
    return floor, upper, inclusive


# ------------------------------------------------------------------ Python (PEP 440 / PEP 508)

_PY_REQ = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*")
_PY_OP = re.compile(r"(~=|===|==|!=|<=|>=|<|>)\s*([A-Za-z0-9_.*+!-]+)")


def _next_release(v, depth):
    """Primeira versão depois do prefixo: _next_release("2.25", 0) == "3", _next_release("3.2", 1) == "3.3"."""
    rel = _release(v)[:depth + 1]
    rel[-1] += 1
    return ".".join(map(str, rel))


def python_floor(req: str):
    """Piso de um requisito PEP 508 ("Pillow>=10", "foo[bar]~=1.2", "django==3.2.*"): (nome, extras, faixa,
    piso, teto, teto_inclusivo), ou None. >X sozinho, nome sem versão e URL não têm piso."""
    text = req.split(";", 1)[0].strip()
    m = _PY_REQ.match(text)
    if not m:
        return None
    name, extras = m.group(1), re.sub(r"\s+", "", m.group(2) or "")
    spec = text[m.end():].strip()
    if spec.startswith("(") and spec.endswith(")"):  # forma antiga: foo (>=1.0)
        spec = spec[1:-1].strip()
    if not spec:
        return None
    lows, excl, highs, skip = [], [], [], []
    for part in spec.split(","):
        p = _PY_OP.fullmatch(part.strip())
        if not p or "!" in p.group(2):  # época (1!2.0) ou lixo: melhor não adivinhar
            return None
        op, v = p.groups()
        if op == "==" and v.endswith(".*"):
            base = v[:-2]
            lows.append(base)
            if _release(base):
                highs.append((_next_release(base, len(_release(base)) - 1), False))
        elif op in ("==", "==="):
            lows.append(v)
            highs.append((v, True))
        elif op == "~=":
            lows.append(v)
            if len(_release(v)) >= 2:
                highs.append((_next_release(v, len(_release(v)) - 2), False))
        elif op == ">=":
            lows.append(v)
        elif op == ">":
            excl.append(v)
        elif op == "<=":
            highs.append((v, True))
        elif op == "<":
            highs.append((v, False))
        else:
            skip.append(v)
    picked = _pick(lows, excl, highs, skip, "PyPI")
    return (name, extras, spec) + picked if picked else None


def _python_range(req, rel, line):
    f = python_floor(req)
    if not f:
        return None
    name, extras, spec, floor, upper, inclusive = f
    return Range("PyPI", name, spec, req.split(";", 1)[0].strip(), floor, upper, inclusive, name + extras, "", rel, line)


def _requirement_lines(text):
    """(requisito, linha) de um requirements.txt: junta as linhas quebradas com \\ e tira comentários e opções
    (-r, -e, --hash). Os fixados com == ficam de fora: _requirements já lê esses para o DEP001."""
    out, buf, start = [], "", 0
    for i, line in enumerate(_lines(text), 1):
        if not buf:
            start = i
        line = line.split("#", 1)[0].rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        req, buf = (buf + line).strip(), ""
        if not req or req.startswith("-"):
            continue
        # Um espaço só antes da opção: "\s+--?" voltava a cada espaço de uma sequência longa (quadrático).
        req = re.split(r"\s--?[A-Za-z]", req, maxsplit=1)[0].strip()
        if not _PIN.match(req):
            out.append((req, start))
    return out


# ------------------------------------------------------------------ npm (node-semver)

_NPM_LOCAL = ("file:", "link:", "workspace:", "portal:", "patch:", "git", "http:", "https:", "github:", "gitlab:",
              "bitbucket:", "gist:")
_NPM_VER = re.compile(r"[vV]?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")
_NPM_CMP = re.compile(r"(\^|~>?|>=|<=|>|<|=)?(.+)")


def _npm_parts(v):
    """(major, minor, patch, pre); a parte que falta ou é x/* vira None. None se não é versão."""
    m = _NPM_VER.fullmatch(v)
    if not m:
        return None
    parts = [int(g) if g and g.isdigit() else None for g in m.groups()[:3]]
    for i in (1, 2):  # 1.x.3: depois de um curinga, o resto também é curinga
        if parts[i - 1] is None:
            parts[i] = None
    return parts[0], parts[1], parts[2], m.group(4) if parts[2] is not None else None


def _v3(major, minor, patch, pre=None):
    return f"{major}.{minor or 0}.{patch or 0}" + (f"-{pre}" if pre else "")


def _caret_upper(major, minor, patch):
    """Teto de ^: ^1.2.3 < 2.0.0, ^0.2.3 < 0.3.0, ^0.0.3 < 0.0.4, ^0.x < 1.0.0."""
    if major:
        return f"{major + 1}.0.0"
    if minor is None:
        return "1.0.0"
    if minor:
        return f"0.{minor + 1}.0"
    return "0.1.0" if patch is None else f"0.0.{patch + 1}"


def _tilde_upper(major, minor):
    """Teto de ~ e das versões parciais: ~1.2.3 e 1.2.x < 1.3.0; ~1 e 1.x < 2.0.0."""
    return f"{major + 1}.0.0" if minor is None else f"{major}.{minor + 1}.0"


def npm_floor(spec: str):
    """Piso de uma faixa do npm ("^1.6.0", "~1.2", ">=1.2 <2", "1.x", "1.2.3 - 2"): (piso, teto, teto_inclusivo),
    ou None para *, latest e outras tags, ||, >X e o que não vem do registro (git, file:, link:, workspace:, URL)."""
    s = spec.strip()
    if not s or "||" in s or s.lower().startswith(_NPM_LOCAL) or "/" in s or ":" in s:
        return None
    hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", s)
    if hyphen:
        lo, hi = _npm_parts(hyphen.group(1)), _npm_parts(hyphen.group(2))
        if not lo or not hi or lo[0] is None or hi[0] is None:
            return None
        high = (_v3(*hi), True) if hi[2] is not None else (_tilde_upper(hi[0], hi[1]), False)
        return _pick([_v3(*lo)], [], [high], eco="npm")
    lows, excl, highs = [], [], []
    for c in re.sub(r"(>=|<=|>|<|=|\^|~>?)\s+", r"\1", s).split():
        m = _NPM_CMP.fullmatch(c)
        op, p = m.group(1) or "", _npm_parts(m.group(2))
        if p is None:
            return None
        major, minor, patch, pre = p
        if major is None:  # *, x: qualquer versão
            if op in ("", "=", ">=", "^", "~", "~>"):
                continue
            return None
        v = _v3(major, minor, patch, pre)
        if op in ("", "="):
            lows.append(v)
            highs.append((v, True) if patch is not None else (_tilde_upper(major, minor), False))
        elif op == "^":
            lows.append(v)
            highs.append((_caret_upper(major, minor, patch), False))
        elif op in ("~", "~>"):
            lows.append(v)
            highs.append((_tilde_upper(major, minor), False))
        elif op == ">=":
            lows.append(v)
        elif op == ">":
            excl.append(v)
        elif op == "<=":
            highs.append((v, True) if patch is not None else (_tilde_upper(major, minor), False))
        else:
            highs.append((v, False))
    return _pick(lows, excl, highs, eco="npm")


def _npm_ranges(text, rel):
    d = json.loads(text)
    if not isinstance(d, dict):
        return
    find = _line_finder(text)
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = d.get(sec)
        if not isinstance(deps, dict):
            continue
        for key, spec in deps.items():
            if not isinstance(spec, str) or _EXACT.fullmatch(spec):
                continue
            s = spec.strip()
            name, rng = _npm_alias(key, s)
            f = npm_floor(rng)
            if f:
                prefix = f'"{key}": "' + s[:len(s) - len(rng)]  # mantém o npm:nome-real@ do alias
                yield Range("npm", name, rng, f'"{key}": "{s}"', *f, prefix, '"', rel, find(f'"{key}"'))


# ------------------------------------------------------------------ pyproject.toml

class _Str(str):
    """String do TOML que lembra a linha onde começa."""
    line = 0


class _Toml:
    """Leitor mínimo de TOML: o Python 3.9 e o 3.10 não têm tomllib, e o tomllib não diz a linha. Entende
    tabelas, chaves com ponto ou aspas, os quatro tipos de string, listas e tabelas inline; números, datas e
    booleanos são pulados. Uma linha que ele não entende é pulada inteira, sem derrubar o resto do arquivo."""

    _BARE = re.compile(r"[A-Za-z0-9_-]+")
    _BASIC = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
    _LITERAL = re.compile(r"'([^'\n]*)'")
    _SCALAR = re.compile(r"[^,\]}\n#]+")
    _ESC = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", "e": "\x1b"}
    MAX_DEPTH = 32

    def __init__(self, text):
        self.s, self.i, self.depth = text, 0, 0
        self.newlines = [m.start() for m in re.finditer("\n", text)]

    def line(self, i):
        return bisect.bisect_left(self.newlines, i) + 1

    def statements(self):
        """(caminho completo da chave, valor) de cada atribuição; o caminho começa pela tabela atual."""
        table, s = (), self.s
        while True:
            self.skip(newlines=True)
            if self.i >= len(s):
                return
            start = self.i
            try:
                if s[self.i] == "[":
                    table = self.header()
                    self.end_of_line()
                else:
                    keys = self.key()
                    self.expect("=")
                    value = self.value()
                    self.end_of_line()
                    yield table + keys, value
            except (ValueError, IndexError, RecursionError):
                nl = s.find("\n", start)
                self.i, self.depth = (len(s) if nl < 0 else nl + 1), 0

    def skip(self, newlines=False):
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c in " \t" or (newlines and c in "\r\n"):
                self.i += 1
            elif c == "#":
                nl = s.find("\n", self.i)
                self.i = len(s) if nl < 0 else nl
            else:
                return

    def expect(self, tok):
        self.skip()
        if not self.s.startswith(tok, self.i):
            raise ValueError(tok)
        self.i += len(tok)

    def end_of_line(self):
        self.skip()
        if self.i < len(self.s) and self.s[self.i] not in "\r\n":
            raise ValueError("fim de linha")

    def header(self):
        close = "]]" if self.s.startswith("[[", self.i) else "]"
        self.i += len(close)
        keys = self.key()
        self.expect(close)
        return keys

    def key(self):
        keys = []
        while True:
            self.skip()
            c = self.s[self.i:self.i + 1]
            if c == '"':
                keys.append(self.basic())
            elif c == "'":
                keys.append(self.match(self._LITERAL))
            else:
                keys.append(self.match(self._BARE, group=0))
            self.skip()
            if not self.s.startswith(".", self.i):
                return tuple(keys)
            self.i += 1

    def match(self, rx, group=1):
        m = rx.match(self.s, self.i)
        if not m:
            raise ValueError(rx.pattern)
        self.i = m.end()
        return m.group(group)

    def basic(self):
        return re.sub(r"\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", self._unescape, self.match(self._BASIC))

    def _unescape(self, m):
        e = m.group(1)
        if len(e) == 1:
            return self._ESC.get(e, e)
        code = int(e[1:], 16)
        if code > 0x10FFFF:  # chr() daria ValueError ou, no 3.9, OverflowError
            raise ValueError("escape")
        return chr(code)

    def multiline(self, quote):
        start, j = self.i, self.i + 3
        while True:
            k = self.s.find(quote, j)
            if k < 0:
                raise ValueError("string sem fim")
            slashes = 0
            while quote == '"""' and k - 1 - slashes >= start + 3 and self.s[k - 1 - slashes] == "\\":
                slashes += 1
            if slashes % 2 == 0:
                break
            j = k + 1
        extra = 0
        while extra < 2 and self.s.startswith(quote[0], k + 3):  # """a"""" termina em a": até duas aspas a mais
            k, extra = k + 1, extra + 1
        self.i = k + 3
        return self.s[start + 3:k]

    def value(self):
        self.skip()
        s, i = self.s, self.i
        line = self.line(i)
        if s.startswith('"""', i) or s.startswith("'''", i):
            out = _Str(self.multiline(s[i:i + 3]))
        elif s.startswith('"', i):
            out = _Str(self.basic())
        elif s.startswith("'", i):
            out = _Str(self.match(self._LITERAL))
        elif s.startswith("[", i) or s.startswith("{", i):
            self.depth += 1
            if self.depth > self.MAX_DEPTH:
                raise ValueError("aninhado demais")
            out = self.array() if s[i] == "[" else self.inline_table()
            self.depth -= 1
            return out
        else:
            if not self.match(self._SCALAR, group=0).strip():
                raise ValueError("valor")
            return None
        out.line = line
        return out

    def array(self):
        self.i += 1
        out = []
        while True:
            self.skip(newlines=True)
            if self.s.startswith("]", self.i):
                self.i += 1
                return out
            out.append(self.value())
            self.skip(newlines=True)
            if self.s.startswith(",", self.i):
                self.i += 1
            elif not self.s.startswith("]", self.i):
                raise ValueError("lista")

    def inline_table(self):
        self.i += 1
        out = {}
        while True:
            self.skip(newlines=True)
            if self.s.startswith("}", self.i):
                self.i += 1
                return out
            keys = self.key()
            self.expect("=")
            out[keys] = self.value()
            self.skip(newlines=True)
            if self.s.startswith(",", self.i):
                self.i += 1
            elif not self.s.startswith("}", self.i):
                raise ValueError("tabela")


def pyproject_requirements(text: str):
    """(requisito, linha) das listas PEP 508 de um pyproject.toml: [project] dependencies, [project.optional-dependencies],
    [dependency-groups] (PEP 735; o {include-group} não é requisito) e o dev-dependencies do [tool.uv]."""
    out = []

    def walk(path, value):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(path + k, v)
        elif isinstance(value, list) and (path in (("project", "dependencies"), ("tool", "uv", "dev-dependencies")) or
                                          (len(path) == 3 and path[:2] == ("project", "optional-dependencies")) or
                                          (len(path) == 2 and path[0] == "dependency-groups")):
            out.extend((str(x), x.line) for x in value if isinstance(x, _Str))

    for path, value in _Toml(text).statements():
        walk(path, value)
    return out


# Dependência do Poetry que não vem do índice de pacotes: não há versão do PyPI para consultar.
_POETRY_LOCAL = ("git", "path", "url", "file")
# Depois do número vem letra, + ou -: sem isso o resto ([A-Za-z0-9.+-]*) também casava dígitos, e um ^111...1! longo
# voltava atrás de um em um (quadrático).
_POETRY_CARET = re.compile(r"([\^~])(\d+)(?:\.(\d+))?(?:\.(\d+))?(?![\d.])(?:[A-Za-z+-][A-Za-z0-9.+-]*)?")


def poetry_requirements(text: str):
    """(nome, faixa, linha, prefixo) de [tool.poetry.dependencies], [tool.poetry.dev-dependencies] e
    [tool.poetry.group.<g>.dependencies]. Ficam de fora o python, a lista de faixas por marcador e o que vem de
    git, path, url ou file. O prefixo mais a faixa nova reescrevem a linha (requests = " ou version = ")."""
    deps = {}

    def walk(path, value):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(path + k, v)
            return
        if path[:3] in (("tool", "poetry", "dependencies"), ("tool", "poetry", "dev-dependencies")):
            rest = path[3:]
        elif path[:3] == ("tool", "poetry", "group") and len(path) > 4 and path[4] == "dependencies":
            rest = path[5:]
        else:
            return
        if not rest:
            return
        d = deps.setdefault(path[:len(path) - len(rest) + 1], {"name": rest[0]})
        if len(rest) == 1:
            d["spec"], d["prefix"] = value, f'{rest[0]} = "'
        elif len(rest) == 2 and rest[1] == "version":
            d["spec"], d["prefix"] = value, 'version = "'
        elif rest[1] in _POETRY_LOCAL:
            d["local"] = True

    for path, value in _Toml(text).statements():
        walk(path, value)
    out = [(d["name"], str(d["spec"]), d["spec"].line, d["prefix"]) for d in deps.values()
           if isinstance(d.get("spec"), _Str) and not d.get("local") and d["name"].lower() != "python"]
    return sorted(out, key=lambda x: x[2])


def _poetry_pep440(spec):
    """Faixa do Poetry em PEP 440: ^2.28 vira >=2.28,<3.0.0, ~1.2 vira >=1.2,<1.3.0, 2.0.1 vira ==2.0.1 e
    o * some. None para || (mais de uma faixa) ou faixa vazia."""
    if "|" in spec:
        return None
    parts = []
    for c in re.sub(r"(~=|===|==|!=|<=|>=|<|>|\^|~)\s+", r"\1", spec).replace(",", " ").split():
        m = _POETRY_CARET.fullmatch(c)
        if m:
            major, minor, patch = (int(g) if g else None for g in m.groups()[1:])
            upper = _caret_upper(major, minor, patch) if m.group(1) == "^" else _tilde_upper(major, minor)
            parts += [">=" + c[1:], "<" + upper]
        elif c != "*":
            parts.append(c if c[0] in "<>=!~" else "==" + c)
    return ",".join(parts) or None


def _poetry_range(name, spec, line, prefix, rel):
    pep = _poetry_pep440(spec) if _PY_REQ.fullmatch(name) else None
    f = python_floor(name + pep) if pep else None
    if not f:
        return None
    floor, upper, inclusive = f[3:]
    return Range("PyPI", name, spec, prefix + spec + '"', floor, upper, inclusive, prefix, '"', rel, line)
