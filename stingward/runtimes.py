"""Versão do PHP em que o projeto roda: a imagem do Docker (Dockerfile, docker-compose) e os arquivos de versão
(.php-version, .tool-versions do asdf, mise.toml). As falhas do próprio PHP estão no OSV.dev, no ecossistema Bitnami,
que segue os números de versão do php.net."""
from __future__ import annotations

import re
from typing import NamedTuple

ECOSYSTEM, NAME = "Bitnami", "php"


class Runtime(NamedTuple):
    version: str  # 8.3.30; 8.3 quando acompanha a série (php:8.3-apache, .php-version com 8.3)
    file: str
    line: int
    image: str = ""  # a imagem como fica depois de trocar os ARG (php:8.3.30-apache); vazio nos arquivos de versão
    arg: str = ""    # o ARG de onde veio a versão (FROM php:${PHP_VERSION}-apache), para dizer onde trocar

    @property
    def floating(self) -> bool:
        return self.version.count(".") == 1

    @property
    def branch(self) -> str:
        return ".".join(self.version.split(".")[:2])

    @property
    def query(self) -> str:
        """A versão perguntada ao OSV: a exata, ou a primeira da série (8.3.0), que tem tudo o que a série teve."""
        return self.version + ".0" if self.floating else self.version


_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")
# A imagem oficial (php, library/php) e a da Bitnami, direto do Docker Hub ou por um espelho conhecido dele.
_IMAGE = re.compile(r"(?:(?:docker\.io|index\.docker\.io|registry-1\.docker\.io|mirror\.gcr\.io|public\.ecr\.aws/docker)/)?"
                    r"(?:(?:library/)?php|bitnami/php-fpm):(?P<tag>[\w][\w.-]*)")
# Tag com série (8.3) ou versão (8.3.30) no começo: 8.3-apache, 8.3.30-fpm-alpine, 8.3.30-debian-12-r5. Sem número
# (latest, apache) ou só com o major (8-cli) não diz qual PHP é. Pré-lançamento (8.5-rc, 8.5.0RC1) fica de fora.
_TAG = re.compile(r"(\d+\.\d+(?:\.\d+)?)(?=$|-)")
_RC = re.compile(r"(?i)(?:^|-)rc\d*(?:-|$)")
_FROM = re.compile(r"(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)")
_ARG = re.compile(r"(?i)^\s*ARG\s+(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)")
_COMPOSE_IMAGE = re.compile(r"^\s*-?\s*image:\s*[\"']?([^\"'\s#]+)")
_VAR = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)")
_DOCKERFILE = re.compile(r"(?i)(?:docker|container)file(?:\.[\w.-]+)?|[\w.-]+\.(?:docker|container)file")
_COMPOSE = re.compile(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml")
_MISE = re.compile(r"\.?mise(?:\.[\w-]+)?\.toml")
_TOOL_VERSIONS = re.compile(r"^\s*php\s+(\S+)")
_MISE_PHP = re.compile(r"""^\s*["']?php["']?\s*=\s*(?:\[\s*)?(?:\{[^}]*?\bversion\s*=\s*)?["']([^"']+)["']""")


def _expand(ref: str, args: dict):
    """(referência com os ARG trocados, o ARG usado), ou None se sobrar variável sem valor."""
    used = []

    def sub(m):
        name = m.group(1) or m.group(3)
        if name in args:
            used.append(name)
            return args[name]
        if m.group(2) is not None:
            return m.group(2)
        raise KeyError(name)
    try:
        return _VAR.sub(sub, ref), (used[0] if used else "")
    except KeyError:
        return None


def _from_image(ref: str):
    """Versão do PHP de uma imagem (php:8.3.30-apache -> 8.3.30), ou None se não for PHP ou não disser a versão."""
    m = _IMAGE.fullmatch(ref.split("@", 1)[0])
    if not m or _RC.search(m["tag"]):
        return None
    v = _TAG.match(m["tag"])
    return v.group(1) if v else None


def _dockerfile(rel, text):
    out, args, seen_from = [], {}, False
    for n, line in enumerate(text.split("\n"), 1):
        a = _ARG.match(line)
        if a and not seen_from:  # o FROM só enxerga os ARG declarados antes do primeiro FROM
            args[a.group(1)] = a.group(2).strip("\"'")
            continue
        m = _FROM.match(line)
        if not m:
            continue
        seen_from = True
        got = _expand(m.group(1), args)
        if got and _from_image(got[0]):
            out.append(Runtime(_from_image(got[0]), rel, n, got[0], got[1]))
    return out


def _compose(rel, text):
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        m = _COMPOSE_IMAGE.match(line)
        got = _expand(m.group(1), {}) if m else None
        if got and _from_image(got[0]):
            out.append(Runtime(_from_image(got[0]), rel, n, got[0]))
    return out


def _php_version(rel, text):
    """.php-version: a primeira linha com conteúdo é a versão."""
    for n, line in enumerate(text.split("\n"), 1):
        s = line.split("#", 1)[0].strip()
        if s:
            return [Runtime(s, rel, n)] if _VERSION.fullmatch(s) else []
    return []


def _first_match(rel, text, pattern, section=None):
    """A primeira linha que dá a versão do PHP: no .tool-versions, ou na tabela [tools] do mise.toml."""
    current = None
    for n, line in enumerate(text.split("\n"), 1):
        s = line.split("#", 1)[0].strip()
        if section and s.startswith("["):
            current = s.strip("[] ")
            continue
        m = pattern.match(s) if not section or current == section else None
        if m and _VERSION.fullmatch(m.group(1)):
            return [Runtime(m.group(1), rel, n)]
    return []


def collect(ctx):
    """A versão do PHP de cada lugar que a define, sem repetir a mesma versão do mesmo tipo (imagem ou arquivo)."""
    out, seen = [], set()
    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if _DOCKERFILE.fullmatch(name):
            found = _dockerfile(rel, ctx.read(rel))
        elif _COMPOSE.fullmatch(name):
            found = _compose(rel, ctx.read(rel))
        elif name == ".php-version":
            found = _php_version(rel, ctx.read(rel))
        elif name == ".tool-versions":
            found = _first_match(rel, ctx.read(rel), _TOOL_VERSIONS)
        elif _MISE.fullmatch(name):
            found = _first_match(rel, ctx.read(rel), _MISE_PHP, "tools")
        else:
            continue
        for rt in found:
            key = (rt.version, bool(rt.image))
            if key not in seen:
                seen.add(key)
                out.append(rt)
    return out


def retag(rt: Runtime, version: str) -> str:
    """A mesma imagem com outra versão: php:8.3.30-apache -> php:8.3.36-apache."""
    head, tag = rt.image.split("@", 1)[0].rsplit(":", 1)
    return f"{head}:{version}{tag[len(_TAG.match(tag).group(1)):]}"
