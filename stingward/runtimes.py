"""Versão do PHP e do Node.js em que o projeto roda: a imagem do Docker (Dockerfile, docker-compose) e os arquivos de
versão (.php-version, .nvmrc, .node-version, .tool-versions do asdf, mise.toml, os módulos do .replit). As falhas do
próprio PHP e do próprio Node.js estão no OSV.dev, no ecossistema Bitnami, que segue os números de versão do php.net e
do nodejs.org."""
from __future__ import annotations

import json
import re
from typing import NamedTuple

ECOSYSTEM = "Bitnami"


class Runtime(NamedTuple):
    version: str  # 8.3.30 ou 24.10.0; 8.3 ou 24 quando acompanha a série (php:8.3-apache, node:24-alpine, .nvmrc com 24)
    file: str
    line: int
    image: str = ""  # a imagem como fica depois de trocar os ARG (php:8.3.30-apache); vazio nos arquivos de versão
    arg: str = ""    # o ARG de onde veio a versão (FROM php:${PHP_VERSION}-apache), para dizer onde trocar
    lang: str = "php"  # o nome no OSV: php ou node

    @property
    def floating(self) -> bool:
        return self.version.count(".") < 2

    @property
    def branch(self) -> str:
        """A série: 8.3 no PHP; no Node.js, o major (24), ou a versão dada quando ela acompanha uma série (24.10)."""
        if self.floating:
            return self.version
        return ".".join(self.version.split(".")[:1 if self.lang == "node" else 2])

    @property
    def query(self) -> str:
        """A versão perguntada ao OSV: a exata, ou a primeira da série (8.3.0, 24.0.0), que tem tudo o que a série teve."""
        return ".".join((self.version.split(".") + ["0", "0"])[:3])


_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")
_NODE_VERSION = re.compile(r"\d+(?:\.\d+){0,2}")
# A imagem oficial (php, library/php; node, library/node) e a da Bitnami, direto do Docker Hub ou por um espelho
# conhecido dele.
_HUB = r"(?:(?:docker\.io|index\.docker\.io|registry-1\.docker\.io|mirror\.gcr\.io|public\.ecr\.aws/docker)/)?"
_IMAGE = re.compile(_HUB + r"(?:(?:library/)?php|bitnami/php-fpm):(?P<tag>[\w][\w.-]*)")
_NODE_IMAGE = re.compile(_HUB + r"(?:(?:library/)?node|bitnami/node):(?P<tag>[\w][\w.-]*)")
# Tag com série (8.3) ou versão (8.3.30) no começo: 8.3-apache, 8.3.30-fpm-alpine, 8.3.30-debian-12-r5. Sem número
# (latest, apache) ou só com o major (8-cli) não diz qual PHP é. Pré-lançamento (8.5-rc, 8.5.0RC1) fica de fora.
_TAG = re.compile(r"(\d+\.\d+(?:\.\d+)?)(?=$|-)")
# No Node.js o major já é a série (node:24-alpine), e o nome de uma série LTS vale por ele (node:iron-alpine, lts/iron
# no .nvmrc). lts e current mudam de série com o tempo: não dizem qual Node.js é.
CODENAMES = {"argon": "4", "boron": "6", "carbon": "8", "dubnium": "10", "erbium": "12", "fermium": "14",
             "gallium": "16", "hydrogen": "18", "iron": "20", "jod": "22", "krypton": "24"}
_NODE_TAG = re.compile(r"(\d+(?:\.\d+){0,2}|" + "|".join(CODENAMES) + r")(?=$|-)")
_RC = re.compile(r"(?i)(?:^|-)rc\d*(?:-|$)")
_FROM = re.compile(r"(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?")
_ARG = re.compile(r"(?i)^\s*ARG\s+(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)")
_COMPOSE_IMAGE = re.compile(r"^\s*-?\s*image:\s*[\"']?([^\"'\s#]+)")
_VAR = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)")
_DOCKERFILE = re.compile(r"(?i)(?:docker|container)file(?:\.[\w.-]+)?|[\w.-]+\.(?:docker|container)file")
_COMPOSE = re.compile(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml")
_MISE = re.compile(r"\.?mise(?:\.[\w-]+)?\.toml")
_TOOL_VERSIONS = re.compile(r"^\s*php\s+(\S+)")
_TOOL_VERSIONS_NODE = re.compile(r"^\s*node(?:js)?\s+(\S+)")
_MISE_TOOL = r"""^\s*["']?{}["']?\s*=\s*(?:\[\s*)?(?:\{{[^}}]*?\bversion\s*=\s*)?["']([^"']+)["']"""
_MISE_PHP = re.compile(_MISE_TOOL.format("php"))
_MISE_NODE = re.compile(_MISE_TOOL.format("node(?:js)?"))
# .replit: modules = ["nodejs-20", "web", "postgresql-16"]; nodejs-20:v8-20230920-bd784b9 fixa a montagem do módulo,
# não a versão do Node.js.
_REPLIT_MODULES = re.compile(r"(?m)^\s*modules\s*=\s*\[([^\]]*)\]")
_REPLIT_NODE = re.compile(r"""["']nodejs-(\d+)(?::[^"']*)?["']""")
# Dependência de quem serve páginas ou API com o Node.js: sem ela, o .nvmrc e os outros arquivos de versão costumam
# só dizer com qual Node.js montar um site estático (Vite, depois arquivos num CDN), e a falha do Node.js não chega
# a quem visita.
_NODE_SERVERS = {"express", "fastify", "koa", "hono", "@hono/node-server", "@nestjs/core", "next", "nuxt",
                 "@remix-run/node", "@remix-run/serve", "@react-router/node", "@react-router/serve",
                 "@sveltejs/adapter-node", "@astrojs/node", "socket.io", "ws", "@apollo/server", "apollo-server",
                 "@trpc/server", "h3", "@hapi/hapi", "restify", "polka", "@feathersjs/feathers"}
_NODE_START = re.compile(r"(?:^|[\s;&|(=])(?:node|tsx|ts-node|nodemon|pm2(?:-runtime)?)\s")


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
    """(php ou node, versão) de uma imagem (php:8.3.30-apache -> php, 8.3.30; node:iron-alpine -> node, 20), ou None
    se não for PHP nem Node.js ou não disser a versão."""
    bare = ref.split("@", 1)[0]
    for lang, image, tag in (("php", _IMAGE, _TAG), ("node", _NODE_IMAGE, _NODE_TAG)):
        m = image.fullmatch(bare)
        if not m:
            continue
        v = tag.match(m["tag"]) if not _RC.search(m["tag"]) else None
        return (lang, CODENAMES.get(v.group(1), v.group(1))) if v else None
    return None


def _final_stage(stages):
    """A etapa que roda: a última, ou a etapa de antes de onde ela parte (FROM node:20 AS base ... FROM base)."""
    i = len(stages) - 1
    while i > 0:
        ref = stages[i][0].lower()
        earlier = [j for j in range(i) if stages[j][1] == ref]
        if not earlier:
            break
        i = earlier[-1]
    return stages[i]


def _dockerfile(rel, text):
    out, args, seen_from, stages = [], {}, False, []
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
        found = _from_image(got[0]) if got else None
        if found and found[0] == "php":
            out.append(Runtime(found[1], rel, n, got[0], got[1]))
        stages.append((m.group(1), (m.group(2) or "").lower(), n, got, found))
    # Do Node.js conta só a etapa que roda: as de antes costumam só montar o app (FROM node:20 AS build, depois
    # FROM nginx com os arquivos prontos), e o Node.js delas não fica na imagem publicada.
    if stages:
        _, _, n, got, found = _final_stage(stages)
        if found and found[0] == "node":
            out.append(Runtime(found[1], rel, n, got[0], got[1], "node"))
    return out


def _compose(rel, text):
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        m = _COMPOSE_IMAGE.match(line)
        got = _expand(m.group(1), {}) if m else None
        found = _from_image(got[0]) if got else None
        if found:
            out.append(Runtime(found[1], rel, n, got[0], lang=found[0]))
    return out


def _php_version(rel, text):
    """.php-version: a primeira linha com conteúdo é a versão."""
    for n, line in enumerate(text.split("\n"), 1):
        s = line.split("#", 1)[0].strip()
        if s:
            return [Runtime(s, rel, n)] if _VERSION.fullmatch(s) else []
    return []


def _node_version(value):
    """24.10.0 de v24.10.0; 20 de lts/iron ou lts-iron; None para lts/*, node, system e o que não for versão."""
    v = value.strip()
    v = v[1:] if v[:1] in "vV" else v
    if v.lower().startswith(("lts/", "lts-")):
        v = CODENAMES.get(v[4:].lower(), "")
    return v if _NODE_VERSION.fullmatch(v) else None


def _first_match(rel, text, pattern, section=None, lang="php"):
    """A primeira linha que dá a versão: no .tool-versions, ou na tabela [tools] do mise.toml."""
    current = None
    for n, line in enumerate(text.split("\n"), 1):
        s = line.split("#", 1)[0].strip()
        if section and s.startswith("["):
            current = s.strip("[] ")
            continue
        m = pattern.match(s) if not section or current == section else None
        if not m:
            continue
        if lang == "node":
            v = _node_version(m.group(1))
            if v:
                return [Runtime(v, rel, n, lang="node")]
        elif _VERSION.fullmatch(m.group(1)):
            return [Runtime(m.group(1), rel, n)]
    return []


def _nvmrc(rel, text):
    """.nvmrc e .node-version: a primeira linha com conteúdo é a versão."""
    for n, line in enumerate(text.split("\n"), 1):
        s = line.split("#", 1)[0].strip()
        if s:
            v = _node_version(s)
            return [Runtime(v, rel, n, lang="node")] if v else []
    return []


def _replit(rel, text):
    """O módulo nodejs-NN do .replit: a Replit roda o Node.js NN mais novo que o módulo tem."""
    m = _REPLIT_MODULES.search(text)
    node = _REPLIT_NODE.search(m.group(1)) if m else None
    if not node:
        return []
    return [Runtime(node.group(1), rel, text.count("\n", 0, m.start(1) + node.start()) + 1, lang="node")]


def _serves_with_node(ctx):
    """Algum package.json do projeto roda um servidor no Node.js: depende de um (express, next...) ou o start chama
    o node."""
    for rel in ctx.files:
        if rel.rsplit("/", 1)[-1] != "package.json":
            continue
        try:
            pkg = json.loads(ctx.read(rel) or "{}")
        except (ValueError, RecursionError):
            continue
        if not isinstance(pkg, dict):
            continue
        deps, scripts = pkg.get("dependencies"), pkg.get("scripts")
        if isinstance(deps, dict) and _NODE_SERVERS & set(deps):
            return True
        start = scripts.get("start") if isinstance(scripts, dict) else None
        if isinstance(start, str) and _NODE_START.search(start + " "):
            return True
    return False


def collect(ctx):
    """A versão do PHP e do Node.js de cada lugar que a define, sem repetir a mesma versão do mesmo tipo (imagem ou
    arquivo). A imagem do Node.js sempre conta: é ela que roda. O arquivo de versão do Node.js conta quando o projeto
    roda um servidor no Node.js."""
    out, seen, node_files = [], set(), []
    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if _DOCKERFILE.fullmatch(name):
            found = _dockerfile(rel, ctx.read(rel))
        elif _COMPOSE.fullmatch(name):
            found = _compose(rel, ctx.read(rel))
        elif name == ".php-version":
            found = _php_version(rel, ctx.read(rel))
        elif name == ".tool-versions":
            text = ctx.read(rel)
            found = _first_match(rel, text, _TOOL_VERSIONS)
            node_files += _first_match(rel, text, _TOOL_VERSIONS_NODE, lang="node")
        elif _MISE.fullmatch(name):
            text = ctx.read(rel)
            found = _first_match(rel, text, _MISE_PHP, "tools")
            node_files += _first_match(rel, text, _MISE_NODE, "tools", lang="node")
        elif name in (".nvmrc", ".node-version"):
            found, node_files = [], node_files + _nvmrc(rel, ctx.read(rel))
        elif name == ".replit":
            found, node_files = [], node_files + _replit(rel, ctx.read(rel))
        else:
            continue
        out += found
    if node_files and _serves_with_node(ctx):
        out += node_files
    unique = []
    for rt in out:
        key = (rt.lang, rt.version, bool(rt.image))
        if key not in seen:
            seen.add(key)
            unique.append(rt)
    return unique


def retag(rt: Runtime, version: str) -> str:
    """A mesma imagem com outra versão: php:8.3.30-apache -> php:8.3.36-apache, node:iron-alpine -> node:20.20.2-alpine."""
    head, tag = rt.image.split("@", 1)[0].rsplit(":", 1)
    return f"{head}:{version}{tag[(_NODE_TAG if rt.lang == 'node' else _TAG).match(tag).end(1):]}"
