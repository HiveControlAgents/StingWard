"""Linha de comando.

  stingward [caminho]            audita o projeto (padrão: pasta atual)
  stingward skill <caminho|url>  audita uma skill, plugin ou servidor MCP antes de instalar
  stingward agents               audita as configurações de agentes desta máquina
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

from . import __version__, gitsafe, report, report_html, scan
from .model import SEV_RANK

COMMANDS = {"scan", "skill", "agents"}
_OWNER_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[\w.-]+")


def _default_lang():
    for var in ("STINGWARD_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        v = os.environ.get(var, "")
        if v:
            return "pt" if v.lower().startswith("pt") else "en"
    return "en"


def _parser():
    ap = argparse.ArgumentParser(prog="stingward", description="Auditoria de segurança para projetos feitos com IA, skills e MCP.")
    ap.add_argument("command", nargs="?", default="scan", help="scan (padrão), skill ou agents")
    ap.add_argument("target", nargs="?", default=".", help="pasta do projeto, ou caminho/URL da skill")
    ap.add_argument("--lang", choices=["pt", "en"], default=None, help="idioma do relatório")
    ap.add_argument("--format", choices=["text", "json", "markdown", "sarif", "html"], default="text", help="formato na saída padrão")
    ap.add_argument("--sarif", metavar="ARQ", help="grava SARIF (painel de segurança do GitHub)")
    ap.add_argument("--markdown", metavar="ARQ", help="grava Markdown (comentário de PR)")
    ap.add_argument("--json", metavar="ARQ", help="grava JSON")
    ap.add_argument("--html", metavar="ARQ", help="grava o relatório em HTML (um arquivo só, para entregar ou imprimir em PDF)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high",
                    help="sai com código 1 se houver achado desta severidade ou acima (padrão: high)")
    ap.add_argument("--only", default=None, help="só estas verificações: deps,secrets,app,agents")
    ap.add_argument("--offline", action="store_true", help="não consulta as bases (pula dependências)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"stingward {__version__}")
    return ap


def _is_remote(target):
    if re.match(r"^(https?://|git@)", target):
        return True
    # Dono no GitHub é letra, número ou hífen: "./minha-skill" que não existe é pasta errada, não repositório.
    return not os.path.exists(target) and _OWNER_REPO.fullmatch(target) is not None


def _fetch(target):
    """Clona a skill numa pasta temporária. Aceita URL do GitHub com /tree/<branch>/<subpasta>."""
    sub = ""
    url = target
    m = re.match(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.*))?)?/?$", target)
    branch = None
    if m:
        url = f"https://github.com/{m.group(1)}/{m.group(2)}.git"
        branch, sub = m.group(3), m.group(4) or ""
    elif _OWNER_REPO.fullmatch(target):
        url = f"https://github.com/{target}.git"
    tmp = tempfile.mkdtemp(prefix="stingward-")
    cmd = ["git", "clone", "--depth", "1", "--quiet"] + (["--branch", branch] if branch else []) + ["--", url, os.path.join(tmp, "repo")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
    if r.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise SystemExit(f"stingward: não consegui baixar {target}: {r.stderr.strip()}")
    return tmp, os.path.join(tmp, "repo", sub)


def agent_files(home):
    """Configurações de agentes conhecidas, relativas à home."""
    candidates = [
        ".claude/settings.json", ".claude/settings.local.json", ".claude.json", ".claude/CLAUDE.md",
        ".cursor/mcp.json", ".codex/config.toml", ".codex/AGENTS.md", ".gemini/settings.json", ".gemini/GEMINI.md",
        ".codeium/windsurf/mcp_config.json", ".config/Claude/claude_desktop_config.json",
        "Library/Application Support/Claude/claude_desktop_config.json",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "Library/Application Support/Code/User/mcp.json", ".config/Code/User/mcp.json",
    ]
    files = [c for c in candidates if os.path.isfile(os.path.join(home, c))]
    for d in (".claude/skills", ".claude/agents", ".claude/commands", ".claude/hooks", ".claude/plugins", ".codex/skills"):
        base = os.path.join(home, d)
        if os.path.isdir(base):
            files += [f"{d}/{p}" for p in scan.list_files(base, max_files=5000)]
    return files


def _utf8_output():
    """No Windows, saída redirecionada usa cp1252 e quebraria nos emojis do relatório."""
    for stream in (sys.stdout, sys.stderr):
        try:
            "🔴".encode(stream.encoding or "ascii")
        except (UnicodeEncodeError, LookupError):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass


def _git_prefix(path):
    """Pasta auditada relativa à raiz do repositório git (vazio se não for repositório). Sem rodar git na pasta auditada."""
    return gitsafe.prefix(path)


def _emit(args, ctx, findings, lang, label, only, remote):
    verdict = args.command == "skill"
    # Skill baixada não tem prefixo no SARIF: os caminhos são da pasta auditada, não do repositório clonado.
    prefix = lambda: "" if args.command == "agents" or remote else _git_prefix(ctx.root)
    outputs = {
        "text": lambda: report.text(ctx, findings, lang, color=not args.no_color and sys.stdout.isatty(), target=label, show_verdict=verdict),
        "json": lambda: report.as_json(ctx, findings, lang),
        "markdown": lambda: report.markdown(ctx, findings, lang, target=label, show_verdict=verdict),
        "sarif": lambda: report.sarif(ctx, findings, lang, prefix=prefix()),
        "html": lambda: report_html.render(ctx, findings, lang, target=label, checks=only),
    }
    done = {}

    def out(fmt):
        if fmt not in done:
            done[fmt] = outputs[fmt]()
        return done[fmt]

    sys.stdout.write(out(args.format))
    for fmt, path in (("sarif", args.sarif), ("markdown", args.markdown), ("json", args.json), ("html", args.html)):
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(out(fmt))


def main(argv=None):
    _utf8_output()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and not argv[0].startswith("-") and argv[0] not in COMMANDS:
        argv.insert(0, "scan")
    args = _parser().parse_args(argv)
    if args.command not in COMMANDS:
        # `stingward --offline minha-pasta`: o primeiro posicional é a pasta, não um comando.
        if args.target != ".":
            print(f"stingward: comando desconhecido: {args.command}", file=sys.stderr)
            return 2
        args.command, args.target = "scan", args.command
    lang = args.lang or _default_lang()
    only = {x.strip() for x in args.only.split(",") if x.strip()} if args.only else None
    if only is not None and (not only or only - set(scan.CHECKS)):
        print(f"stingward: --only aceita {','.join(scan.CHECKS)}", file=sys.stderr)
        return 2

    tmp = None
    try:
        if args.command == "agents":
            home = os.path.expanduser("~")
            ctx, findings = scan.run(home, mode="agents", offline=args.offline, only=only, files=agent_files(home))
            label = "~"
        elif args.command == "skill":
            path = args.target
            if _is_remote(path):
                tmp, path = _fetch(path)
            if not os.path.isdir(path):
                print(f"stingward: pasta não encontrada: {path}", file=sys.stderr)
                return 2
            ctx, findings = scan.run(path, mode="skill", offline=args.offline, only=only)
            label = args.target
        else:
            if not os.path.isdir(args.target):
                print(f"stingward: pasta não encontrada: {args.target}", file=sys.stderr)
                return 2
            ctx, findings = scan.run(args.target, mode="project", offline=args.offline, only=only)
            label = args.target
        # Os relatórios saem antes de apagar a skill baixada: o HTML lê dela os trechos de código e o commit.
        _emit(args, ctx, findings, lang, label, only, remote=tmp is not None)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    if args.fail_on == "never":
        return 0
    if any(SEV_RANK[f.severity] >= SEV_RANK[args.fail_on] for f in findings):
        return 1
    # Portão de CI não pode passar só porque a base não respondeu.
    if ctx.sources.get("osv_error"):
        msg = {"pt": "stingward: o OSV.dev não respondeu e as dependências não foram checadas (use --offline para pular de propósito).",
               "en": "stingward: OSV.dev did not respond, so dependencies were not checked (use --offline to skip them on purpose)."}
        print(msg[lang], file=sys.stderr)
        return 3
    return 0
