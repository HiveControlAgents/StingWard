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

from . import __version__, _redact as redact, gitsafe, report, report_html, review, scan
from .model import SEV_RANK

COMMANDS = {"scan", "skill", "agents"}
_OWNER_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[\w.-]+")
# Usuário e senha (ou token) dentro de uma URL: https://x-access-token:<token>@github.com/... Vai até o último @ do host.
_USERINFO = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{0,30}://)[^/?#\s]*@")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _shown(text):
    """Texto que vai para a tela e para os relatórios: sem a credencial de uma URL e sem sequências de terminal."""
    return _CONTROL.sub("", _USERINFO.sub(r"\1", str(text)))


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
    ap.add_argument("--review", metavar="ARQ", help="arquivo de revisão (JSON): o status e o comentário de quem revisou cada achado")
    ap.add_argument("--review-template", metavar="ARQ", help="grava o arquivo de revisão com um item por achado (mantém o que já foi revisado)")
    ap.add_argument("--client", metavar="NOME", help="para quem é o relatório: aparece na capa como \"Preparado para\"")
    ap.add_argument("--notes", metavar="ARQ", help="parecer do analista em Markdown simples (parágrafos, listas, **negrito**, `código`)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high",
                    help="sai com código 1 se houver achado desta severidade ou acima (padrão: high)")
    ap.add_argument("--only", default=None, help="só estas verificações: deps,secrets,app,code,agents")
    ap.add_argument("--offline", action="store_true", help="não consulta as bases (pula dependências)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"stingward {__version__}")
    return ap


def _is_remote(target):
    if re.match(r"^(https?://|git@)", target):
        return True
    # Dono no GitHub é letra, número ou hífen: "./minha-skill" que não existe é pasta errada, não repositório.
    return not os.path.exists(target) and _OWNER_REPO.fullmatch(target) is not None


CLONE_TIMEOUT = 180


class FetchError(Exception):
    """Não deu para baixar a skill. key escolhe a mensagem em MSG; detail é o que o git disse."""

    def __init__(self, key, detail=""):
        super().__init__(key, detail)
        self.key, self.detail = key, detail


def _fetch(target):
    """Clona a skill numa pasta temporária. Aceita URL do GitHub com /tree/<branch>/<subpasta>.
    Em qualquer falha (ou Ctrl+C) a pasta temporária é apagada antes de sair."""
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
    try:
        # As mesmas opções do gitsafe: hooks globais (core.hooksPath, init.templateDir) não rodam no checkout da skill.
        cmd = ["git", *gitsafe._SAFE, "clone", "--depth", "1", "--quiet"] + (["--branch", branch] if branch else []) + \
            ["--", url, os.path.join(tmp, "repo")]
        try:
            r = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=CLONE_TIMEOUT,
                               env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
        except subprocess.TimeoutExpired:
            raise FetchError("timeout") from None
        except OSError as e:
            raise FetchError("nogit", str(e)) from None
        if r.returncode != 0:
            # A mensagem do git traz texto do servidor remoto ("remote: ..."): sai mascarada e sem sequências de terminal.
            raise FetchError("git", redact.sanitize_text((r.stderr or "").strip()))
        repo = os.path.realpath(os.path.join(tmp, "repo"))
        path = os.path.join(tmp, "repo", sub)
        # A subpasta vem da URL e os links simbólicos, do autor da skill: "../.." ou skill -> ~ levariam a auditoria
        # (e o veredito) para uma pasta que não é a skill baixada.
        real = os.path.realpath(path)
        if real != repo and not real.startswith(repo + os.sep):
            raise FetchError("outside", sub)
        return tmp, path
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


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


MSG = {
    "pt": {"unknown": "stingward: comando desconhecido: {cmd}",
           "only": "stingward: --only aceita {checks}",
           "nodir": "stingward: pasta não encontrada: {path}",
           "git": "stingward: não consegui baixar {target}: {detail}",
           "timeout": f"stingward: não consegui baixar {{target}}: o git clone passou de {CLONE_TIMEOUT} s",
           "nogit": "stingward: não consegui baixar {target}: o git não está instalado ou não abriu ({detail})",
           "outside": "stingward: não vou auditar {target}: a subpasta {detail} fica fora do repositório baixado",
           "stale": "stingward: {n} item(ns) de {path} não batem com nenhum achado desta varredura (o código mudou ou o achado sumiu).",
           "todo": "stingward: {n} achado(s) ainda sem status em {path}; eles contam como achados.",
           "masked": "stingward: mascarei algo que parece segredo num comentário ou no parecer. Confira o relatório antes de entregar.",
           "template": "stingward: arquivo de revisão gravado em {path}: {n} achado(s), {kept} já revisado(s), {stale} que não batem mais com nenhum achado."},
    "en": {"unknown": "stingward: unknown command: {cmd}",
           "only": "stingward: --only takes {checks}",
           "nodir": "stingward: folder not found: {path}",
           "git": "stingward: could not download {target}: {detail}",
           "timeout": f"stingward: could not download {{target}}: git clone took more than {CLONE_TIMEOUT} s",
           "nogit": "stingward: could not download {target}: git is not installed or did not start ({detail})",
           "outside": "stingward: will not audit {target}: the subfolder {detail} is outside the downloaded repository",
           "stale": "stingward: {n} item(s) in {path} match no finding of this scan (the code changed or the finding is gone).",
           "todo": "stingward: {n} finding(s) still have no status in {path}; they count as found.",
           "masked": "stingward: masked something that looks like a secret in a comment or the notes. Check the report before you deliver it.",
           "template": "stingward: review file written to {path}: {n} finding(s), {kept} already reviewed, {stale} no longer matching any finding."},
}


def _say(lang, key, **kw):
    print(MSG[lang][key].format(**{k: _shown(v) for k, v in kw.items()}), file=sys.stderr)


def _emit(args, ctx, findings, lang, label, only, remote, audit=None):
    verdict = args.command == "skill"
    # Skill baixada não tem prefixo no SARIF: os caminhos são da pasta auditada, não do repositório clonado.
    prefix = lambda: "" if args.command == "agents" or remote else _git_prefix(ctx.root)
    outputs = {
        "text": lambda: report.text(ctx, findings, lang, color=not args.no_color and sys.stdout.isatty(), target=label, show_verdict=verdict,
                                    audit=audit),
        "json": lambda: report.as_json(ctx, findings, lang, audit=audit),
        "markdown": lambda: report.markdown(ctx, findings, lang, target=label, show_verdict=verdict, audit=audit),
        "sarif": lambda: report.sarif(ctx, findings, lang, prefix=prefix()),
        "html": lambda: report_html.render(ctx, findings, lang, target=label, checks=only, audit=audit),
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
    lang = args.lang or _default_lang()
    if args.command not in COMMANDS:
        # `stingward --offline minha-pasta`: o primeiro posicional é a pasta, não um comando.
        if args.target != ".":
            _say(lang, "unknown", cmd=args.command)
            return 2
        args.command, args.target = "scan", args.command
    only = {x.strip() for x in args.only.split(",") if x.strip()} if args.only else None
    if only is not None and (not only or only - set(scan.CHECKS)):
        _say(lang, "only", checks=",".join(scan.CHECKS))
        return 2

    try:
        rv = review.load(args.review) if args.review else None
        notes = review.load_notes(args.notes) if args.notes else ""
        old = review.load(args.review_template) if args.review_template and os.path.exists(args.review_template) else None
    except review.ReviewError as e:
        print(f"stingward: {e}", file=sys.stderr)
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
                try:
                    tmp, path = _fetch(path)
                except FetchError as e:
                    _say(lang, e.key, target=path, detail=e.detail)
                    return 2
            if not os.path.isdir(path):
                _say(lang, "nodir", path=path)
                return 2
            ctx, findings = scan.run(path, mode="skill", offline=args.offline, only=only)
            label = _shown(args.target)
        else:
            if not os.path.isdir(args.target):
                _say(lang, "nodir", path=args.target)
                return 2
            ctx, findings = scan.run(args.target, mode="project", offline=args.offline, only=only)
            label = args.target
        audit = None
        if rv is not None or notes or args.client:
            audit = review.Audit(ctx, findings, rv, client=args.client or "", notes=notes)
        if rv is not None:
            stale = rv.stale(findings)
            todo = sum(1 for f in findings if not rv.status(f))
            if stale:
                _say(lang, "stale", n=len(stale), path=args.review)
            if todo:
                _say(lang, "todo", n=todo, path=args.review)
        # Os relatórios saem antes de apagar a skill baixada: o HTML lê dela os trechos de código e o commit.
        _emit(args, ctx, findings, lang, label, only, remote=tmp is not None, audit=audit)
        if audit is not None and audit.mask.changed:
            _say(lang, "masked")
        if args.review_template:
            text, kept, stale = review.template(findings, lang, old=old, target=report_html._name(ctx, label, report_html.H[lang]))
            with open(args.review_template, "w", encoding="utf-8") as fh:
                fh.write(text)
            _say(lang, "template", path=args.review_template, n=len(findings), kept=kept, stale=stale)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    if args.fail_on == "never":
        return 0
    # Com revisão, alarme falso e o que foi corrigido não reprovam: valem os mesmos achados da nota.
    if any(SEV_RANK[f.severity] >= SEV_RANK[args.fail_on] for f in report.counted(findings, rv)):
        return 1
    # Portão de CI não pode passar só porque a base não respondeu.
    if ctx.sources.get("osv_error"):
        msg = {"pt": "stingward: o OSV.dev não respondeu e as dependências não foram checadas (use --offline para pular de propósito).",
               "en": "stingward: OSV.dev did not respond, so dependencies were not checked (use --offline to skip them on purpose)."}
        print(msg[lang], file=sys.stderr)
        return 3
    return 0
