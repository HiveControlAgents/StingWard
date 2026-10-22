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


# Textos do --help, no idioma dos relatórios. As palavras do próprio argparse ("usage", "options", as mensagens de
# erro) seguem o gettext do Python, em inglês.
HELP = {
    "pt": {"description": "Auditoria de segurança para projetos feitos com IA, skills e MCP.",
           "file": "ARQ", "name": "NOME", "list": "LISTA",
           "help": "mostra esta ajuda e sai",
           "command": "scan (padrão), skill ou agents",
           "target": "pasta do projeto, ou caminho/URL da skill",
           "lang": "idioma do relatório (padrão: STINGWARD_LANG, depois o idioma do sistema)",
           "format": "formato na saída padrão",
           "sarif": "grava SARIF (painel de segurança do GitHub)",
           "markdown": "grava Markdown (comentário de PR)",
           "json": "grava JSON",
           "html": "grava o relatório em HTML (um arquivo só, para entregar ou imprimir em PDF)",
           "review": "arquivo de revisão (JSON): o status e o comentário de quem revisou cada achado",
           "review_template": "grava o arquivo de revisão com um item por achado (mantém o que já foi revisado)",
           "client": "para quem é o relatório: aparece na capa como \"Preparado para\"",
           "notes": "parecer do analista em Markdown simples (parágrafos, listas, **negrito**, `código`)",
           "fail_on": "sai com código 1 se houver achado desta severidade ou acima (padrão: high)",
           "only": "só estas verificações: deps,secrets,app,code,agents",
           "offline": "não consulta as bases (pula dependências)",
           "no_ignore": "não aplica o .stingwardignore nem os comentários stingward:ignore do projeto (para auditar o "
                        "projeto de outra pessoa)",
           "no_color": "texto sem cores, mesmo no terminal",
           "version": "mostra a versão e sai"},
    "en": {"description": "Security audit for AI-built projects, skills and MCP servers.",
           "file": "FILE", "name": "NAME", "list": "LIST",
           "help": "show this help and exit",
           "command": "scan (default), skill or agents",
           "target": "project folder, or the skill's path or URL",
           "lang": "report language (default: STINGWARD_LANG, then the system language)",
           "format": "format of the standard output",
           "sarif": "write SARIF (GitHub security tab)",
           "markdown": "write Markdown (pull request comment)",
           "json": "write JSON",
           "html": "write the HTML report (a single file, to deliver or print to PDF)",
           "review": "review file (JSON): the status and comment of whoever reviewed each finding",
           "review_template": "write the review file with one entry per finding (keeps what was already reviewed)",
           "client": "who the report is for: shown on the cover as \"Prepared for\"",
           "notes": "analyst summary in simple Markdown (paragraphs, lists, **bold**, `code`)",
           "fail_on": "exit with code 1 if there is a finding at this severity or above (default: high)",
           "only": "only these checks: deps,secrets,app,code,agents",
           "offline": "do not query the online databases (skips dependencies)",
           "no_ignore": "do not apply the project's .stingwardignore or stingward:ignore comments (to audit someone "
                        "else's project)",
           "no_color": "plain text without colors, even in a terminal",
           "version": "show the version and exit"},
}


def _argv_lang(argv):
    """--lang da linha de comando, lido antes do argparse: o --help é impresso assim que aparece, antes do resto."""
    lang = None
    for i, a in enumerate(argv):
        if a == "--":
            break
        v = argv[i + 1] if a == "--lang" and i + 1 < len(argv) else a[len("--lang="):] if a.startswith("--lang=") else None
        if v in HELP:
            lang = v
    return lang


def _parser(lang=None):
    h = HELP[lang or _default_lang()]
    ap = argparse.ArgumentParser(prog="stingward", description=h["description"], add_help=False)
    ap.add_argument("-h", "--help", action="help", help=h["help"])
    # Sem default: _parse precisa saber o que foi dado para pôr o alvo depois de `--` no lugar certo.
    ap.add_argument("command", nargs="?", help=h["command"])
    ap.add_argument("target", nargs="?", help=h["target"])
    ap.add_argument("--lang", choices=["pt", "en"], default=None, help=h["lang"])
    ap.add_argument("--format", choices=["text", "json", "markdown", "sarif", "html"], default="text", help=h["format"])
    ap.add_argument("--sarif", metavar=h["file"], help=h["sarif"])
    ap.add_argument("--markdown", metavar=h["file"], help=h["markdown"])
    ap.add_argument("--json", metavar=h["file"], help=h["json"])
    ap.add_argument("--html", metavar=h["file"], help=h["html"])
    ap.add_argument("--review", metavar=h["file"], help=h["review"])
    ap.add_argument("--review-template", metavar=h["file"], help=h["review_template"])
    ap.add_argument("--client", metavar=h["name"], help=h["client"])
    ap.add_argument("--notes", metavar=h["file"], help=h["notes"])
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high", help=h["fail_on"])
    ap.add_argument("--only", metavar=h["list"], default=None, help=h["only"])
    ap.add_argument("--offline", action="store_true", help=h["offline"])
    ap.add_argument("--no-ignore", action="store_true", help=h["no_ignore"])
    ap.add_argument("--no-color", action="store_true", help=h["no_color"])
    ap.add_argument("--version", action="version", version=f"stingward {__version__}", help=h["version"])
    return ap


def _parse(argv):
    """Linha de comando com o alvo em qualquer posição e depois de `--`, igual do Python 3.9 ao 3.13.

    Até o 3.12 o argparse preenchia command e target de uma vez ao ver `skill`: `skill --offline pasta` e
    `skill --offline -- pasta` davam "unrecognized arguments". parse_intermixed_args lê as opções antes; o que vem
    depois de `--` entra à parte porque, antes do 3.13, ele tomava `-- -pasta` por uma opção."""
    ap = _parser(_argv_lang(argv))
    head, tail = argv, []
    if "--" in argv:
        i = argv.index("--")
        head, tail = argv[:i], argv[i + 1:]
    args = ap.parse_intermixed_args(head)
    pos = [p for p in (args.command, args.target) if p is not None] + tail
    if len(pos) > 2:
        ap.error("unrecognized arguments: " + " ".join(pos[2:]))
    if len(pos) == 1 and pos[0] not in COMMANDS:
        pos.insert(0, "scan")  # `stingward minha-pasta`: o único posicional é a pasta
    args.command, args.target = (pos + ["scan", "."][len(pos):])[:2]
    return args


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
           "write": "stingward: não consegui gravar {path}: {detail}",
           "too_big": "stingward: {n} arquivo(s) acima de {mb} MB não foram lidos e ficaram fora da auditoria: {files}",
           "truncated": "stingward: a pasta tem mais de {n} arquivos; parei de ler aí, e o resto ficou fora da auditoria.",
           "osv_down": "stingward: o OSV.dev não respondeu e as dependências não foram checadas (use --offline para pular de propósito).",
           "osv_partial": "stingward: a checagem de dependências ficou incompleta: {detail}. Rode de novo mais tarde.",
           "kev_down": "stingward: a lista CISA KEV não respondeu: uma falha que atacantes já exploram pode aparecer com "
                       "severidade abaixo da real.",
           "stale": "stingward: {n} item(ns) de {path} não batem com nenhum achado desta varredura (o código mudou ou o achado sumiu).",
           "todo": "stingward: {n} achado(s) ainda sem status em {path}; eles contam como achados.",
           "masked": "stingward: mascarei algo que parece segredo num comentário ou no parecer. Confira o relatório antes de entregar.",
           "template": "stingward: arquivo de revisão gravado em {path}: {n} achado(s), {kept} já revisado(s), {stale} que não batem mais com nenhum achado (marcados com \"stale\": true e mantidos no fim).",
           "nothing": "stingward: nenhum arquivo foi lido, então não há o que avaliar (código de saída 4). Confira o caminho e, no CI, se o código foi baixado antes (checkout)."},
    "en": {"unknown": "stingward: unknown command: {cmd}",
           "only": "stingward: --only takes {checks}",
           "nodir": "stingward: folder not found: {path}",
           "git": "stingward: could not download {target}: {detail}",
           "timeout": f"stingward: could not download {{target}}: git clone took more than {CLONE_TIMEOUT} s",
           "nogit": "stingward: could not download {target}: git is not installed or did not start ({detail})",
           "outside": "stingward: will not audit {target}: the subfolder {detail} is outside the downloaded repository",
           "write": "stingward: could not write {path}: {detail}",
           "too_big": "stingward: {n} file(s) over {mb} MB were not read and are not covered by this audit: {files}",
           "truncated": "stingward: the folder has more than {n} files; reading stopped there and the rest is not covered by this audit.",
           "osv_down": "stingward: OSV.dev did not respond, so dependencies were not checked (use --offline to skip them on purpose).",
           "osv_partial": "stingward: the dependency check is incomplete: {detail}. Run it again later.",
           "kev_down": "stingward: the CISA KEV list did not respond: a vulnerability attackers already exploit may show a lower "
                       "severity than it should.",
           "stale": "stingward: {n} item(s) in {path} match no finding of this scan (the code changed or the finding is gone).",
           "todo": "stingward: {n} finding(s) still have no status in {path}; they count as found.",
           "masked": "stingward: masked something that looks like a secret in a comment or the notes. Check the report before you deliver it.",
           "template": "stingward: review file written to {path}: {n} finding(s), {kept} already reviewed, {stale} no longer matching any finding (marked \"stale\": true and kept at the end).",
           "nothing": "stingward: no file was read, so there is nothing to grade (exit code 4). Check the path and, in CI, that the code was checked out first."},
}


def _say(lang, key, **kw):
    print(MSG[lang][key].format(**{k: _shown(v) for k, v in kw.items()}), file=sys.stderr)


class WriteError(Exception):
    """Arquivo de saída (--json, --sarif, --html...) que não deu para gravar."""

    def __init__(self, path, err):
        super().__init__(path, err)
        self.path, self.detail = path, err.strerror or str(err)


def _write(path, text):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as e:
        raise WriteError(path, e) from None


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
            _write(path, out(fmt))


def main(argv=None):
    _utf8_output()
    argv = list(sys.argv[1:] if argv is None else argv)
    args = _parse(argv)
    lang = args.lang or _default_lang()
    if args.command not in COMMANDS:
        _say(lang, "unknown", cmd=args.command)
        return 2
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
            ctx, findings = scan.run(args.target, mode="project", offline=args.offline, only=only,
                                     honor_ignores=not args.no_ignore)
            label = args.target
        if rv is not None:
            try:
                rv.check(findings, ctx)  # regras que dependem da varredura, como "fixed" num achado que continua nela
            except review.ReviewError as e:
                print(f"stingward: {e}", file=sys.stderr)
                return 2
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
        if ctx.too_big:
            limit = scan.SKILL_MAX_BYTES if ctx.mode == "skill" else scan.MAX_BYTES
            shown = ", ".join(ctx.too_big[:5]) + (", ..." if len(ctx.too_big) > 5 else "")
            _say(lang, "too_big", n=len(ctx.too_big), mb=limit // 1_000_000, files=shown)
        if ctx.truncated:
            _say(lang, "truncated", n=scan.MAX_FILES)
        if args.review_template:
            text, kept, stale = review.template(findings, lang, old=old, target=report_html._name(ctx, label, report_html.H[lang]))
            _write(args.review_template, text)
            _say(lang, "template", path=args.review_template, n=len(findings), kept=kept, stale=stale)
    except WriteError as e:
        # Caminho errado em --sarif não pode sair como traceback e código 1, que quer dizer "achou problema".
        _say(lang, "write", path=e.path, detail=e.detail)
        return 2
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    # A base que falhou é dita sempre, em qualquer formato: com --format json ou sarif o stderr é o único aviso legível.
    if report.osv_partial(ctx):  # respondeu em parte: dizer "não respondeu" exageraria (o código de saída continua 3)
        _say(lang, "osv_partial", detail=report._clean(ctx.sources["osv_error"]))
    elif ctx.sources.get("osv_error"):
        _say(lang, "osv_down")
    elif ctx.sources.get("kev_error"):
        _say(lang, "kev_down")
    if args.fail_on == "never":
        return 0
    # Com revisão, alarme falso e o que foi corrigido não reprovam: valem os mesmos achados da nota.
    if any(SEV_RANK[f.severity] >= SEV_RANK[args.fail_on] for f in report.counted(findings, rv)):
        return 1
    # Nem passar porque nada foi lido: pasta vazia, caminho errado ou checkout esquecido no CI dariam um A sem ler nada.
    if report.nothing_read(ctx, findings):
        _say(lang, "nothing")
        return 4
    # Portão de CI não pode passar só porque a base não respondeu.
    if ctx.sources.get("osv_error"):
        return 3
    return 0
