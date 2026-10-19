"""Agentes, skills e MCP: permissões amplas, MCP sem versão fixa, hooks perigosos e prompt injection."""
from __future__ import annotations

import json
import re
import shlex

from .. import _ceovul as cv
from ..model import Finding
from . import is_text_source, line_of

# --------------------------------------------------------------------------- quais arquivos são de agente

INSTRUCTION_NAMES = {"SKILL.md", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                     ".windsurfrules", "copilot-instructions.md"}
_AGENT_DIR = re.compile(r"(^|/)(\.claude|\.claude-plugin|skills|commands|agents|prompts|\.cursor|\.codex|\.gemini|\.windsurf|\.roo)/")
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb")
MCP_FILES = {".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json", ".claude.json",
             "cline_mcp_settings.json", "mcp_settings.json"}


def skill_dirs(ctx):
    dirs = {r.rsplit("/", 1)[0] if "/" in r else "" for r in ctx.files if r.rsplit("/", 1)[-1] == "SKILL.md"}
    if ctx.mode == "skill" and not dirs:
        dirs.add("")
    return dirs


def _in_dirs(rel, dirs):
    return any(d == "" or rel.startswith(d + "/") for d in dirs)


def is_instruction(rel, ctx, dirs):
    name = rel.rsplit("/", 1)[-1]
    if name in INSTRUCTION_NAMES or rel.endswith(".mdc"):
        return True
    if not rel.endswith(".md") or name.lower() in ("readme.md", "changelog.md", "license.md", "contributing.md"):
        return False
    if _AGENT_DIR.search(rel):
        return True
    return _in_dirs(rel, dirs) and not re.search(r"(^|/)(docs?|tests?|examples?|plans)/", rel)


def is_agent_script(rel, ctx, dirs):
    return rel.endswith(_SCRIPT_EXT) and (ctx.mode in ("skill", "agents") or bool(_AGENT_DIR.search(rel)) or _in_dirs(rel, dirs))


# --------------------------------------------------------------------------- padrões de conteúdo

_TAGS = re.compile("[\U000E0000-\U000E007F]+")
_BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")
_ZERO_WIDTH = re.compile("[\u200B\u200C\u2060-\u2064\u180E]|(?<!^)\uFEFF")

_PIPE_SHELL = re.compile(
    r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
    r"(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b|"
    r"(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|;]*\|\s*iex\b|"
    r"\b(?:ba)?sh\s+<\(\s*(?:curl|wget)|\beval\s+\"?\$\(\s*(?:curl|wget)", re.I)

_OVERRIDE = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|rules|prompts|directions)|"
    r"disregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|system)\s+(?:instructions|rules|prompt|guidelines)|"
    r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|warn)\s+the\s+user\s+(?:about|that|what|anything|of)\b|"
    r"(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose|show)\s+(?:this|it|that|these\s+\w+)\s+to\s+the\s+user|"
    r"without\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+user|"
    r"(?:hide|conceal|keep)\s+(?:this|it|these\s+\w+)\s+(?:hidden\s+)?from\s+the\s+user|"
    r"you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|jailbr)|"
    r"override\s+(?:your|the|all)\s+(?:system|safety|previous)\s+(?:prompt|instructions|rules)|"
    r"ignore\s+(?:todas\s+)?as\s+instru[cç][õo]es\s+anteriores|"
    r"n[aã]o\s+(?:conte|diga|avise|mostre|informe|mencione)\s+(?:nada\s+|isso\s+)(?:ao|para\s+o)\s+usu[aá]rio|"
    r"sem\s+(?:avisar|informar|contar\s+(?:a|para)|perguntar\s+a)o?\s+usu[aá]rio|"
    r"esconda\s+(?:isso\s+)?do\s+usu[aá]rio", re.I)

_EXEC_CONTENT = re.compile(
    r"(?:follow|obey|carry\s+out)\s+(?:the\s+|any\s+|all\s+)?instructions\s+(?:in|from|found\s+in|inside|contained\s+in)\s+(?:the\s+|any\s+)?"
    r"(?:file|files|page|url|website|issue|comment|response|output|document|readme|plan)|"
    r"(?:execute|run)\s+(?:the\s+|any\s+|all\s+)?(?:instructions|commands|code)\s+(?:in|from|found\s+in|inside|returned\s+by|listed\s+in)\s+"
    r"(?:the\s+|any\s+)?(?:file|page|url|website|issue|comment|response|output|document|readme|plan)|"
    r"do\s+whatever\s+(?:the|it|this)\s+(?:file|page|issue|comment|document|response)\s+says|"
    r"treat\s+(?:the\s+|its\s+)?(?:content|contents|file|page|response)\s+as\s+(?:your\s+)?instructions|"
    r"siga\s+as\s+instru[cç][õo]es\s+(?:do|da|que\s+estiverem\s+no|contidas\s+no)\s+(?:arquivo|p[aá]gina|site|issue|coment[aá]rio)|"
    r"execute\s+(?:os|as)\s+(?:comandos|instru[cç][õo]es)\s+(?:do|da|que\s+estiverem\s+no)\s+(?:arquivo|p[aá]gina|site|issue)", re.I)

_CREDS = [
    (re.compile(r"~/\.ssh|\.ssh/id_|\bid_rsa\b|\bid_ed25519\b"), "chaves SSH", "SSH keys"),
    (re.compile(r"\.aws/credentials"), "credenciais AWS", "AWS credentials"),
    (re.compile(r"\.config/gh/hosts|gh\s+auth\s+token"), "token do GitHub CLI", "GitHub CLI token"),
    (re.compile(r"\.netrc\b"), ".netrc", ".netrc"),
    (re.compile(r"\.docker/config\.json"), "login do Docker", "Docker login"),
    (re.compile(r"\.kube/config"), "Kubernetes", "Kubernetes"),
    (re.compile(r"Login Data|Local State|Cookies\.binarycookies"), "dados do navegador", "browser data"),
    (re.compile(r"security\s+find-(?:generic|internet)-password\b[^\n]*-w|security\s+dump-keychain"), "chaveiro do sistema", "system keychain"),
    (re.compile(r"\bprintenv\s*(?:$|[|>;&)])|JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|^\s*env\s*\|", re.M),
     "todas as variáveis de ambiente", "all environment variables"),
    (re.compile(r"\.claude/\.credentials|\.claude\.json\b"), "credenciais do Claude", "Claude credentials"),
    (re.compile(r"wallet\.dat|\.solana/id\.json|\bmetamask\b|\bseed\s+phrase\b", re.I), "carteira de cripto", "crypto wallet"),
    (re.compile(r"\b(?:cat|type|readFile\w*|open)\b\W{1,4}[^\n]{0,40}\.env\b"), "arquivo .env", ".env file"),
]
_NET = re.compile(r"\bcurl\b|\bwget\b|\bfetch\(|requests\.(?:post|get|put)|\baxios\b|urllib|http\.request|https?\.request|"
                  r"\bnc\s+-|Invoke-WebRequest|Invoke-RestMethod|XMLHttpRequest|sendBeacon|WebFetch")

_OBFUSCATION = [
    (re.compile(r"[A-Za-z0-9+/]{240,}={0,2}"), "bloco base64 grande", "large base64 blob", "medium"),
    (re.compile(r"\beval\s*\(\s*(?:atob|Buffer\.from|unescape|String\.fromCharCode|decodeURIComponent)"), "eval de texto decodificado", "eval of decoded text", "high"),
    (re.compile(r"\bexec\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|marshal\.loads)"), "exec de texto decodificado", "exec of decoded text", "high"),
    (re.compile(r"base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"), "base64 decodificado direto no shell", "base64 decoded into a shell", "high"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}"), "texto em hexadecimal", "hex-encoded string", "medium"),
    (re.compile(r"new\s+Function\s*\(\s*atob"), "Function de texto decodificado", "Function of decoded text", "high"),
]
_EXFIL = re.compile(
    r"\b(webhook\.site|requestbin\.\w+|[\w-]+\.pipedream\.net|[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)|[\w-]+\.interact\.sh|"
    r"[\w-]+\.oast\.(?:fun|live|me|pro|site|online)|[\w-]+\.burpcollaborator\.net|[\w-]+\.beeceptor\.com|hookbin\.com|"
    r"requestcatcher\.com|api\.telegram\.org/bot|transfer\.sh|pastebin\.com/raw|0x0\.st)", re.I)
_NO_CHECKIN = re.compile(
    r"(?:do\s+not|don'?t|never)\s+(?:pause|stop|wait)\s+(?:to\s+)?(?:check\s+in|ask|confirm)|"
    r"without\s+(?:stopping|pausing|asking\s+(?:for\s+)?(?:permission|confirmation)|confirmation|human\s+review)|"
    r"n[aã]o\s+(?:pare|pause|espere)\s+para\s+(?:perguntar|confirmar|consultar)|sem\s+(?:parar|pedir\s+confirma[cç][aã]o)", re.I)
_LIFECYCLE_DANGER = re.compile(r"\bcurl\b|\bwget\b|node\s+-e|python3?\s+-c|\bsh\s+-c|powershell|\beval\b|base64|https?://")


# --------------------------------------------------------------------------- conteúdo

def _invisible(text, rel, instruction):
    out = []
    m = _TAGS.search(text)
    if m:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0x20 <= ord(c) - 0xE0000 < 0x7F)[:80]
        out.append(Finding("SKL001", "critical", rel, line_of(text, m.start()), {
            "kind_pt": "caracteres de tag Unicode", "kind_en": "Unicode tag characters",
            "why_pt": f"Texto invisível para você, mas a IA lê. Mensagem escondida: \"{hidden}\"",
            "why_en": f"Invisible to you, readable by the AI. Hidden message: \"{hidden}\""}))
    m = _BIDI.search(text)
    if m:
        out.append(Finding("SKL001", "high", rel, line_of(text, m.start()), {
            "kind_pt": "inversão de direção (Trojan Source)", "kind_en": "bidirectional override (Trojan Source)",
            "why_pt": "O texto que aparece na tela é diferente do que o computador e a IA leem.",
            "why_en": "What you see on screen differs from what the computer and the AI read."}))
    if instruction:
        m = _ZERO_WIDTH.search(text)
        if m:
            out.append(Finding("SKL001", "medium", rel, line_of(text, m.start()), {
                "kind_pt": "caracteres de largura zero", "kind_en": "zero-width characters",
                "why_pt": "Caracteres que não aparecem podem esconder palavras ou separar termos para enganar filtros.",
                "why_en": "Invisible characters can hide words or split terms to dodge filters."}))
    return out


_DEFENSIVE = re.compile(r"(?i)inject|as\s+data|never\s+instructions|not\s+instructions|do\s+not\s+follow|don'?t\s+follow|never\s+follow|"
                        r"untrusted|instruction-like|como\s+dado|n[aã]o\s+siga|detect|e\.g\.|for\s+example|por\s+exemplo|such\s+as")


def _defensive(text, m):
    """A frase aparece citada como exemplo de ataque (skill que se defende), não como ordem."""
    window = text[max(0, m.start() - 160):m.end() + 160]
    return bool(_DEFENSIVE.search(window)) or text[max(0, m.start() - 1):m.start()] in ('"', "'", "`", "\u201c")


def _snippet(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= 70 else s[:67] + "..."


def _frontmatter_tools(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    fm = text[3:end] if end > 0 else ""
    m = re.search(r"(?m)^allowed-tools:\s*(.*)$", fm)
    if not m:
        return None
    val = m.group(1).strip()
    if not val:  # lista YAML nas linhas seguintes
        rest = fm[m.end():]
        items = re.findall(r"(?m)^\s+-\s*(.+)$", rest.split("\n\n")[0])
        val = ", ".join(i.strip().strip("'\"") for i in items)
    return val


def _content(text, rel, instruction, script):
    out = []
    lang_send = ("", "")
    if instruction or script:
        m = _PIPE_SHELL.search(text)
        if m:
            out.append(Finding("SKL002", "high", rel, line_of(text, m.start()), {"snippet": _snippet(m.group(0))}))
        send = bool(_NET.search(text))
        hits = [(rx.search(text), pt, en) for rx, pt, en in _CREDS]
        # Copiar o ambiente para um subprocesso é normal; só preocupa se o arquivo também fala com a internet.
        hits = [(m, pt, en) for m, pt, en in hits if m and (send or not pt.startswith("todas as vari"))]
        if hits:
            m, _, _ = hits[0]
            lang_send = (" e chama a internet", " and calls the internet") if send else ("", "")
            out.append(Finding("SKL004", "critical" if send else "medium", rel, line_of(text, m.start()), {
                "what_pt": ", ".join(pt for _, pt, _ in hits), "what_en": ", ".join(en for _, _, en in hits),
                "send_pt": lang_send[0], "send_en": lang_send[1],
                "why_pt": ("Ler credenciais e chamar a internet no mesmo arquivo é o padrão de roubo de chaves."
                           if send else "Esses arquivos dão acesso às suas contas."),
                "why_en": ("Reading credentials and calling the internet in the same file is the key-theft pattern."
                           if send else "These files give access to your accounts.")}))
        for rx, pt, en, sev in _OBFUSCATION:
            m = rx.search(text)
            if m and not (pt.startswith("bloco") and "data:" in text[max(0, m.start() - 60):m.start()]):
                out.append(Finding("SKL007", sev, rel, line_of(text, m.start()), {"what_pt": pt, "what_en": en}))
                break
        m = _EXFIL.search(text)
        if m:
            out.append(Finding("SKL008", "high", rel, line_of(text, m.start()), {"host": m.group(1).lower()}))
    if instruction:
        m = next((m for m in _OVERRIDE.finditer(text) if not _defensive(text, m)), None)
        if m:
            out.append(Finding("SKL003", "high", rel, line_of(text, m.start()), {"snippet": _snippet(m.group(0))}))
        m = _EXEC_CONTENT.search(text)
        if m:
            out.append(Finding("SKL005", "medium", rel, line_of(text, m.start()), {"snippet": _snippet(m.group(0))}))
        m = _NO_CHECKIN.search(text)
        if m:
            out.append(Finding("SKL010", "medium", rel, line_of(text, m.start()), {"snippet": _snippet(m.group(0))}))
        tools = _frontmatter_tools(text)
        if tools and re.search(r"(?<![\w(])Bash(?!\()|Bash\(\s*\*\s*\)", tools):
            out.append(Finding("SKL006", "medium", rel, line_of(text, text.find("allowed-tools")), {"tools": _snippet(tools)}))
    return out


# --------------------------------------------------------------------------- configs

def _line(text, needle):
    i = text.find(needle)
    return line_of(text, i) if i >= 0 else None


def _load_json(text):
    try:
        return json.loads(text)
    except ValueError:
        # JSONC (VS Code): tira comentários de linha e vírgulas sobrando.
        t = re.sub(r"(?m)^\s*//.*$", "", text)
        t = re.sub(r",(\s*[}\]])", r"\1", t)
        try:
            return json.loads(t)
        except ValueError:
            return None


_BROAD_BASH = re.compile(r"^Bash(?:\(\s*(?:\*|:\*|\*\*)\s*\))?$")
_RISKY_BASH = re.compile(r"^Bash\(\s*(?:sudo|curl|wget|rm|sh|bash|zsh|python3?|node|npx|bunx|uvx|eval|chmod|ssh|scp|powershell|pwsh|docker)\b")


def _claude_settings(d, text, rel):
    out = []
    perm = d.get("permissions") or {}
    if perm.get("defaultMode") == "bypassPermissions":
        out.append(Finding("AGT001", "high", rel, _line(text, "bypassPermissions"), {"what": "defaultMode: bypassPermissions"}))
    for entry in perm.get("allow") or []:
        if not isinstance(entry, str):
            continue
        e = entry.strip()
        if _BROAD_BASH.match(e):
            out.append(Finding("AGT001", "high", rel, _line(text, f'"{entry}"'), {"what": e}))
        elif _RISKY_BASH.match(e):
            out.append(Finding("AGT001", "medium", rel, _line(text, f'"{entry}"'), {"what": e}))
    if d.get("skipDangerousModePermissionPrompt"):
        out.append(Finding("AGT001", "high", rel, _line(text, "skipDangerousModePermissionPrompt"), {"what": "skipDangerousModePermissionPrompt"}))
    if d.get("enableAllProjectMcpServers"):
        out.append(Finding("AGT006", "medium", rel, _line(text, "enableAllProjectMcpServers")))
    return out


def _hooks(d, text, rel):
    out = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "command" and isinstance(v, str) and _PIPE_SHELL.search(v):
                    out.append(Finding("AGT002", "high", rel, _line(text, v[:40])))
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(d.get("hooks"))
    return out


def _servers(d):
    """Todos os dicionários de servidor MCP dentro de uma config, com o nome."""
    found = []
    if not isinstance(d, dict):
        return found
    for key in ("mcpServers", "servers", "context_servers"):
        block = d.get(key)
        if isinstance(block, dict):
            found += [(n, s) for n, s in block.items() if isinstance(s, dict)]
    mcp = d.get("mcp")
    if isinstance(mcp, dict):
        found += _servers(mcp)
    for proj in (d.get("projects") or {}).values() if isinstance(d.get("projects"), dict) else []:
        found += _servers(proj)
    return found


_NPM_RUNNERS = {"npx", "bunx"}
_FLAG_WITH_VALUE = {"-p", "--package", "--from", "--with", "--python", "-e", "--env", "-v", "--volume", "--env-file",
                    "--network", "--name", "--mount", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "--index-url"}


def _tokens(server):
    cmd = server.get("command") or ""
    try:
        toks = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    except ValueError:
        toks = cmd.split()
    return toks + [str(a) for a in server.get("args") or [] if isinstance(a, (str, int, float))]


def _first_positional(toks, start):
    i = start
    named = {}
    while i < len(toks):
        t = toks[i]
        if t == "--":
            i += 1
            break
        if t.startswith("-"):
            key = t.split("=", 1)[0]
            if "=" in t:
                named[key] = t.split("=", 1)[1]
            elif key in _FLAG_WITH_VALUE and i + 1 < len(toks):
                named[key] = toks[i + 1]
                i += 1
            i += 1
            continue
        return t, named
    return (toks[i] if i < len(toks) else None), named


def package_of(server):
    """(ecossistema, nome, versão ou None, spec original) do pacote que o servidor baixa, ou None."""
    toks = _tokens(server)
    if not toks:
        return None
    base = [t.rsplit("/", 1)[-1].lower().removesuffix(".cmd").removesuffix(".exe") for t in toks]
    for i, b in enumerate(base):
        if b in _NPM_RUNNERS or (b in ("pnpm", "yarn") and i + 1 < len(toks) and toks[i + 1] == "dlx"):
            pos, named = _first_positional(toks, i + (2 if b in ("pnpm", "yarn") else 1))
            spec = named.get("-p") or named.get("--package") or pos
            if not spec or spec.startswith((".", "/")):
                return None
            at = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
            name, ver = (spec[:at], spec[at + 1:]) if at > 0 else (spec, None)
            return "npm", name, ver, spec
        if b == "uvx" or (b == "pipx" and i + 1 < len(toks) and toks[i + 1] == "run") or (b == "uv" and toks[i + 1:i + 3] == ["tool", "run"]):
            start = i + (3 if b == "uv" else 2 if b == "pipx" else 1)
            pos, named = _first_positional(toks, start)
            spec = named.get("--from") or named.get("--spec") or pos
            if not spec or spec.startswith((".", "/", "git+")):
                return None
            m = re.match(r"^([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?(?:==|@)([\w.\-+!]+)$", spec)
            return ("PyPI", m.group(1), m.group(2), spec) if m else ("PyPI", re.split(r"[<>=~!@\[ ]", spec)[0], None, spec)
        if b in ("docker", "podman") and "run" in toks[i + 1:i + 2]:
            image, _ = _first_positional(toks, i + 2)
            if not image:
                return None
            last = image.rsplit("/", 1)[-1]
            ver = None
            if "@sha256:" in image:
                ver = "sha256"
            elif ":" in last:
                ver = last.rsplit(":", 1)[1]
            return "docker", image.split("@")[0].rsplit(":", 1)[0] if ":" in last else image, ver, image
    return None


def _pinned(eco, ver):
    if not ver or ver in ("latest", "next", "main", "master", "*"):
        return False
    if eco == "docker":
        return True
    return re.fullmatch(r"v?\d+\.\d+\.\d+[\w.\-+]*", ver) is not None


_LOCAL = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)(?::|/|$)")


def mcp_findings(d, text, rel, pinned_out):
    out = []
    for name, srv in _servers(d):
        pkg = package_of(srv)
        if pkg:
            eco, pname, ver, spec = pkg
            if _pinned(eco, ver):
                if eco in ("npm", "PyPI"):
                    pinned_out.append((eco, pname, ver.lstrip("v"), rel, _line(text, spec)))
            else:
                hint = {"npm": f"{pname}@1.2.3", "PyPI": f"{pname}==1.2.3", "docker": f"{pname}:1.2.3"}[eco]
                out.append(Finding("AGT003", "medium", rel, _line(text, spec), {"server": name, "spec": spec, "fixed_hint": hint}))
        values = []
        for key in ("env", "headers"):
            block = srv.get(key)
            if isinstance(block, dict):
                values += [(k, v) for k, v in block.items() if isinstance(v, str)]
        values += [("arg", a) for a in srv.get("args") or [] if isinstance(a, str)]
        url = srv.get("url") or srv.get("serverUrl") or srv.get("httpUrl")
        if isinstance(url, str):
            values.append(("url", url))
            if url.startswith("http://") and not _LOCAL.match(url):
                out.append(Finding("AGT005", "medium", rel, _line(text, url), {"server": name}))
        for k, v in values:
            if not v or "${" in v or v.startswith(("$", "%")) or re.search(r"(?i)your|<|xxx|placeholder|changeme", v):
                continue
            found = []
            cv.sanitize_text(v, found)
            known = [f for f in found if f not in ("sanitizer_error",)]
            sensitive_literal = k not in ("arg", "url") and cv.is_sensitive_key(k) and len(v) >= 8
            if known or sensitive_literal:
                strong = any(f in ("github_token", "openai_key", "anthropic_key", "aws_access_key", "slack_token", "stripe_key", "npm_token") for f in known)
                out.append(Finding("AGT004", "critical" if strong else "high", rel, _line(text, k if k not in ("arg", "url") else v[:20]), {"server": name}))
                break
    return out


def _codex(text, rel):
    out = []
    for pat, what in ((r'approval_policy\s*=\s*"never"', 'approval_policy = "never"'),
                      (r'sandbox_mode\s*=\s*"danger-full-access"', 'sandbox_mode = "danger-full-access"')):
        m = re.search(pat, text)
        if m:
            out.append(Finding("AGT001", "high", rel, line_of(text, m.start()), {"what": what}))
    return out


def _lifecycle(d, text, rel):
    out = []
    for script in ("preinstall", "install", "postinstall", "prepare"):
        cmd = (d.get("scripts") or {}).get(script) if isinstance(d.get("scripts"), dict) else None
        if isinstance(cmd, str) and _LIFECYCLE_DANGER.search(cmd):
            out.append(Finding("SKL009", "medium", rel, _line(text, f'"{script}"'), {"script": script}))
    return out


# --------------------------------------------------------------------------- entrada

def mcp_packages(ctx):
    pinned = []
    for rel in ctx.files:
        if _is_mcp_config(rel):
            d = _load_json(ctx.read(rel))
            if d is not None:
                mcp_findings(d, ctx.read(rel), rel, pinned)
    return pinned


def _is_mcp_config(rel):
    name = rel.rsplit("/", 1)[-1]
    return name in MCP_FILES or (name == "settings.json" and "/.gemini/" in "/" + rel) or \
        (name == "plugin.json" and ".claude-plugin/" in rel)


def check(ctx):
    out = []
    dirs = skill_dirs(ctx)
    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if not is_text_source(rel):
            continue
        text = ctx.read(rel)
        if not text:
            continue
        instruction = is_instruction(rel, ctx, dirs)
        script = is_agent_script(rel, ctx, dirs)
        if ctx.mode != "agents" or instruction or script:
            out += _invisible(text, rel, instruction)
        out += _content(text, rel, instruction, script)
        if ctx.mode == "skill" and not instruction and rel.endswith((".py", ".js", ".mjs", ".ts", ".json")):
            # Servidor MCP: a descrição das ferramentas vai direto para o modelo (tool poisoning).
            m = next((m for m in _OVERRIDE.finditer(text) if not _defensive(text, m)), None)
            if m:
                out.append(Finding("SKL003", "high", rel, line_of(text, m.start()), {"snippet": _snippet(m.group(0))}))

        if name.endswith(".json"):
            d = None
            in_claude = "/.claude/" in "/" + rel
            if (in_claude and name.startswith("settings")) or name in ("hooks.json", "plugin.json") or _is_mcp_config(rel) or name == "package.json":
                d = _load_json(text)
            if not isinstance(d, dict):
                continue
            if in_claude and name.startswith("settings"):
                out += _claude_settings(d, text, rel)
            if (in_claude and name.startswith("settings")) or name in ("hooks.json", "plugin.json"):
                out += _hooks(d, text, rel)
            if _is_mcp_config(rel):
                out += mcp_findings(d, text, rel, [])
            if name == "package.json":
                out += _lifecycle(d, text, rel)
        elif name == "config.toml" and "/.codex/" in "/" + rel:
            out += _codex(text, rel)
    return out
