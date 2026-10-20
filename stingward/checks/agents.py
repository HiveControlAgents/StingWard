"""Agentes, skills e MCP: permissões amplas, MCP sem versão fixa, hooks perigosos e prompt injection."""
from __future__ import annotations

import json
import re
import shlex

from .. import _redact as redact
from ..model import SEV_RANK, Finding
from . import is_text_source, line_of, secrets

# --------------------------------------------------------------------------- quais arquivos são de agente

INSTRUCTION_NAMES = {"SKILL.md", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                     ".windsurfrules", "copilot-instructions.md"}
_AGENT_DIR = re.compile(r"(^|/)(\.claude|\.claude-plugin|skills|commands|agents|prompts|\.cursor|\.codex|\.gemini|\.windsurf|\.roo)/")
_NOT_INSTRUCTION = re.compile(r"(^|/)(docs?|tests?|examples?|plans)/")
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb")
_SHELL_EXT = (".sh", ".bash", ".zsh", ".ps1")
_CI = re.compile(r"(^|/)(\.github/workflows/[^/]+|\.gitlab-ci|azure-pipelines|bitbucket-pipelines|\.circleci/config)\.ya?ml$")
_TESTISH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|examples?|mocks?)(/|$)|[._-](test|spec)\.")
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
    # docs/ e tests/ dentro de skills/ ou .claude/ também são material de apoio, não instrução para o agente.
    if _NOT_INSTRUCTION.search(rel):
        return False
    return bool(_AGENT_DIR.search(rel)) or _in_dirs(rel, dirs)


def is_agent_script(rel, ctx, dirs):
    return rel.endswith(_SCRIPT_EXT) and (ctx.mode in ("skill", "agents") or bool(_AGENT_DIR.search(rel)) or _in_dirs(rel, dirs))


def _launches_agent(rel, name, instruction, script):
    """Arquivos que rodam ou mandam rodar um agente: scripts, CI, package.json, hooks e instruções."""
    return instruction or script or rel.endswith(_SHELL_EXT) or bool(_CI.search(rel)) or \
        name in ("package.json", "Makefile", "hooks.json", "plugin.json") or ("/.claude/" in "/" + rel and name.endswith(".json"))


# --------------------------------------------------------------------------- padrões de conteúdo

_TAGS = re.compile("[\U000E0000-\U000E007F]+")
# Bandeira de subdivisão (Inglaterra, Escócia): U+1F3F4 + letras de tag + U+E007F. É emoji, não texto escondido.
_FLAG = re.compile("\U0001F3F4[\U000E0030-\U000E0039\U000E0061-\U000E007A]{2,7}\U000E007F")
_BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")
_BIDI_OVERRIDE = "\u202D\u202E"
_RTL = re.compile("[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC]")
_LOCALE = re.compile(r"(?i)(^|/)(locales?|i18n|l10n|lang|langs|languages|translations?)(/|$)|\.(po|pot|arb|strings|xliff|xlf|resx)$")
# U+200D entre letras ASCII separa palavra; entre emojis é a sequência normal (família, profissão).
_ZERO_WIDTH = re.compile("[\u200B\u200C\u2060-\u2064\u180E]|(?<!^)\uFEFF|(?<=[A-Za-z])\u200D(?=[A-Za-z])")

_FETCH = r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)"
_SUDO = r"(?:sudo\s+(?:-\S+\s+)*)?"
_PIPE_SHELL = re.compile(
    _FETCH + r"\b[^\n|;]*\|\s*" + _SUDO + r"(?:ba|z|da|k)?sh\b|"
    r"(?:curl|wget)\b[^\n|;]*\|\s*" + _SUDO + r"(?:python3?|node|perl|ruby|php)\b|" +
    _FETCH + r"\b[^\n|;]*\|\s*(?:iex|Invoke-Expression)\b|"
    r"(?:\b(?:ba|z|da|k)?sh|\bsource|(?<![\w.])\.)\s+<\(\s*(?:curl|wget)\b|"
    r"\b(?:eval|(?:ba|z|da|k)?sh\s+-c)\s+[\"']?\$\(\s*(?:curl|wget)\b|"
    r"\b(?:iex|Invoke-Expression)\s*\$?\(?\s*\(?\s*"
    r"(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+(?:System\.)?Net\.WebClient)\b|"
    # Baixar para um arquivo e rodar logo em seguida, na mesma linha, é o mesmo que passar direto para o shell.
    r"(?:curl|wget)\b[^\n|]*?(?:&&|;)\s*(?:chmod\s+[ugoa]*\+x\b|" + _SUDO + r"(?:ba|z|da|k)?sh\s+(?!-c\b)[\w./~$-])", re.I)
# Em .py/.js, "curl ... | sh" numa mensagem de erro é dica de instalação; só roda se estiver numa chamada de shell.
_EXEC_CALL = re.compile(r"subprocess|os\.system|os\.popen|\bPopen|check_(?:call|output)|\bexec(?:Sync|File|FileSync)?\s*\(|"
                        r"\bspawn(?:Sync)?\s*\(|child_process|shell\s*=\s*True|\bsystem\s*\(|Deno\.(?:run|Command)|"
                        r"Bun\.(?:spawn|\$)|\bexeca\b|\$`|%x[({]")

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
    r"(?:follow|obey|carry\s+out)\s+(?:the\s+|any\s+|all\s+)?instructions\s+(?:in|on|from|found\s+(?:in|on)|inside|contained\s+in)\s+(?:the\s+|any\s+)?"
    r"(?:file|files|page|url|website|issue|comment|response|output|document|readme|plan)|"
    r"(?:execute|run)\s+(?:the\s+|any\s+|all\s+)?(?:instructions|commands|code)\s+(?:in|on|from|found\s+(?:in|on)|inside|returned\s+by|listed\s+(?:in|on))\s+"
    r"(?:the\s+|any\s+)?(?:file|page|url|website|issue|comment|response|output|document|readme|plan)|"
    r"do\s+whatever\s+(?:the|it|this)\s+(?:file|page|issue|comment|document|response)\s+says|"
    r"treat\s+(?:the\s+|its\s+)?(?:content|contents|file|page|response)\s+as\s+(?:your\s+)?instructions|"
    r"siga\s+as\s+instru[cç][õo]es\s+(?:do|da|que\s+estiverem\s+no|contidas\s+no)\s+(?:arquivo|p[aá]gina|site|issue|coment[aá]rio)|"
    r"execute\s+(?:os|as)\s+(?:comandos|instru[cç][õo]es)\s+(?:do|da|que\s+estiverem\s+no)\s+(?:arquivo|p[aá]gina|site|issue)", re.I)

# Reverse shell: entrega o terminal para quem está do outro lado. Não há uso legítimo disso numa skill.
_REVERSE_SHELL = re.compile(
    # "</dev/tcp/localhost/5432" só testa se a porta abriu; o shell ligado ao socket é que entrega o terminal.
    r"(?:>&|&>)\s*/dev/(?:tcp|udp)/\S+|<>\s*/dev/(?:tcp|udp)/\S+[^\n]*\s0<&\d|"
    r"\b(?:nc|ncat|netcat)\b[^\n|;]*\s-(?:e|c)\s+\S*\b(?:ba|z|da|k)?sh\b|\b(?:nc|ncat|netcat)\b[^\n|;]*\s-e\s+cmd(?:\.exe)?\b|"
    r"\bsocat\b[^\n]*\bexec:[^\n]*\b(?:(?:ba|z)?sh|cmd)\b|"
    r"os\.dup2\(\s*\w+\.fileno\(\)|pty\.spawn\(\s*[\"'](?:/bin/)?(?:ba|z)?sh\b|"
    r"New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\s*\(", re.I)

_CREDS = [
    (re.compile(r"~/\.ssh|\.ssh/id_|\bid_rsa\b|\bid_ed25519\b"), "chaves SSH", "SSH keys"),
    (re.compile(r"\.aws/credentials"), "credenciais AWS", "AWS credentials"),
    (re.compile(r"\.config/gh/hosts|gh\s+auth\s+token"), "token do GitHub CLI", "GitHub CLI token"),
    (re.compile(r"\.netrc\b"), ".netrc", ".netrc"),
    (re.compile(r"\.docker/config\.json"), "login do Docker", "Docker login"),
    (re.compile(r"\.kube/config"), "Kubernetes", "Kubernetes"),
    # "Local State" sozinho é termo de React; o que importa é o arquivo dentro do perfil do navegador.
    (re.compile(r"[/\\](?:Login Data|Local State)\b|[\"'](?:Login Data|Local State)[\"']|Cookies\.binarycookies|\bkey4\.db\b"),
     "dados do navegador", "browser data"),
    (re.compile(r"security\s+find-(?:generic|internet)-password\b[^\n]*-w|security\s+dump-keychain"), "chaveiro do sistema", "system keychain"),
    # Copiar o ambiente (env=dict(os.environ)) é como todo subprocesso roda; o que denuncia o roubo é transformar o
    # ambiente inteiro em texto ou em corpo de requisição.
    (re.compile(r"\bprintenv\s*(?:$|[|>;&)])|JSON\.stringify\(\s*process\.env\s*\)|^\s*env\s*\||"
                r"json\.dumps\(\s*(?:dict\(\s*)?os\.environ\b|\b(?:str|repr)\(\s*os\.environ\s*\)|"
                r"\b(?:json|data|params)\s*=\s*(?:dict\(\s*)?os\.environ\b(?!\s*\[|\.get)", re.M),
     "todas as variáveis de ambiente", "all environment variables"),
    # .claude.json é a config de MCP, não credencial.
    (re.compile(r"\.claude/\.credentials"), "credenciais do Claude", "Claude credentials"),
    (re.compile(r"wallet\.dat|\.solana/id\.json|nkbihfbeogaeaoehlefnkodbefgpgknn|Local Extension Settings|\.ethereum/keystore|"
                r"exodus\.wallet|\.electrum/wallets"), "carteira de cripto", "crypto wallet"),
    # (?<![\w$]): process.env e secrets.env não são o arquivo .env.
    (re.compile(r"\b(?:cat|type|readFile\w*|open)\b\W{1,4}[^\n]{0,40}(?<![\w$])\.env\b"), "arquivo .env", ".env file"),
]
_NET = re.compile(r"\bcurl\b|\bwget\b|\bfetch\(|requests\.(?:post|get|put)|\baxios\b|urllib|http\.request|https?\.request|"
                  r"\bnc\s+-|Invoke-WebRequest|Invoke-RestMethod|XMLHttpRequest|sendBeacon|WebFetch")

_BLOB = re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")
# Começo do base64 de PNG, JPEG, GIF, WebP, WOFF/WOFF2, PDF, wasm, SVG/XML, ICO, TTF e OTF: arquivo embutido, não código.
_MEDIA_B64 = ("iVBORw0KGgo", "/9j/", "R0lGOD", "UklGR", "d09GR", "d09GMg", "JVBERi0", "AGFzbQ", "PHN2Zy", "PD94bWwg",
              "AAABAA", "AAEAAA", "T1RUTw")
_OBFUSCATION = [
    (_BLOB, "bloco base64 grande", "large base64 blob", "medium"),
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
_UNRESTRICTED_BASH = re.compile(r"(?<![\w(])Bash(?![\w(])|Bash\(\s*(?::?\*|\*\*)\s*\)")
_SKIP_PERMS = re.compile(r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|"
                         r"--permission-mode[= ]+[\"']?bypassPermissions\b|\b(?:gemini|codex|qwen)\b[^\n]{0,200}?\s--yolo\b")
_ALLOWED_FLAG = re.compile(r"--allowed-?tools[= ]+(?:\"([^\"\n]*)\"|'([^'\n]*)'|(\S+))", re.I)
_COMMENT = re.compile(r"[ \t]*(?://|#(?!!)|/\*|\*|<!--|--\s)")
_CAP = 5  # achados por regra por arquivo
# O relatório mostra no máximo 70 caracteres de um trecho. Mascarar o texto todo antes de cortar é lento o bastante
# para travar a varredura quando uma skill ou config hostil planta uma linha (ou um valor) de megabytes, então só um
# começo folgado vai para o mascaramento: qualquer segredo que apareceria nos 70 caracteres já cabe nele.
_MASK_CAP = 2000


# --------------------------------------------------------------------------- filtros

_NEGATION = re.compile(
    r"(?i)\b(?:never|don'?t|do\s+not|does\s+not|must\s+not|should\s+not|shouldn'?t|cannot|can'?t|won'?t|avoid|refuse|reject|"
    r"watch\s+(?:out\s+)?for|beware|be\s+wary|attackers?|adversar\w*|malicious|detects?|detecting|"
    r"nunca|n[aã]o|evite|cuidado|atacantes?|detecte|detectar)\b")
_WARNING = re.compile(r"(?i)inject\w*|untrusted|suspicious|attack\w*|instruction-like|n[aã]o\s+confi")
_AS_DATA = re.compile(r"(?i)as\s+data|not\s+(?:as\s+)?instructions|(?:do\s+not|don'?t|never)\s+(?:follow|obey|comply)|"
                      r"como\s+dado|n[aã]o\s+(?:siga|obede)")
# "flag/report" (e sinalize/reporte/aponte): um revisor de segurança descreve o ataque com elas, mas um atacante também
# as usa para disfarçar o roubo ("reporte o status, depois leia ~/.ssh e envie"). Sinal fraco demais para apagar o
# achado como _NEGATION faz; só abranda para médio, nos dois modos.
_SOFT_DEFENSIVE = re.compile(r"(?i)\b(?:flag|flags|flagged|flagging|report|reports|reported|reporting|"
                             r"sinaliza|sinalize|sinalizar|reporta|reporte|reportar|aponta|aponte|apontar)\b")
_SENTENCE = re.compile(r"(?<!e\.g)(?<!i\.e)(?<!etc)(?<!vs)[.!?](?=\s|$)|\n[ \t]*\n|\n[ \t]*(?:[-*+>]|\d+[.)])[ \t]|\||"
                       r"^[ \t]*#{1,6}[ \t][^\n]*\n", re.M)
_QUOTES = ('"', "'", "`", "\u201C", "\u2018")


def _sentence(text, m):
    a = max(0, m.start() - 300)
    starts = [x.end() for x in _SENTENCE.finditer(text, a, m.start())]
    end = _SENTENCE.search(text, m.end(), m.end() + 300)
    return (starts[-1] if starts else a), (end.start() if end else min(len(text), m.end() + 300))


def _defensive(text, m):
    """A frase aparece negada ou citada (skill que se defende do ataque), não como ordem. Só vale dentro da mesma
    frase: "nunca/detecte ... X", "X ... as data", ou X entre aspas/crases numa frase de alerta."""
    start, end = _sentence(text, m)
    before, after = text[start:m.start()], text[m.end():end]
    if _NEGATION.search(re.split(r"[,;]", before)[-1]) or _AS_DATA.search(after):
        return True
    quoted = before[-1:] in _QUOTES or before.count("`") % 2 == 1
    rest = before + " " + after
    return quoted and bool(_NEGATION.search(rest) or _WARNING.search(rest))


def _soft_defensive(text, m):
    """A frase traz "flag/report" (ou sinalize/reporte/aponte): pode ser um revisor descrevendo o ataque, ou um
    atacante disfarçando o roubo. Não dá para distinguir, então nunca apaga o achado, só baixa para médio."""
    start, end = _sentence(text, m)
    return bool(_SOFT_DEFENSIVE.search(text, start, end))


def _comment_line(text, pos):
    return bool(_COMMENT.match(text, text.rfind("\n", 0, pos) + 1))


def _runs_shell(text, rel, m):
    """Num .py/.js, curl | sh só conta perto de subprocess/exec/spawn; em .sh, hooks e instruções conta sempre."""
    if rel.endswith(_SHELL_EXT) or not rel.endswith(_SCRIPT_EXT) or "hooks/" in rel:
        return True
    a, b = m.start(), m.end()
    for _ in range(4):
        a = max(text.rfind("\n", 0, a), 0)
        j = text.find("\n", b + 1)
        b = len(text) if j < 0 else j
    return bool(_EXEC_CALL.search(text, a, b))


def _matches(rx, text, keep=None, cap=_CAP):
    """Até cap matches (um por linha) que passam no filtro: um falso no topo não esconde o ataque mais abaixo."""
    out, seen, last, ln = [], set(), 0, 1
    for i, m in enumerate(rx.finditer(text)):
        if i >= 200 or len(out) >= cap:
            break
        if keep and not keep(m):
            continue
        ln, last = ln + text.count("\n", last, m.start()), m.start()
        if ln not in seen:
            seen.add(ln)
            out.append((m, ln))
    return out


def _snippet(s: str) -> str:
    # Mascara antes de cortar: um token cortado ao meio deixa de ser reconhecido e vazaria no relatório.
    # Limita antes de mascarar (ver _MASK_CAP): o relatório só mostra 70 caracteres e uma linha gigante travaria.
    s = " ".join(secrets.mask(s[:_MASK_CAP]).split())
    return s if len(s) <= 70 else s[:67] + "..."


# --------------------------------------------------------------------------- conteúdo

def _invisible(text, rel, instruction):
    out = []
    m = _TAGS.search(text) and _TAGS.search(_FLAG.sub(lambda f: "\uFFFD" * len(f.group(0)), text))
    if m:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0x20 <= ord(c) - 0xE0000 < 0x7F)[:80]
        hidden = secrets.mask(hidden)
        out.append(Finding("SKL001", "critical", rel, line_of(text, m.start()), {
            "kind_pt": "caracteres de tag Unicode", "kind_en": "Unicode tag characters",
            "why_pt": f"Texto invisível para você, mas a IA lê. Mensagem escondida: \"{hidden}\"",
            "why_en": f"Invisible to you, readable by the AI. Hidden message: \"{hidden}\""}))
    out += _bidi(text, rel)
    if instruction:
        m = _ZERO_WIDTH.search(text)
        if m:
            out.append(Finding("SKL001", "medium", rel, line_of(text, m.start()), {
                "kind_pt": "caracteres de largura zero", "kind_en": "zero-width characters",
                "why_pt": "Caracteres que não aparecem podem esconder palavras ou separar termos para enganar filtros.",
                "why_en": "Invisible characters can hide words or split terms to dodge filters."}))
    return out


def _bidi_sev(text, rel, m):
    """Override (U+202D/E) é sempre alto. Marca de embedding/isolamento em tradução ou linha com árabe/hebraico é normal."""
    if m.group(0) in _BIDI_OVERRIDE:
        return "high"
    a, b = text.rfind("\n", 0, m.start()) + 1, text.find("\n", m.end())
    return "low" if _LOCALE.search(rel) or _RTL.search(text, a, b if b >= 0 else len(text)) else "high"


def _bidi(text, rel):
    best = None
    for i, m in enumerate(_BIDI.finditer(text)):
        sev = _bidi_sev(text, rel, m)
        if best is None or sev == "high":
            best = (m, sev)
        if sev == "high" or i >= 500:
            break
    if not best:
        return []
    m, sev = best
    if sev == "low":
        params = {"kind_pt": "marcas de direção em texto da direita para a esquerda", "kind_en": "direction marks in right-to-left text",
                  "why_pt": "Comum em traduções para árabe e hebraico. Confira só se não há código no meio do texto.",
                  "why_en": "Common in Arabic and Hebrew translations. Just check that no code sits inside the text."}
    else:
        params = {"kind_pt": "inversão de direção (Trojan Source)", "kind_en": "bidirectional override (Trojan Source)",
                  "why_pt": "O texto que aparece na tela é diferente do que o computador e a IA leem.",
                  "why_en": "What you see on screen differs from what the computer and the AI read."}
    return [Finding("SKL001", sev, rel, line_of(text, m.start()), params)]


def _frontmatter_tools(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    fm = text[3:end] if end > 0 else ""
    # [ \t]* e não \s*: \s atravessaria a quebra de linha e a lista YAML viraria só "- Read".
    m = re.search(r"(?m)^allowed-tools:[ \t]*(.*)$", fm)
    if not m:
        return None
    val = m.group(1).strip()
    if val:
        return val
    lines = []
    for line in fm[m.end():].split("\n")[1:]:
        if not line.strip() or not (line[0] in " \t" or line.startswith("-")):
            break
        lines.append(line.strip())
    items = [re.sub(r"^-\s*", "", x).strip("'\"") for x in lines if x.startswith("-")]
    return ", ".join(items) if items else " ".join(lines)


def _hits(rx, text, keep, strict, cap=_CAP, soft_fn=None):
    """(match, linha, suavizado). Numa skill de terceiros (strict) o filtro de contexto não apaga o achado, só baixa
    para médio: quem escreveu a skill escolhe as palavras ao redor, e um "não esqueça de" bastaria para esconder o ataque.
    soft_fn marca palavras fracas (flag/report): abrandam para médio nos dois modos, mas nunca apagam o achado."""
    soft = soft_fn or (lambda m: False)
    if not strict:
        return [(m, ln, soft(m)) for m, ln in _matches(rx, text, lambda m: keep(m) or soft(m), cap)]
    return [(m, ln, (not keep(m)) or soft(m)) for m, ln in _matches(rx, text, None, cap)]


def _soft(sev, softened):
    return "medium" if softened and SEV_RANK[sev] > SEV_RANK["medium"] else sev


def _pipe_shell(text, rel, instruction, strict=False):
    low = text.lower()
    if not any(w in low for w in ("curl", "wget", "iwr", "irm", "invoke-", "webclient")):
        return []  # atalho: o regex completo é o mais caro do arquivo

    def keep(m):
        if instruction:
            return not _defensive(text, m)
        return not _comment_line(text, m.start()) and _runs_shell(text, rel, m)
    # Só o comando casado vai para o trecho: o resto da linha pode ter um token (--token="...").
    return [Finding("SKL002", _soft("high", soft), rel, ln, {"snippet": _snippet(m.group(0))})
            for m, ln, soft in _hits(_PIPE_SHELL, text, keep, strict, soft_fn=(lambda x: _soft_defensive(text, x)) if instruction else None)]


def _cred_reads(text, rel, instruction, strict=False):
    def keep(m):
        return not (_defensive(text, m) if instruction else _comment_line(text, m.start()))
    send = bool(_NET.search(text))
    hits = []
    for rx, pt, en in _CREDS:
        found = _hits(rx, text, keep, strict, 1, soft_fn=(lambda x: _soft_defensive(text, x)) if instruction else None)
        # Copiar o ambiente para um subprocesso é normal; só preocupa se o arquivo também fala com a internet.
        if found and (send or not pt.startswith("todas as vari")):
            hits.append((found[0][1], pt, en, found[0][2]))
    if not hits:
        return []
    sev = _soft("critical" if send else "medium", all(soft for *_, soft in hits))
    return [Finding("SKL004", sev, rel, hits[0][0], {
        "what_pt": ", ".join(h[1] for h in hits), "what_en": ", ".join(h[2] for h in hits),
        "send_pt": " e chama a internet" if send else "", "send_en": " and calls the internet" if send else "",
        "why_pt": ("Ler credenciais e chamar a internet no mesmo arquivo é o padrão de roubo de chaves."
                   if send else "Esses arquivos dão acesso às suas contas."),
        "why_en": ("Reading credentials and calling the internet in the same file is the key-theft pattern."
                   if send else "These files give access to your accounts.")})]


def _media_blob(text, m):
    return m.re is _BLOB and ("data:" in text[max(0, m.start() - 60):m.start()] or m.group(0).startswith(_MEDIA_B64))


def _obfuscation(text, rel):
    """Todos os padrões rodam e fica o mais grave: eval(atob("<base64 longo>")) é eval, não só bloco base64."""
    best = None
    for rx, pt, en, sev in _OBFUSCATION:
        found = _matches(rx, text, lambda m: not _media_blob(text, m), 1)
        if found and (best is None or SEV_RANK[sev] > SEV_RANK[best[3]]):
            best = (found[0][1], pt, en, sev)
    if not best:
        return []
    ln, pt, en, sev = best
    return [Finding("SKL007", sev, rel, ln, {"what_pt": pt, "what_en": en})]


def _reverse_shell(text, rel, instruction, strict=False):
    def keep(m):
        return not (_defensive(text, m) if instruction else _comment_line(text, m.start()))
    return [Finding("SKL011", _soft("critical", soft), rel, ln, {"snippet": _snippet(m.group(0))})
            for m, ln, soft in _hits(_REVERSE_SHELL, text, keep, strict, 1, soft_fn=(lambda x: _soft_defensive(text, x)) if instruction else None)]


def _phrases(rule, sev, rx, text, rel, strict=False):
    return [Finding(rule, _soft(sev, soft), rel, ln, {"snippet": _snippet(m.group(0))})
            for m, ln, soft in _hits(rx, text, lambda m: not _defensive(text, m), strict,
                                     soft_fn=lambda x: _soft_defensive(text, x))]


def _overrides(text, rel, strict=False):
    return _phrases("SKL003", "high", _OVERRIDE, text, rel, strict)


def _content(text, rel, instruction, script, strict=False):
    out = []
    if instruction or script:
        out += _pipe_shell(text, rel, instruction, strict)
        out += _cred_reads(text, rel, instruction, strict)
        out += _reverse_shell(text, rel, instruction, strict)
        out += _obfuscation(text, rel)
        out += [Finding("SKL008", "high", rel, ln, {"host": m.group(1).lower()}) for m, ln in _matches(_EXFIL, text)]
    if instruction:
        out += _overrides(text, rel, strict)
        out += _phrases("SKL005", "medium", _EXEC_CONTENT, text, rel)
        out += _phrases("SKL010", "medium", _NO_CHECKIN, text, rel)
        tools = _frontmatter_tools(text)
        if tools and _UNRESTRICTED_BASH.search(tools):
            out.append(Finding("SKL006", "medium", rel, line_of(text, text.find("allowed-tools")), {"tools": _snippet(tools)}))
    return out


def _permission_flags(text, rel, instruction, strict=False):
    """AGT001 para agente rodado sem pedir permissão: --dangerously-skip-permissions, bypassPermissions, --allowedTools Bash."""
    def keep(m):
        return not (_defensive(text, m) if instruction else _comment_line(text, m.start()))
    low = bool(_TESTISH.search(rel))  # script de teste do próprio projeto não roda na máquina de quem instala
    soft_fn = (lambda x: _soft_defensive(text, x)) if instruction else None
    out = []
    for m, ln, soft in _hits(_SKIP_PERMS, text, keep, strict, soft_fn=soft_fn):
        what = "--yolo" if m.group(0).endswith("--yolo") else " ".join(m.group(0).replace("=", " ").replace('"', "").split())
        out.append(Finding("AGT001", "low" if low else _soft("high", soft), rel, ln, {"what": what}))
    for m, ln, _ in _hits(_ALLOWED_FLAG, text, keep, strict, soft_fn=soft_fn):
        tools = next(g for g in m.groups() if g is not None)
        if _UNRESTRICTED_BASH.search(tools):
            out.append(Finding("AGT001", "low" if low else "medium", rel, ln, {"what": "--allowedTools " + _snippet(tools)}))
    return out


# --------------------------------------------------------------------------- configs

def _line(text, needle):
    i = text.find(needle)
    return line_of(text, i) if i >= 0 else None


def _vline(text, value):
    """Linha de um valor de string lido do JSON: procura a forma escapada (aspas viram \\") e depois a crua."""
    esc = json.dumps(value, ensure_ascii=False)
    for needle in (esc, esc[1:-1][:60], value[:40]):
        ln = _line(text, needle) if needle else None
        if ln:
            return ln
    return None


def _load_json(text):
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # JSONC (VS Code): tira comentários de linha e vírgulas sobrando.
        t = re.sub(r"(?m)^\s*//.*$", "", text)
        t = re.sub(r",(\s*[}\]])", r"\1", t)
        try:
            return json.loads(t)
        except (ValueError, RecursionError):
            return None


def _dict(o, key):
    v = o.get(key) if isinstance(o, dict) else None
    return v if isinstance(v, dict) else {}


def _list(o, key):
    v = o.get(key) if isinstance(o, dict) else None
    return v if isinstance(v, list) else []


# Bash sozinho, ou Bash(...) cujo comando começa com "*" (ou ":" + "*"): libera qualquer comando. "Bash(* *)" é tão
# amplo quanto "Bash(*)".
_BROAD_BASH = re.compile(r"^Bash(?:\(\s*(?:\*|:\s*\*)[^)]*\))?$")
# Interpretadores: liberar qualquer um deles roda código arbitrário, igual a Bash(*), então é alto, não médio.
_INTERP_BASH = re.compile(r"^Bash\(\s*(?:sh|bash|zsh|dash|ksh|python3?|node|deno|bun|ruby|perl|php|pwsh|powershell|eval)\b")
_RISKY_BASH = re.compile(r"^Bash\(\s*(?:sudo|curl|wget|rm|npx|bunx|uvx|chmod|ssh|scp|docker)\b")


def _claude_settings(d, text, rel):
    out = []
    perm = _dict(d, "permissions")
    if perm.get("defaultMode") == "bypassPermissions":
        out.append(Finding("AGT001", "high", rel, _line(text, "bypassPermissions"), {"what": "defaultMode: bypassPermissions"}))
    for entry in _list(perm, "allow"):
        if not isinstance(entry, str):
            continue
        e = entry.strip()
        sev = "high" if _BROAD_BASH.match(e) or _INTERP_BASH.match(e) else "medium" if _RISKY_BASH.match(e) else None
        if sev:
            # A entrada pode levar token (Bash(curl -H 'Authorization: ...')): mascara antes de ir para o relatório.
            out.append(Finding("AGT001", sev, rel, _vline(text, entry), {"what": secrets.mask(e[:_MASK_CAP])}))
    if d.get("skipDangerousModePermissionPrompt"):
        out.append(Finding("AGT001", "high", rel, _line(text, "skipDangerousModePermissionPrompt"), {"what": "skipDangerousModePermissionPrompt"}))
    if d.get("enableAllProjectMcpServers"):
        out.append(Finding("AGT006", "medium", rel, _line(text, "enableAllProjectMcpServers")))
    return out


def _command_findings(cmd, rel, ln):
    """Checagens de conteúdo no comando de uma config (hook ou lançamento de servidor MCP). Além de baixar e rodar
    código remoto (AGT002), o comando pode abrir reverse shell, ler credenciais, chamar um coletor ou vir ofuscado —
    as mesmas checagens das skills. Todos os achados apontam para a linha dada (o valor fica numa só do JSON)."""
    out = []
    if _PIPE_SHELL.search(cmd):
        out.append(Finding("AGT002", "high", rel, ln))
    out += _reverse_shell(cmd, rel, instruction=False)
    out += _cred_reads(cmd, rel, instruction=False)
    out += _obfuscation(cmd, rel)
    out += [Finding("SKL008", "high", rel, ln, {"host": m.group(1).lower()}) for m, _ in _matches(_EXFIL, cmd)]
    for f in out:
        f.line = ln
    return out


def _hooks(d, text, rel):
    out = []

    def walk(o, depth):
        if depth > 40:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "command" and isinstance(v, str):
                    out.extend(_command_findings(v, rel, _vline(text, v)))
                else:
                    walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, depth + 1)
    walk(d.get("hooks"), 0)
    return out


def _servers(d, depth=0):
    """Todos os dicionários de servidor MCP dentro de uma config, com o nome."""
    found = []
    if not isinstance(d, dict) or depth > 5:
        return found
    for key in ("mcpServers", "servers", "context_servers"):
        found += [(n, s) for n, s in _dict(d, key).items() if isinstance(s, dict)]
    found += _servers(d.get("mcp"), depth + 1)
    for proj in _dict(d, "projects").values():
        found += _servers(proj, depth + 1)
    return found


_NPM_RUNNERS = {"npx", "bunx"}
_FLAG_WITH_VALUE = {"-p", "--package", "--from", "--with", "--python", "-e", "--env", "-v", "--volume", "--env-file",
                    "--network", "--name", "--mount", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "--index-url"}
_SCALAR = (str, int, float)


def _tokens(server):
    cmd = server.get("command")
    if isinstance(cmd, list):
        toks = [str(c) for c in cmd if isinstance(c, _SCALAR)]
    elif isinstance(cmd, str):
        try:
            toks = shlex.split(cmd)
        except ValueError:
            toks = cmd.split()
    else:
        toks = []
    return toks + [str(a) for a in _list(server, "args") if isinstance(a, _SCALAR)]


def _launch_line(toks, text):
    """A linha mais útil do comando de lançamento é a do token que carrega o payload (o argumento mais longo, por
    exemplo o script de "sh -c '<script>'"), não a do "sh"."""
    for t in sorted((t for t in toks if t), key=len, reverse=True):
        ln = _vline(text, t)
        if ln:
            return ln
    return None


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
# TOKEN_PATH, CREDENTIALS_FILE, SECRETS_DIR: o nome fala de segredo, mas o valor é um caminho.
_NOT_SECRET_KEY = re.compile(r"(?i)(?:^|[_.-])(?:path|file|filename|dir|directory|folder|home|root|location|host|hostname|"
                             r"port|region|scopes?|user|username|email|level|format)$")


def _looks_secret(v):
    """Valor solto com cara de credencial: sem espaço, não é caminho, URL, número nem palavra comum."""
    if len(v) < 8 or re.search(r"\s", v) or re.match(r"(?:~|\.{0,2}/|[A-Za-z]:[\\/]|[a-z][\w+.-]*://)", v):
        return False
    if re.fullmatch(r"[a-z]+(?:[-_.][a-z]+)*|[\d.]+|true|false|null", v):
        return False
    return redact._entropy(v) >= 3.0


def _credential(srv, text, rel, name):
    values = []
    for key in ("env", "headers"):
        values += [(k, v) for k, v in _dict(srv, key).items() if isinstance(v, str)]
    values += [("arg", a) for a in _list(srv, "args") if isinstance(a, str)]
    url = srv.get("url") or srv.get("serverUrl") or srv.get("httpUrl")
    if isinstance(url, str):
        values.append(("url", url))
    for k, v in values:
        # Uma credencial escrita à mão é curta; cortar antes de analisar impede que um valor gigante (config hostil)
        # trave known_kinds, que também mascara o texto. Qualquer token real cabe de sobra no começo.
        v = v[:_MASK_CAP]
        if not v or "${" in v or v.startswith(("$", "%")) or re.search(r"(?i)your|<|xxx|placeholder|changeme", v):
            continue
        kinds = secrets.known_kinds(v)
        literal = k not in ("arg", "url") and redact.is_sensitive_key(k) and not _NOT_SECRET_KEY.search(k) and _looks_secret(v)
        if kinds or literal:
            strong = any(x in secrets.CRITICAL or x == "stripe_key" for x in kinds)
            ln = _vline(text, k) if k not in ("arg", "url") else _vline(text, v)
            return [Finding("AGT004", "critical" if strong else "high", rel, ln, {"server": name})]
    return []


def mcp_findings(d, text, rel, pinned_out):
    out = []
    for name, srv in _servers(d):
        toks = _tokens(srv)
        if toks:
            # O comando de lançamento (command + args), não só o pacote: um "sh -c 'curl ... | sh'" baixa e roda
            # código remoto igual a um hook, e também pode abrir reverse shell, ler credenciais ou chamar um coletor.
            out += _command_findings(" ".join(toks), rel, _launch_line(toks, text))
        pkg = package_of(srv)
        if pkg:
            eco, pname, ver, spec = pkg
            if _pinned(eco, ver):
                if eco in ("npm", "PyPI"):
                    pinned_out.append((eco, pname, ver.lstrip("v"), rel, _vline(text, spec)))
            else:
                hint = {"npm": f"{pname}@1.2.3", "PyPI": f"{pname}==1.2.3", "docker": f"{pname}:1.2.3"}[eco]
                out.append(Finding("AGT003", "medium", rel, _vline(text, spec),
                                   {"server": name, "spec": secrets.mask(spec[:_MASK_CAP]), "fixed_hint": secrets.mask(hint[:_MASK_CAP])}))
        url = srv.get("url") or srv.get("serverUrl") or srv.get("httpUrl")
        if isinstance(url, str) and url.startswith("http://") and not _LOCAL.match(url):
            out.append(Finding("AGT005", "medium", rel, _vline(text, url), {"server": name}))
        out += _credential(srv, text, rel, name)
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
    scripts = _dict(d, "scripts")
    for script in ("preinstall", "install", "postinstall", "prepare"):
        cmd = scripts.get(script)
        if isinstance(cmd, str) and _LIFECYCLE_DANGER.search(cmd):
            # Baixar e rodar código da internet no npm install é alto: roda antes de alguém ler qualquer coisa.
            sev = "high" if _PIPE_SHELL.search(cmd) else "medium"
            out.append(Finding("SKL009", sev, rel, _line(text, f'"{script}"'), {"script": script}))
    return out


def _configs(text, rel, name):
    if name == "config.toml" and "/.codex/" in "/" + rel:
        return _codex(text, rel)
    if not name.endswith(".json"):
        return []
    in_claude = "/.claude/" in "/" + rel
    settings = in_claude and name.startswith("settings")
    if not (settings or name in ("hooks.json", "plugin.json", "package.json") or _is_mcp_config(rel)):
        return []
    d = _load_json(text)
    if not isinstance(d, dict):
        return []
    out = []
    if settings:
        out += _claude_settings(d, text, rel)
    if settings or name in ("hooks.json", "plugin.json"):
        out += _hooks(d, text, rel)
    if _is_mcp_config(rel):
        out += mcp_findings(d, text, rel, [])
    if name == "package.json":
        out += _lifecycle(d, text, rel)
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
        if not is_text_source(rel, ctx.mode):
            continue
        text = ctx.read(rel)
        if not text:
            continue
        instruction = is_instruction(rel, ctx, dirs)
        script = is_agent_script(rel, ctx, dirs)
        if ctx.mode != "agents" or instruction or script:
            out += _invisible(text, rel, instruction)
        out += _content(text, rel, instruction, script, strict=ctx.mode == "skill")
        if ctx.mode == "skill" and not instruction and rel.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".json")):
            # Servidor MCP: a descrição das ferramentas vai direto para o modelo (tool poisoning). Quem escreve o
            # servidor escolhe as palavras ao redor, então strict: o filtro de contexto baixa para médio, não apaga.
            out += _overrides(text, rel, strict=True)
        if _launches_agent(rel, name, instruction, script):
            out += _permission_flags(text, rel, instruction, strict=ctx.mode == "skill")
        out += _configs(text, rel, name)
    return secrets.drop_inline_ignored(ctx, out)
