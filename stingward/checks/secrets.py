"""Segredos no código e arquivos .env no git. Usa os padrões do motor de mascaramento (_redact)."""
from __future__ import annotations

import base64
import fnmatch
import itertools
import json
import re

from .. import _redact as redact, gitsafe
from ..model import Finding
from . import is_text_source

# Os padrões do _redact aceitam rabo curto de propósito (pegam token truncado em log). Aqui o formato
# precisa ser o real, senão npm_registry, "xoxp-new-..." e "sk-ant-admin..." viram segredo.
TOKEN_PATTERNS = [
    ("private_key", redact._TOKEN_PATTERNS[0][1]),
    ("jwt", re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-\d{6,}-[A-Za-z0-9-]{8,}|\bxoxe\.xox[bp]-\d-[A-Za-z0-9-]{40,}|"
                               r"\bxapp-\d-[A-Z0-9]{8,}-\d{6,}-[a-f0-9]{32,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[a-z]{2,6}\d{2}-[A-Za-z0-9_-]{20,}")),
    ("openrouter_key", re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b")),
    ("openai_key", re.compile(r"\bsk-(?!ant-|or-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("stripe_webhook", re.compile(r"\bwhsec_[A-Za-z0-9]{32,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("meta_token", re.compile(r"\bEAA[A-Za-z0-9]{20,}")),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{52}\b")),
    ("supabase_secret", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")),
    ("supabase_pat", re.compile(r"\bsbp_[a-f0-9]{40}\b")),
    ("xai_key", re.compile(r"\bxai-[A-Za-z0-9]{80}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("digitalocean_token", re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b")),
]
# Filtro rápido: linha sem nenhum desses prefixos não tem token de formato conhecido.
_HINT = re.compile(r"-----BEGIN|eyJ|AKIA|ASIA|ABIA|ACCA|gh[pousr]_|github_pat_|xox|xapp-|sk-|[rs]k_|whsec_|AIza|EAA|SK[0-9a-fA-F]|"
                   r"npm_|glpat-|hf_|gsk_|sb_secret_|sbp_|xai-|SG\.|pypi-|do[opr]_v1_")
# Token aleatório de verdade tem dígito e maiúscula/minúscula; nome de variável e exemplo de doc, não.
_MIXED = {"openai_key", "meta_token", "npm_token", "huggingface_token"}
# Exemplo de documentação: "sk-ant-oat01-...", "ghp_abc***", "xoxb-<token>", "AKIA1234xxxx".
_TRUNCATED = re.compile(r"\.\.\.|\u2026|\*|<(?!/)|[xX]{4}")

# Formatos que identificam o serviço com certeza: severidade crítica.
CRITICAL = {"private_key", "aws_access_key", "github_token", "slack_token", "anthropic_key", "openai_key", "npm_token",
            "gitlab_token", "huggingface_token", "groq_key", "supabase_secret", "supabase_pat", "openrouter_key",
            "xai_key", "sendgrid_key", "pypi_token", "digitalocean_token"}
_PLACEHOLDER = re.compile(
    r"(?i)example|exemplo|xxxx|\.\.\.|your[_-]?|seu[_-]?|sua[_-]?|placeholder|dummy|fake|redacted|changeme|changethis|"
    r"replace[_-]?me|\*{3,}|0{8,}|<[^>]*>|\$\{|\{\{|\benv\(|^\$[A-Za-z_]\w*$|process\.env|os\.environ|getenv|import\.meta\.env")
_ASSIGN = re.compile(r"""(?P<key>[A-Za-z_][\w.-]{1,63})["']?\s*(?::|=|:=|=>)\s*(?P<q>["'`])(?P<val>[^"'`\s]{8,200})(?P=q)""")
_FENCE = re.compile(r"\s*(```|~~~)")
_WEAK_PW = {"password", "pass", "senha", "postgres", "root", "admin", "secret", "user", "test", "changeme", "changethis",
            "example", "guest", "mysql"}
_LOCAL_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)(?![\w.-])")
KIND = {
    "private_key": ("chave privada", "private key"), "aws_access_key": ("chave de acesso AWS", "AWS access key"),
    "github_token": ("token do GitHub", "GitHub token"), "slack_token": ("token do Slack", "Slack token"),
    "anthropic_key": ("chave da API da Anthropic", "Anthropic API key"), "openai_key": ("chave da API da OpenAI", "OpenAI API key"),
    "stripe_key": ("chave do Stripe", "Stripe key"), "google_api_key": ("chave de API do Google", "Google API key"),
    "meta_token": ("token da Meta/Facebook", "Meta/Facebook token"), "twilio_key": ("chave do Twilio", "Twilio key"),
    "npm_token": ("token do npm", "npm token"), "discord_webhook": ("webhook do Discord", "Discord webhook"),
    "slack_webhook": ("webhook do Slack", "Slack webhook"), "url_password": ("senha dentro de URL", "password in URL"),
    "jwt": ("token JWT", "JWT"), "stripe_webhook": ("segredo de webhook do Stripe", "Stripe webhook secret"),
    "gitlab_token": ("token do GitLab", "GitLab token"), "huggingface_token": ("token do Hugging Face", "Hugging Face token"),
    "groq_key": ("chave da API da Groq", "Groq API key"), "supabase_secret": ("chave secreta do Supabase", "Supabase secret key"),
    "supabase_pat": ("token de acesso do Supabase", "Supabase access token"),
    "openrouter_key": ("chave da API do OpenRouter", "OpenRouter API key"), "xai_key": ("chave da API da xAI", "xAI API key"),
    "sendgrid_key": ("chave do SendGrid", "SendGrid key"), "pypi_token": ("token do PyPI", "PyPI token"),
    "digitalocean_token": ("token da DigitalOcean", "DigitalOcean token"),
}


def _kind(kind, key=None):
    if key:
        return {"kind_pt": f"valor fixo em {key}", "kind_en": f"hard-coded value in {key}"}
    pt, en = KIND.get(kind, (kind, kind))
    return {"kind_pt": pt, "kind_en": en}


ENV_NAME = re.compile(r"^\.env(?:\.[\w.-]+)?$")
ENV_TEMPLATE = re.compile(r"\.(?:example|sample|template|dist|defaults?|exemplo)$", re.I)


def _jwt_role(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except (IndexError, ValueError, AttributeError, RecursionError):
        return None


def _real_token(kind, m, line):
    """Descarta exemplo de documentação: placeholder, valor truncado ("sk-ant-oat01-...") e nome de variável."""
    val = m.group(0)
    if kind == "private_key":
        return True
    if _PLACEHOLDER.search(val) or len(set(val)) < 6 or _TRUNCATED.match(line, m.end()):
        return False
    return kind not in _MIXED or bool(re.search(r"\d", val) and re.search(r"[a-z]", val) and re.search(r"[A-Z]", val))


def _tokens(line):
    """(tipo, match) de cada token de formato conhecido na linha, sem sobreposição."""
    spans, out = [], []
    if not _HINT.search(line):
        return out
    for kind, rx in TOKEN_PATTERNS:
        for m in itertools.islice(rx.finditer(line), 50):  # bundle minificado: limita o custo por linha
            if any(a < m.end() and m.start() < b for a, b in spans):
                continue
            spans.append(m.span())
            if _real_token(kind, m, line):
                out.append((kind, m))
    return out


def _url_password(m, line):
    """None se for senha de exemplo; "low" se o banco é local; "high" no resto."""
    pw = m["pw"]
    if _PLACEHOLDER.search(pw) or pw.lower() in _WEAK_PW or pw.startswith("$"):
        return None
    return "low" if _LOCAL_HOST.match(line, m.end()) else "high"


def known_kinds(text: str):
    """Tipos de segredo num valor solto (config de MCP). Formatos estritos daqui + estruturas do _redact."""
    kinds = [k for k, _ in _tokens(text)]
    kinds += ["url_password" for m in redact._URL_CREDS.finditer(text) if _url_password(m, text) == "high"]
    found = []
    redact.sanitize_text(text, found)
    skip = {k for k, _ in redact._TOKEN_PATTERNS} | {"url_password", "sanitizer_error"}
    return kinds + [f for f in found if f not in skip]


# Opção de linha de comando com segredo (--token=..., --api-key ...), que o _redact não pega por causa do hífen.
# A opção é lida inteira primeiro e só depois se procura a palavra nela: com a palavra no meio de "[\w-]*...[\w-]*",
# o regex tentava cada posição dela e ficava quadrático numa sequência longa ("-keykeykey...").
_FLAG = re.compile(r"--?[\w-]+")
_FLAG_WORD = re.compile(r"(?i)token|key|secret|passw(?:or)?d|pwd|auth|credential")
_FLAG_VALUE = re.compile(r"(?:=|\s+)[\"']?([^\s\"']{6,})")


def _mask_flags(text: str) -> str:
    out, pos = [], 0
    for m in _FLAG.finditer(text):
        if m.start() < pos or not _FLAG_WORD.search(m.group(0)):
            continue
        v = _FLAG_VALUE.match(text, m.end())
        if v:
            out += [text[pos:v.start(1)], "[REDACTED]"]
            pos = v.end(1)
    return "".join(out) + text[pos:]


def mask(text: str) -> str:
    """Texto seguro para o relatório: token vira prefixo + reticências e o resto que o _redact reconhece vira [REDACTED:tipo]."""
    for _, rx in TOKEN_PATTERNS[1:]:
        text = rx.sub(lambda m: m.group(0)[:4] + "\u2026", text)
    text = _mask_flags(text)
    return redact.sanitize_text(text)


def drop_inline_ignored(ctx, findings):
    """Comentário stingward:ignore na linha do achado vale para todas as regras, só no modo projeto.
    Numa skill de terceiros o comentário é do autor, que poderia esconder o próprio ataque."""
    if ctx.mode != "project":
        return findings
    lines = {}

    def keep(f):
        if not f.line:
            return True
        if f.file not in lines:
            lines[f.file] = ctx.read(f.file).split("\n")
        ls = lines[f.file]
        return not (f.line <= len(ls) and "stingward:ignore" in ls[f.line - 1])
    return [f for f in findings if keep(f)]


def _known_sev(kind, val):
    if kind == "stripe_key":
        return "critical" if "_live_" in val else "low"
    if kind == "google_api_key":
        return "medium"  # chaves do Firebase/Maps são públicas por desenho, mas vale restringir
    return "critical" if kind in CRITICAL else "high"


def _known(line, n, rel, low_conf, out):
    for kind, m in _tokens(line):
        if kind == "jwt":
            role = _jwt_role(m.group(0))
            if role == "service_role":
                out.append(Finding("SEC004", "critical", rel, n))
            elif role not in ("anon", "authenticated") and not low_conf:
                out.append(Finding("SEC001", "medium", rel, n, _kind("jwt")))
            continue
        out.append(Finding("SEC001", "low" if low_conf else _known_sev(kind, m.group(0)), rel, n, _kind(kind)))
    for rx, kind in ((redact._DISCORD_HOOK, "discord_webhook"), (redact._SLACK_HOOK, "slack_webhook")):
        if rx.search(line) and not _PLACEHOLDER.search(line):
            out.append(Finding("SEC001", "low" if low_conf else "high", rel, n, _kind(kind)))


def _generic(line, n, rel, low, out):
    """Senha em URL e atribuição a campo sensível. low=True para exemplo (docs, referência de skill, bloco de código)."""
    for m in redact._URL_CREDS.finditer(line):
        sev = _url_password(m, line)
        if sev:
            out.append(Finding("SEC001", "low" if low else sev, rel, n, _kind("url_password")))
    for m in _ASSIGN.finditer(line):
        key, val = m["key"].rsplit(".", 1)[-1], m["val"]
        if not redact.is_sensitive_key(key) or _PLACEHOLDER.search(val) or redact._PH_RE.search(val):
            continue
        if redact._entropy(val) < 3.3 or not re.search(r"\d", val) or re.fullmatch(r"[\w-]+\.(?:js|ts|py|json|html)", val):
            continue
        if out and out[-1].line == n:  # as linhas vêm em ordem: um achado desta linha é sempre o último da lista
            continue
        out.append(Finding("SEC001", "low" if low else "high", rel, n, _kind(None, key)))


def scan_text(text: str, rel: str, generic: bool = True, sample: bool = False):
    """Achados de segredo num texto. Nunca guarda o valor, só o tipo e a linha.
    sample=True: arquivo de exemplo (references/, assets/, templates/ de skill); senha genérica fica baixa."""
    low_conf = bool(re.search(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|examples?|mocks?|docs?)(/|$)|\.(test|spec)\.", rel))
    markdown = rel.lower().endswith((".md", ".mdx", ".mdc"))
    out, fence = [], False
    # split("\n") e não splitlines(): \f e \v contariam como quebra e a linha do achado sairia errada.
    for n, line in enumerate(text.split("\n"), 1):
        if markdown and _FENCE.match(line):
            fence = not fence
        if len(line) > 4000:
            # Linha enorme (bundle minificado): só formatos conhecidos, um achado por tipo.
            found = []
            _known(line, n, rel, low_conf, found)
            out += list({(f.rule, f.params.get("kind_en")): f for f in found}.values())
            continue
        _known(line, n, rel, low_conf, out)
        if generic:
            _generic(line, n, rel, low_conf or sample or fence, out)
    return out


def _ignored_by_gitignore(ctx, rel: str) -> bool:
    if ctx.git_tracked is not None:
        r = gitsafe.run(ctx.root, "check-ignore", "-q", "--", rel, timeout=10)
        if r is not None and r.returncode in (0, 1):
            return r.returncode == 0
    name = rel.rsplit("/", 1)[-1]
    patterns = [p.strip() for p in ctx.read(".gitignore").splitlines() if p.strip() and not p.startswith("#")]
    return any(fnmatch.fnmatch(name, p.lstrip("/")) or fnmatch.fnmatch(rel, p.lstrip("/")) for p in patterns)


# O valor vai até o fim da linha e o strip() tira os espaços do fim: "(?P<val>.*?)\s*$" testava o fim de novo a cada
# caractere do valor, quadrático numa sequência longa de espaços.
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][\w.-]*)\s*=(?P<val>.*)")


def _env_has_secret(text: str) -> bool:
    """O .env tem algum valor que parece segredo? URL, host, porta e "changethis" não contam."""
    for line in text.split("\n"):
        m = _ENV_LINE.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        key, val = m["key"], m["val"].strip().split(" #", 1)[0].strip().strip("\"'")
        if not val or _PLACEHOLDER.search(val) or val.lower() in _WEAK_PW:
            continue
        if _tokens(val) or any(_url_password(u, val) == "high" for u in redact._URL_CREDS.finditer(val)):
            return True
        if redact.is_sensitive_key(key) and not re.search(r"(?i)(?:^|_)(?:url|uri|host|port|path|file|dir|user|username|email)$", key) \
                and not redact._URL_CREDS.search(val):
            return True
    return False


def _sample_dirs(ctx):
    """Pastas de skill (com SKILL.md): references/, assets/ e templates/ dentro delas são material de exemplo."""
    roots = {r.rsplit("/", 1)[0] if "/" in r else "" for r in ctx.files if r.rsplit("/", 1)[-1] == "SKILL.md"}
    if ctx.mode == "skill":
        roots.add("")
    return roots


def _is_sample(rel, roots):
    m = re.search(r"(^|/)(references?|assets|templates?)/", rel)
    return bool(m) and any(r == "" or rel.startswith(r + "/") for r in roots)


def check(ctx):
    findings = []
    roots = _sample_dirs(ctx)
    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if ENV_NAME.match(name) and not ENV_TEMPLATE.search(name):
            if ctx.mode == "agents":
                continue
            if ctx.git_tracked is not None and rel in ctx.git_tracked:
                # .env só com URL, porta e "changethis" (template de projeto) continua no relatório, mas baixo.
                findings.append(Finding("SEC002", "high" if _env_has_secret(ctx.read(rel)) else "low", rel, None, {"name": name}))
            elif not _ignored_by_gitignore(ctx, rel):
                findings.append(Finding("SEC003", "medium", rel, None, {"name": name}))
            continue
        if not is_text_source(rel, ctx.mode):
            continue
        findings.extend(scan_text(ctx.read(rel), rel, sample=_is_sample(rel, roots)))
    return drop_inline_ignored(ctx, findings)
