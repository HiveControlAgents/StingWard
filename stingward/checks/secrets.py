"""Segredos no código e arquivos .env no git. Usa os padrões do motor de mascaramento (_redact)."""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
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
    # Dado binário em base64 (imagem, fonte, wasm) é cheio de "AAAA": "/EAA..." e "+EAA..." no meio dele não são token.
    ("meta_token", re.compile(r"(?<![\w+/])EAA[A-Za-z0-9]{20,}(?![\w+/=])")),
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
    # Tamanhos exatos de cada serviço: um prefixo curto como r8_, ntn_ ou re_ também aparece em nome de variável.
    ("google_oauth_secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])")),
    ("replicate_token", re.compile(r"\br8_[A-Za-z0-9]{37}\b")),
    ("pinecone_key", re.compile(r"\bpcsk_[A-Za-z0-9]{4,8}_[A-Za-z0-9]{50,80}\b")),
    ("shopify_token", re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b")),
    ("notion_token", re.compile(r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b")),
    ("linear_key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("resend_key", re.compile(r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b")),
]
# Filtro rápido: linha sem nenhum desses prefixos não tem token de formato conhecido.
_HINT = re.compile(r"-----BEGIN|eyJ|AKIA|ASIA|ABIA|ACCA|gh[pousr]_|github_pat_|xox|xapp-|sk-|[rs]k_|whsec_|AIza|EAA|SK[0-9a-fA-F]|"
                   r"npm_|glpat-|hf_|gsk_|sb_secret_|sbp_|xai-|SG\.|pypi-|do[opr]_v1_|GOCSPX-|r8_|pcsk_|shp(?:at|ss|ca|pa)_|"
                   r"ntn_|lin_api_|\bre_[A-Za-z0-9]{8}_")
# Token aleatório de verdade tem dígito e maiúscula/minúscula; nome de variável e exemplo de doc, não.
_MIXED = {"openai_key", "meta_token", "npm_token", "replicate_token", "resend_key"}
# Token do Hugging Face: 34 letras e dígitos aleatórios, e cerca de 1 em 400 sai sem dígito. Basta ter as duas caixas.
_CASED = {"huggingface_token"}
# Prefixo com minúscula ou dígito (hf_, r8_, re_, npm_, sk-proj-): a conta de caixas e dígito olha só o que vem
# depois dele. Senão "npm_" + MAIÚSCULAS E DÍGITOS passava por ter as duas caixas.
_OWN_PREFIX = {"huggingface_token": re.compile(r"hf_"), "replicate_token": re.compile(r"r8_"),
               "resend_key": re.compile(r"re_"), "npm_token": re.compile(r"npm_"),
               "openai_key": re.compile(r"sk-(?:proj-|svcacct-|admin-)?")}
# Exemplo de documentação: "sk-ant-oat01-...", "ghp_abc***", "xoxb-<token>", "AKIA1234xxxx".
_TRUNCATED = re.compile(r"\.\.\.|\u2026|\*|<(?!/)|[xX]{4}")

# Formatos que identificam o serviço com certeza: severidade crítica.
CRITICAL = {"private_key", "aws_access_key", "github_token", "slack_token", "anthropic_key", "openai_key", "npm_token",
            "gitlab_token", "huggingface_token", "groq_key", "supabase_secret", "supabase_pat", "openrouter_key",
            "xai_key", "sendgrid_key", "pypi_token", "digitalocean_token", "replicate_token", "pinecone_key", "shopify_token",
            "notion_token", "linear_key", "resend_key"}
# "seu" e "sua" só no começo de uma palavra (SUA_CHAVE, sk-sua-chave): com três letras, apareciam no meio aleatório de
# cerca de 1 em cada 100 chaves de projeto da OpenAI, que então passavam por exemplo.
_PLACEHOLDER = re.compile(
    r"(?i)example|exemplo|xxxx|\.\.\.|your[_-]?|(?<![a-z0-9])(?:seu|sua)[_-]?|placeholder|dummy|fake|redacted|changeme|changethis|"
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
    "google_oauth_secret": ("segredo de cliente OAuth do Google", "Google OAuth client secret"),
    "replicate_token": ("token da API do Replicate", "Replicate API token"),
    "pinecone_key": ("chave da API do Pinecone", "Pinecone API key"), "shopify_token": ("token do Shopify", "Shopify token"),
    "notion_token": ("token da API do Notion", "Notion API token"), "linear_key": ("chave da API do Linear", "Linear API key"),
    "resend_key": ("chave da API do Resend", "Resend API key"), "clerk_key": ("chave secreta do Clerk", "Clerk secret key"),
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


# Segredo padrão do Supabase CLI: o supabase start assina com ele as chaves anon e service_role de toda instalação local
# (emissor "supabase-demo"). Público na documentação; a chave assinada com ele só abre o banco local.
_DEMO_JWT_SECRET = b"super-secret-jwt-token-with-at-least-" + b"32-characters-long"
_DEMO_NOTE = {"note_pt": " (chave padrão do ambiente local)", "note_en": " (local default key)",
              "local_pt": " Esta é a chave padrão que o supabase start cria em toda máquina: só abre o banco local. "
                          "Confira se a produção usa uma chave própria.",
              "local_en": " This is the default key that supabase start creates on every machine: it only opens the "
                          "local database. Make sure production uses a key of its own."}


def _demo_key(token: str) -> bool:
    """A chave de exemplo do Supabase local: emissor supabase-demo e assinatura feita com o segredo padrão do CLI.
    Com outra assinatura (o projeto trocou o segredo) ou outro emissor, é chave de verdade."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, RecursionError):
        return False
    if not isinstance(claims, dict) or claims.get("iss") != "supabase-demo":
        return False
    sig = hmac.new(_DEMO_JWT_SECRET, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    return hmac.compare_digest(base64.urlsafe_b64encode(sig).decode().rstrip("="), parts[2])


# Também o bloco do PGP ("PRIVATE KEY BLOCK"), cujo armor tem cabeçalhos (Version:, Comment:) e uma linha em branco.
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_PEM_HEADER = re.compile(r"(?:Proc-Type|DEK-Info|Comment|Version|Hash|Charset|MessageID):")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}")


def _pem_body(text: str) -> bool:
    """O texto tem corpo de chave: base64 com maiúscula, minúscula e dígito, e não um "...", "abc" ou "YOUR_KEY"."""
    for run in _B64_RUN.findall(text):
        if (len(set(run)) >= 10 and re.search(r"\d", run) and re.search(r"[a-z]", run) and re.search(r"[A-Z]", run)
                and not _PLACEHOLDER.search(run)):
            return True
    return False


def _real_key(val, nxt):
    """Chave privada de verdade, e não só o cabeçalho: código que lida com chaves (startsWith, replace, placeholder=
    "-----BEGIN...") também escreve o cabeçalho. O corpo vem na mesma linha (JSON com \\n) ou, se depois do
    cabeçalho só sobra pontuação, na próxima linha que não está em branco (nxt). nxt None é valor solto sem linha seguinte (.env, config
    de MCP): aí o cabeçalho sozinho conta, como antes."""
    head = _PEM_BEGIN.match(val)  # o padrão vem do _redact: um cabeçalho que este não conhece não derruba a varredura
    body = re.sub(r"\\[rn]", "\n", val[head.end() if head else val.find("-----", 5) + 5:])
    closed = "-----END" in body
    body = body.split("-----END", 1)[0]
    lines = [ln for ln in body.split("\n") if re.search(r"[A-Za-z0-9]", ln) and not _PEM_HEADER.match(ln.strip(" \t\"'`"))]
    if lines or closed:
        return _pem_body(" ".join(lines))
    if nxt is None:
        return True
    return _pem_body(nxt) or _PEM_HEADER.match(nxt.strip(" \t\"'`>")) is not None


def _real_token(kind, m, line, nxt=None):
    """Descarta exemplo de documentação: placeholder, valor truncado ("sk-ant-oat01-...") e nome de variável."""
    val = m.group(0)
    if kind == "private_key":
        return _real_key(val, nxt)
    if _PLACEHOLDER.search(val) or len(set(val)) < 6 or _TRUNCATED.match(line, m.end()):
        return False
    if kind in _OWN_PREFIX:  # dígito e caixas contam só depois do prefixo: o "r8" de r8_ já tem os dois
        val = val[_OWN_PREFIX[kind].match(val).end():]
    cased = bool(re.search(r"[a-z]", val) and re.search(r"[A-Z]", val))
    if kind in _CASED:
        return cased
    return kind not in _MIXED or bool(cased and re.search(r"\d", val))


def _tokens(line, nxt=None):
    """(tipo, match) de cada token de formato conhecido na linha, sem sobreposição. nxt: a linha seguinte."""
    spans, out = [], []
    if not _HINT.search(line):
        return out
    for kind, rx in TOKEN_PATTERNS:
        for m in itertools.islice(rx.finditer(line), 50):  # bundle minificado: limita o custo por linha
            if any(a < m.end() and m.start() < b for a, b in spans):
                continue
            spans.append(m.span())
            if _real_token(kind, m, line, nxt):
                out.append((kind, m))
    return out


# Senha que o código preenche: f"{settings.DB_PASSWORD}", "{}".format, "%s", "%(password)s", Ruby "#{pw}", Swift "\(pw)".
_INTERP = re.compile(r"(?:\{[^{}]*\}|%(?:\([^)]*\))?[-+ #0-9.]*[sdrv]|#\{[^}]*\}|\\\([^)]*\))+")
# Porta escrita como palavra (host:port, servidor:porta, 主机名:端口): é modelo de URL, não endereço de verdade.
# Só letras: "{host}:{port}" é código que monta a URL e a senha ao lado dele pode ser de verdade.
_WORD_PORT = re.compile(r"[^\s/?#@:\[\]]*:[^\W\d_]+(?!\w)")


def _url_password(m, line):
    """None se for senha de exemplo; "low" se o banco é local; "high" no resto."""
    pw = m["pw"]
    if _PLACEHOLDER.search(pw) or pw.lower() in _WEAK_PW or pw.startswith("$") or _INTERP.fullmatch(pw):
        return None
    # Letra fora do ASCII só entra numa URL de verdade codificada (%C3%A7): "usuario:contraseña@" é texto de exemplo.
    if not pw.isascii() or _WORD_PORT.match(line, m.end()):
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


# Rede extra do mask(): o detector exige o formato exato, mas o relatório não pode mostrar um token com comprimento
# fora do padrão nem de um serviço que o detector ainda não conhece. Só prefixo de serviço com rabo aleatório.
_LOOSE_TOKEN = re.compile(
    r"\b(?:hf_|gsk_|xai-|sbp_|npm_|r8_|ntn_|lin_api_|shp(?:at|ss|ca|pa)_|do[opr]_v1_)[A-Za-z0-9]{16,}"
    r"|\b(?:glpat-|sb_secret_|GOCSPX-|pcsk_)[A-Za-z0-9_-]{16,}|\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{16,}"
    r"|\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")
# Credencial em URL (?key=) e na linha de comando: curl -u usuario:senha, sshpass -p, mysql -psenha.
_QUERY_KEY = re.compile(r"([?&;]key=)([^&\s#\"']{8,})")
_USER_PASS = re.compile(r"(?<!\S)(?:--user[=\s]\s*|-u\s*)[^\s:\"']+:([^\s\"']{4,})")
_SSHPASS = re.compile(r"\bsshpass\s+-p\s*([^\s\"']+)")
_MYSQL = re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b")
_MYSQL_PW = re.compile(r"(?<!\S)-p([^\s\"']{4,})")


def _mask_loose(text: str) -> str:
    def redact_group(m):
        g = m.lastindex
        if m.re is _USER_PASS and m.group(g).isdigit():  # docker run -u 1000:1000
            return m.group(0)
        return m.group(0)[:m.start(g) - m.start()] + "[REDACTED]" + m.group(0)[m.end(g) - m.start():]
    text = _LOOSE_TOKEN.sub(lambda m: m.group(0)[:4] + "\u2026", text)
    for rx in (_QUERY_KEY, _USER_PASS, _SSHPASS):
        text = rx.sub(redact_group, text)
    if _MYSQL.search(text):
        text = _MYSQL_PW.sub(redact_group, text)
    return text


def mask(text: str) -> str:
    """Texto seguro para o relatório: token vira prefixo + reticências e o resto que o _redact reconhece vira [REDACTED:tipo]."""
    for _, rx in TOKEN_PATTERNS[1:]:
        text = rx.sub(lambda m: m.group(0)[:4] + "\u2026", text)
    text = _mask_flags(_mask_loose(text))
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


# A chave secreta do Clerk tem o formato da do Stripe (sk_live_, sk_test_): quem diz o serviço é a linha.
_CLERK = re.compile(r"(?i)clerk")


def _known(line, n, rel, low_conf, out, nxt=""):
    for kind, m in _tokens(line, nxt):
        if kind == "jwt":
            role = _jwt_role(m.group(0))
            if role == "service_role":
                demo = _demo_key(m.group(0))
                out.append(Finding("SEC004", "low" if demo else "critical", rel, n, dict(_DEMO_NOTE) if demo else {}))
            elif role not in ("anon", "authenticated") and not low_conf:
                out.append(Finding("SEC001", "medium", rel, n, _kind("jwt")))
            continue
        sev = "low" if low_conf else _known_sev(kind, m.group(0))
        if kind == "stripe_key" and _CLERK.search(line):
            kind = "clerk_key"  # mesmo formato sk_live_/sk_test_ do Stripe, mesma severidade
        out.append(Finding("SEC001", sev, rel, n, _kind(kind)))
    for rx, kind in ((redact._DISCORD_HOOK, "discord_webhook"), (redact._SLACK_HOOK, "slack_webhook")):
        # O exemplo está no token do próprio webhook (XXXX, YOUR/WEBHOOK/URL), não no resto da linha: um "your build
        # finished" ou um process.env.X || "https://hooks..." ao lado escondia o webhook de verdade.
        if any(not _PLACEHOLDER.search(m["tok"]) for m in itertools.islice(rx.finditer(line), 50)):
            out.append(Finding("SEC001", "low" if low_conf else "high", rel, n, _kind(kind)))


# Valores que não são segredo: caminho de configuração (image_generation.automatic1111.api_auth), nome de variável
# (DUCKLAKE_S3_SECRET, MOCK_ACCESS_TOKEN) e chave pública por desenho (sb_publishable_, pk_live_ e pk_test_ do Stripe).
_NOT_SECRET = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|(?:sb_publishable_|pk_(?:live|test)_)\S*")
_DIGITS = "0123456789" * 3


def _not_secret(val: str) -> bool:
    """Texto traduzido (fora do ASCII ou com \\uXXXX: arquivo de i18n), 1234567890 de exemplo e os de _NOT_SECRET."""
    if not val.isascii() or "\\u" in val or _NOT_SECRET.fullmatch(val):
        return True
    return val.isdigit() and (val in _DIGITS or val in _DIGITS[::-1])


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
        if _not_secret(val):
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
    lines = text.split("\n")
    for n, line in enumerate(lines, 1):
        # A linha seguinte que não está em branco: no PGP o corpo vem depois de uma linha vazia.
        nxt = next((ln for ln in lines[n:n + 3] if ln.strip()), "") if "-----BEGIN" in line else ""
        if markdown and _FENCE.match(line):
            fence = not fence
        if len(line) > 4000:
            # Linha enorme (bundle minificado): só formatos conhecidos, um achado por tipo.
            found = []
            _known(line, n, rel, low_conf, found, nxt)
            out += list({(f.rule, f.params.get("kind_en")): f for f in found}.values())
            continue
        _known(line, n, rel, low_conf, out, nxt)
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
        # Valor cifrado pelo dotenvx e a chave pública dele, e os ambientes cifrados do .env.vault (dotenv-vault):
        # commitar esse arquivo é o uso previsto (a chave que abre fica no .env.keys, que continua contando).
        if val.startswith("encrypted:") or key.startswith(("DOTENV_PUBLIC_KEY", "DOTENV_VAULT")):
            continue
        if key == "DOTENV_ME" and val.startswith("me_"):  # login do dotenv-vault: baixa todos os ambientes
            return True
        toks = _tokens(val)
        # A chave anon do Supabase vai para o navegador de propósito; o SEC001 também não a conta. A service_role
        # padrão do Supabase local (_demo_key) também não abre nada fora da máquina.
        if toks and all(kind == "jwt" and (_jwt_role(m.group(0)) in ("anon", "authenticated") or _demo_key(m.group(0)))
                        for kind, m in toks):
            continue
        if toks or any(_url_password(u, val) == "high" for u in redact._URL_CREDS.finditer(val)):
            return True
        # Endereço puro (sem senha nem query) não é segredo, mesmo num nome como AUTH_CALLBACK ou ..._REDIRECT_URLS.
        plain_urls = all(re.fullmatch(r"https?://[^\s?#@]+", u.strip()) for u in val.split(","))
        if redact.is_sensitive_key(key) and not re.search(r"(?i)(?:^|_)(?:url|uri|host|port|path|file|dir|user|username|email)s?$", key) \
                and not redact._URL_CREDS.search(val) and not plain_urls:
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


# Arquivo de chave (id_rsa, server.key, cert.pem, AuthKey_X.p8) fica fora das extensões de texto, mas é nele que a chave
# privada costuma ir para o git. Só os formatos conhecidos: um certificado (só a parte pública) não dá achado.
_KEY_FILE = re.compile(r"(?i)^id_(?:rsa|dsa|ecdsa|ed25519)$|\.(?:pem|key|p8)$")


def check(ctx):
    findings = []
    roots = _sample_dirs(ctx)
    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if ENV_NAME.match(name) and not ENV_TEMPLATE.search(name):
            if ctx.mode == "agents":
                continue
            # O .env.vault do dotenv-vault é feito para ir ao git (só leva os ambientes cifrados): só conta se
            # alguém pôs nele um segredo em texto puro.
            vault = name == ".env.vault"
            if ctx.git_tracked is not None and rel in ctx.git_tracked:
                # .env só com URL, porta e "changethis" (template de projeto) continua no relatório, mas baixo.
                secret = _env_has_secret(ctx.read(rel))
                if secret or not vault:
                    findings.append(Finding("SEC002", "high" if secret else "low", rel, None, {"name": name}))
            elif not vault and not _ignored_by_gitignore(ctx, rel):
                findings.append(Finding("SEC003", "medium", rel, None, {"name": name}))
            continue
        if not is_text_source(rel, ctx.mode):
            if _KEY_FILE.search(name):
                findings.extend(scan_text(ctx.read(rel), rel, generic=False))
            continue
        findings.extend(scan_text(ctx.read(rel), rel, sample=_is_sample(rel, roots)))
    return drop_inline_ignored(ctx, findings)
