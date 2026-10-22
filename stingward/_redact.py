"""Sanitizador central de segredos para logs, diagnósticos, banco e notificações.

Regras de projeto:
- Idempotente: sanitize_text(sanitize_text(x)) == sanitize_text(x). Pode rodar
  em todos os pontos de saída do fluxo sem quebrar nada.
- Não sanitiza demais: arquivo e linha de stack trace são preservados.
- Nunca levanta exceção com entrada estranha (registros antigos, tipos mistos).
"""
from __future__ import annotations

import math
import re
from urllib.parse import unquote

VERSION = "0.1.0"

_PH_RE = re.compile(r"\[REDACTED:[a-z_]+\]")


def _ph(kind: str) -> str:
    return f"[REDACTED:{kind}]"


# "[REDACTED]" sem tipo é o que o mask() das verificações já pôs antes: lido como valor, ganharia um segundo marcador.
_PH_PREFIXES = ("[REDACTED:", "[REDACTED]")


def _is_ph(value: str) -> bool:
    return value.startswith(_PH_PREFIXES)


def _note(findings, kind):
    if findings is not None:
        findings.append(kind)


# --------------------------------------------------------------------------
# Chaves sensíveis
# --------------------------------------------------------------------------

_SENSITIVE_PARTS = {
    "password", "passwd", "pwd", "pass", "passphrase", "secret", "token",
    "authorization", "auth", "cookie", "otp", "pin", "cvv", "cvc",
    "credential", "credentials", "signature", "sig", "jwt", "bearer",
    "session", "sessionid", "sid", "apikey",
    # português
    "senha", "segredo", "credencial", "credenciais",
}
# Substrings que denunciam segredo mesmo coladas a outra palavra (dbpassword, csrftoken).
_SENSITIVE_SUBSTR = ("password", "passwd", "secret", "token", "apikey", "privatekey", "credential", "senha", "sessid", "sessionid")
_NONSECRET_LAST = {
    "type", "types", "count", "expires", "expiry", "expiration", "exp", "ttl",
    "length", "len", "name", "names", "hint", "format", "url", "uri",
    "endpoint", "policy", "required", "field", "fields", "enabled", "present",
    "method", "mode", "provider", "scheme", "status", "state", "flow",
    "version", "at", "in", "id", "ids", "strength", "changed", "reset",
}


def is_sensitive_key(key) -> bool:
    """True se o nome do campo indica que o valor é segredo, de qualquer tamanho."""
    try:
        k = str(key).strip().strip("\"'")
    except Exception:
        return False
    if not k:
        return False
    k = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", k).lower()
    parts = [p for p in re.split(r"[^a-z0-9]+", k) if p]
    if not parts:
        return False
    if len(parts) > 1 and parts[-1] in _NONSECRET_LAST:
        return False
    compact = "".join(parts)
    if any(p in _SENSITIVE_PARTS for p in parts):
        return True
    return any(s in compact for s in _SENSITIVE_SUBSTR)


# --------------------------------------------------------------------------
# Estágio 1: padrões de token com formato conhecido (rodam antes de tudo)
# --------------------------------------------------------------------------

_TOKEN_PATTERNS = [
    # PEM (RSA, EC, OPENSSH, ENCRYPTED...) e o bloco armado do PGP/GPG, que termina em "PRIVATE KEY BLOCK-----".
    ("private_key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")),
    # Prefixos com mínimo baixo de propósito: pegam também tokens já truncados.
    ("jwt", re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}(?:\.[A-Za-z0-9_-]*)?")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{12,16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{4,}|github_pat_[A-Za-z0-9_]{4,})")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{4,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{4,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}")),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{4,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{10,}")),
    ("meta_token", re.compile(r"\bEAA[A-Za-z0-9]{20,}")),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{8,}")),
    # Bot do Telegram (123456789:AA...), também dentro da URL da API: https://api.telegram.org/bot<token>/sendMessage
    ("telegram_token", re.compile(r"(?:(?<=bot)|(?<![\w-]))\d{8,10}:AA[A-Za-z0-9_-]{20,}")),
    # Connection string do Azure (Storage, Service Bus, Event Hubs): só o valor some, o nome do campo fica.
    ("azure_key", re.compile(r"(?:(?<=AccountKey=)|(?<=SharedAccessKey=))[A-Za-z0-9+/]{16,}={0,2}")),
]

# Esquema com teto de tamanho: sem ele, "a.a.a.a..." testaria cada letra até o fim do texto (tempo quadrático).
# A senha vai até o último @ antes do host: "P@ssw0rd" sem codificar é comum, e cortar no primeiro @ deixaria
# "ssw0rd" no relatório. Depois de um @, aspas, vírgula, ?, #, & e = encerram: são de outro valor ou da query.
_URL_CREDS = re.compile(r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.\-]{0,30}://)(?P<user>[^:/\s@\[]*):"
                        r"(?P<pw>[^@\s/]+(?:@[^@\s/\"'`<>,;?#&=]+)*)@")
_DISCORD_HOOK = re.compile(r"(?P<base>https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/\d+/)(?P<tok>[\w-]+)")
_SLACK_HOOK = re.compile(r"(?P<base>https://hooks\.slack\.com/services/)(?P<tok>[\w/]+)")
_AUTH_SCHEME = re.compile(r"(?i)\b(?P<s>Bearer|Basic|Digest)\s+(?P<v>[A-Za-z0-9\-._~+/]{8,}=*)")


def _apply_tokens(s: str, f) -> str:
    for kind, rx in _TOKEN_PATTERNS:
        if kind == "private_key":
            def repl(m, kind=kind):
                _note(f, kind)
                return _ph(kind)
            s = rx.sub(repl, s)

    def creds(m):
        if _is_ph(m["pw"]):
            return m[0]
        _note(f, "url_password")
        return f"{m['scheme']}{m['user']}:{_ph('url_password')}@"
    s = _URL_CREDS.sub(creds, s)

    for kind, rx in ((("discord_webhook"), _DISCORD_HOOK), ("slack_webhook", _SLACK_HOOK)):
        def hook(m, kind=kind):
            if _is_ph(m["tok"]):
                return m[0]
            _note(f, kind)
            return m["base"] + _ph(kind)
        s = rx.sub(hook, s)

    for kind, rx in _TOKEN_PATTERNS:
        if kind == "private_key":
            continue
        def repl(m, kind=kind):
            _note(f, kind)
            return _ph(kind)
        s = rx.sub(repl, s)

    def scheme(m):
        v = m["v"]
        # "Basic authentication" não é credencial: token real tem dígito ou símbolo.
        if not re.search(r"[\d\-._~+/=]", v):
            return m[0]
        _note(f, "bearer_token")
        return f"{m['s']} {_ph('bearer_token')}"
    return _AUTH_SCHEME.sub(scheme, s)


# --------------------------------------------------------------------------
# Proteção de stack trace: arquivo e linha são referência de código, não segredo
# --------------------------------------------------------------------------

_EXT = r"(?:py|js|mjs|cjs|ts|tsx|jsx|go|java|kt|rb|php|rs|cs|scala|swift)"
# Os padrões só começam no início de um caminho e têm teto de tamanho: valor longo vindo da skill auditada
# (config de MCP) não pode levar tempo quadrático.
_FRAME_PATTERNS = [
    re.compile(r'File "[^"\n]+", line \d+'),
    re.compile(r"(?:https?|file|webpack|node):/{1,3}[^\s()]{1,500}?\." + _EXT + r"(?::\d+){1,2}"),
    re.compile(r"(?<![\w.\-@~%/\\])(?:[A-Za-z]:)?(?:[\w.\-@~%]*[/\\])+[\w.\-@%]+\." + _EXT + r"(?::\d+){1,2}"),
    re.compile(r"\b[\w$]+\." + _EXT + r":\d+(?::\d+)?"),
]


def _protect_frames(s: str):
    frames: list[str] = []

    def keep(m):
        frames.append(m[0])
        return f"\x00F{len(frames) - 1}\x00"
    for rx in _FRAME_PATTERNS:
        s = rx.sub(keep, s)
    return s, frames


def _restore_frames(s: str, frames) -> str:
    if not frames:
        return s
    return re.sub(r"\x00F(\d+)\x00", lambda m: frames[int(m[1])], s)


# --------------------------------------------------------------------------
# Estágio 2: estruturas (JSON, cabeçalhos, chave=valor, caminhos de URL)
# --------------------------------------------------------------------------

# "chave" => "valor" é o array do PHP (config do Laravel, wp-config) e o hash do Ruby.
_JSON_PLAIN = re.compile(
    r"""(?<!\\)(?P<q>["'])(?P<key>[^"'\\\s:]{1,64})(?P=q)\s*(?::|=>)\s*"""
    r"""(?:(?P<vq>["'])(?P<sval>(?:\\.|(?!(?P=vq))[^\\\n])*)(?P<close>(?P=vq)|(?=\n)|\Z)"""
    r"""|(?P<nval>-?[\w.+\-]+))""")
# JSON serializado dentro de string: {\"password\": \"x\"}. Até 8 barras (8 níveis de escape): sem teto, uma
# sequência longa de barras seria varrida de cada posição até o fim (tempo quadrático).
_JSON_ESCAPED = re.compile(
    r"""(?P<q>\\{1,8}["'])(?P<key>[^"'\\\s:]{1,64})(?P=q)\s*:\s*"""
    r"""(?:(?P<vq>\\{1,8}["'])(?P<sval>(?:(?!(?P=vq))[^\n])*?)(?P<close>(?P=vq)|(?=\n)|\Z)"""
    r"""|(?P<nval>-?[\w.+\-]+))""")


def _json_rule(rx, f):
    def sub(m):
        if not is_sensitive_key(m["key"]):
            return m[0]
        base = m.start()
        if m.start("sval") != -1:
            v = m["sval"]
            if not v or _is_ph(v):
                return m[0]
            _note(f, "secret_field")
            return m[0][: m.start("sval") - base] + _ph("secret_field") + m["close"]
        v = m["nval"]
        if v in ("null", "true", "false", "None", "True", "False") or _is_ph(v):
            return m[0]
        _note(f, "secret_field")
        q = m["q"]
        return m[0][: m.start("nval") - base] + q + _ph("secret_field") + q
    return lambda s: rx.sub(sub, s)


_HEADER = re.compile(
    r"(?i)(?P<key>(?<![\w-])(?:proxy-)?authorization|(?<![\w-])set-cookie|(?<![\w-])cookie"
    r"|(?<![\w-])x-api-key|(?<![\w-])x-auth-token|(?<![\w-])api-key)(?P<sep>\s*:\s*)(?P<val>[^\r\n\"']+)")


def _apply_headers(s: str, f) -> str:
    def sub(m):
        val = m["val"].rstrip()
        tail = m["val"][len(val):]
        if not val or _is_ph(val):
            return m[0]
        sm = re.match(r"(?i)(bearer|basic|digest|token)\s+(.*)$", val)
        if sm:
            if not sm[2] or _is_ph(sm[2]):
                return m[0]
            _note(f, "authorization")
            return f"{m['key']}{m['sep']}{sm[1]} {_ph('authorization')}{tail}"
        _note(f, "authorization")
        return f"{m['key']}{m['sep']}{_ph('authorization')}{tail}"
    return _HEADER.sub(sub, s)


# Casa só chave + separador. O valor é lido à mão para que uma chave não sensível
# nunca "engula" um par sensível que vem depois (next=/cb?token=abc).
# Separador: := e ::= (Go, Pascal, BNF), ?= (Makefile), == e != (senha comparada no código) e => só antes de aspas
# (hash do Ruby; sem aspas é arrow function). Lidos como "=" ou ":", o valor virava o resto do operador e vazava.
_ASSIGN_KEY = re.compile(r"(?<![\w.\-\[\]%\"'\\])(?P<key>[A-Za-z_][\w.\-\[\]]{0,63})"
                         r"(?P<sep>\s*(?::{1,2}=|\?=|={2,3}|!={1,2}|=>(?=\s*[\"'])|[=:])\s*)")
_UNQUOTED_STOP = set("&;,\"'<>#)]}") | {" ", "\t", "\r", "\n"}


def _read_value(s: str, i: int):
    if i >= len(s):
        return i
    q = s[i]
    if q in "\"'":
        j = i + 1
        while j < len(s) and s[j] != "\n":
            if s[j] == "\\":
                j += 2
                continue
            if s[j] == q:
                return j + 1
            j += 1
        return min(j, len(s))
    j = i
    if s.startswith(_PH_PREFIXES, i):
        end = s.find("]", i)
        return end + 1 if end != -1 else len(s)
    while j < len(s) and s[j] not in _UNQUOTED_STOP:
        j += 1
    return j


# Valor sem aspas que é palavra da linguagem, não segredo: credentials: true (cors, fetch), password = None.
_LITERALS = {"true", "false", "null", "undefined", "nil", "None", "True", "False", "NULL", "TRUE", "FALSE"}


def _apply_assign(s: str, f) -> str:
    out, pos = [], 0
    for m in _ASSIGN_KEY.finditer(s):
        if m.start() < pos or not is_sensitive_key(m["key"]):
            continue
        vstart = m.end()
        vend = _read_value(s, vstart)
        val = s[vstart:vend]
        if not val:
            continue
        core = val[1:] if val[0] in "\"'" else val
        if _is_ph(core) or val.startswith("\x00") or val in ('""', "''") or val in _LITERALS:
            continue
        # "Authorization: Bearer [REDACTED...]" já foi tratado pelo cabeçalho.
        if val.lower() in ("bearer", "basic", "digest", "token") and s.startswith(" [REDACTED:", vend):
            continue
        _note(f, "secret_field")
        if val[0] in "\"'":
            closed = len(val) > 1 and val[-1] == val[0]
            repl = val[0] + _ph("secret_field") + (val[0] if closed else "")
        else:
            repl = _ph("secret_field")
        out.append(s[pos:vstart])
        out.append(repl)
        pos = vend
    out.append(s[pos:])
    return "".join(out)


_PATH_TRIGGERS = {
    "token", "tokens", "reset", "reset-password", "password-reset", "verify",
    "verification", "confirm", "activate", "activation", "magic", "magic-link",
    "invite", "invitation", "api-key", "api-keys", "apikey", "keys", "key",
    "secret", "secrets", "session", "sessions", "otp", "code", "auth-code",
    "signature", "unsubscribe",
}
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ASSET = re.compile(r".+\.(?:js|css|map|png|jpe?g|gif|svg|webp|html?|ico|woff2?|ttf|txt|json)$", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _full_unquote(s: str, layers: int = 5) -> str:
    for _ in range(layers):
        d = unquote(s)
        if d == s:
            break
        s = d
    return s


def _high_entropy(seg: str) -> bool:
    if len(seg) < 20 or _UUID.fullmatch(seg) or _ASSET.match(seg):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_\-+=.~]+", seg):
        return False
    if not (re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg)):
        return False
    return _entropy(seg) >= 3.5


def _looks_like_value(seg: str) -> bool:
    return bool(seg) and not re.fullmatch(r"[a-z]+(?:[-_][a-z]+)*", seg)


def sanitize_path(path: str, findings=None) -> str:
    """Sanitiza segmentos de um caminho de URL (sem a query)."""
    segs = path.split("/")
    prev = ""
    for i, seg in enumerate(segs):
        dec = _full_unquote(seg)
        if seg and not _PH_RE.fullmatch(seg) and "\x00" not in seg:
            if prev in _PATH_TRIGGERS and _looks_like_value(dec):
                _note(findings, "path_secret")
                segs[i] = _ph("path_secret")
            elif _high_entropy(dec):
                _note(findings, "path_secret")
                segs[i] = _ph("path_secret")
        prev = dec.lower()
    return "/".join(segs)


_URL = re.compile(r"(?P<base>\bhttps?://[^\s/?#\"'<>]+)(?P<path>/[^\s?#\"'<>]*)?")
_METHOD_PATH = re.compile(r"\b(?P<m>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<path>/[^\s?#\"'<>]*)")


def _apply_paths(s: str, f) -> str:
    def url(m):
        if not m["path"]:
            return m[0]
        return m["base"] + sanitize_path(m["path"], f)
    s = _URL.sub(url, s)
    return _METHOD_PATH.sub(lambda m: f"{m['m']} {sanitize_path(m['path'], f)}", s)


def _apply_structured(s: str, f) -> str:
    s = _apply_headers(s, f)
    s = _json_rule(_JSON_PLAIN, f)(s)
    s = _json_rule(_JSON_ESCAPED, f)(s)
    s = _apply_assign(s, f)
    return _apply_paths(s, f)


# --------------------------------------------------------------------------
# Codificação dupla: decodifica para detectar, troca só o que tinha segredo
# --------------------------------------------------------------------------

# Só a partir do começo de cada pedaço: tentar de cada posição seria quadrático num valor longo sem %.
_ENCODED = re.compile(r"(?<![^\s\"'<>])[^\s\"'<>]*%[0-9A-Fa-f]{2}[^\s\"'<>]*")


def _apply_encoded(s: str, f) -> str:
    def sub(m):
        tok = m[0]
        dec = _full_unquote(tok)
        if dec == tok:
            return tok
        inner = _apply_structured(_apply_tokens(dec, None), None)
        if inner == dec:
            return tok
        _note(f, "encoded_secret")
        return inner
    return _ENCODED.sub(sub, s)


# --------------------------------------------------------------------------
# API pública
# --------------------------------------------------------------------------

def sanitize_text(text, findings=None):
    """Remove segredos de um texto livre. Devolve não-strings sem mexer."""
    if not isinstance(text, str) or not text:
        return text
    try:
        s = _apply_tokens(text, findings)
        s, frames = _protect_frames(s)
        s = _apply_encoded(s, findings)
        s = _apply_structured(s, findings)
        return _restore_frames(s, frames)
    except Exception:
        # Falha fechada: melhor perder o diagnóstico do que vazar o segredo.
        _note(findings, "sanitizer_error")
        return _ph("sanitizer_error")


def find_secrets(text) -> list[str]:
    """Tipos de segredo encontrados no texto (sem devolver os valores)."""
    found: list[str] = []
    sanitize_text(text, found)
    return sorted(set(found))


def contains_secret(text) -> bool:
    return bool(find_secrets(text))


_PATH_KEYS = {
    "path", "url", "uri", "route", "referer", "referrer", "location", "endpoint",
    "href", "redirect", "redirect_uri", "redirect_url", "callback", "callback_url",
    "next", "return_to", "request_uri",
}


def _sanitize_path_value(v: str, f) -> str:
    v = sanitize_text(v, f)
    if v.startswith("/"):
        path, sep, rest = v.partition("?")
        return sanitize_path(path, f) + sep + rest
    return v


def sanitize_obj(obj, findings=None, _depth: int = 0):
    """Sanitiza dicts/listas recursivamente. Chave sensível tem o valor todo trocado."""
    if _depth > 50:
        return _ph("too_deep")
    if isinstance(obj, str):
        return sanitize_text(obj, findings)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if is_sensitive_key(k) and v not in (None, "") and not (isinstance(v, str) and _is_ph(v)):
                _note(findings, "secret_field")
                out[k] = _ph("secret_field")
            elif isinstance(v, str) and str(k).lower() in _PATH_KEYS:
                out[k] = _sanitize_path_value(v, findings)
            else:
                out[k] = sanitize_obj(v, findings, _depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        items = [sanitize_obj(v, findings, _depth + 1) for v in obj]
        return type(obj)(items) if isinstance(obj, tuple) else items
    if isinstance(obj, bytes):
        try:
            return sanitize_text(obj.decode("utf-8"), findings).encode("utf-8")
        except UnicodeDecodeError:
            return obj
    return obj


def truncate(text: str, max_len: int, marker: str = "…[truncado]") -> str:
    """Sanitiza ANTES de truncar. Truncar primeiro deixa pedaço de segredo irreconhecível."""
    s = sanitize_text(text)
    if not isinstance(s, str) or len(s) <= max_len:
        return s
    cut = s[:max_len]
    i = cut.rfind("[REDACTED:")
    if i != -1 and "]" not in cut[i:]:
        cut = cut[:i]
    return cut + marker
