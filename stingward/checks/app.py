"""Erros típicos de app feito com IA: chave no front-end, CORS aberto, Supabase sem RLS, Firebase aberto."""
from __future__ import annotations

import re

from ..model import Finding
from . import is_text_source, line_of
from .code import ai_check
from .secrets import drop_inline_ignored

_PUBLIC = re.compile(
    r"(?<![A-Za-z0-9_])(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_|PUBLIC_)([A-Z0-9_]{2,80})")
_SECRET_WORDS = re.compile(
    r"SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD|OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|"
    r"REPLICATE|HUGGING|HF_TOKEN|GEMINI|DEEPSEEK|PERPLEXITY|ELEVENLABS|OPENROUTER|DATABASE_URL|DB_URL|POSTGRES|"
    r"MONGO|REDIS_URL|STRIPE_SK|RESEND|SENDGRID|MAILGUN|TWILIO_AUTH|AWS_SECRET|GITHUB_TOKEN|ADMIN_KEY|ADMIN_TOKEN|API_TOKEN")
_SAFE_WORDS = re.compile(r"ANON|PUBLISHABLE|PUBLIC_KEY|SITE_KEY|CLIENT_ID|MEASUREMENT|_URL$|_MODEL$|_ID$|_REGION$|_ENDPOINT$|_HOST$|_ENABLED$|_VERSION$")
_DB_URL = re.compile(r"DATABASE_URL|DB_URL|POSTGRES|MONGO|REDIS_URL")

_BROWSER_AI = re.compile(r"dangerouslyAllowBrowser\s*:\s*true")

_CORS = [
    re.compile(r"""Access-Control-Allow-Origin['"]?\s*[,:=]\s*['"]\*['"]""", re.I),
    re.compile(r"""\borigin\s*:\s*(?:['"]\*['"]|true)"""),
    re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]"""),
    re.compile(r"""\bCORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True"""),
    re.compile(r"""\bCORS\(\s*app\s*\)"""),
    re.compile(r"""\bcors\(\s*\)"""),
    re.compile(r"""AllowAnyOrigin\(\)|AllowedOrigins\s*\(\s*["']\*["']"""),
]
_CORS_CRED = re.compile(
    r"""credentials\s*:\s*true|allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|"""
    r"""Access-Control-Allow-Credentials['"]?\s*[,:=]\s*['"]?true|AllowCredentials\(\)""", re.I)

_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_CREATE_TABLE = re.compile(r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?P<name>(?:\"?\w+\"?\.)?\"?\w+\"?)", re.I)
_ENABLE_RLS = re.compile(
    r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?P<name>(?:\"?\w+\"?\.)?\"?\w+\"?)\s+enable\s+row\s+level\s+security", re.I)
_POLICY = re.compile(
    r"\bcreate\s+policy\s+(?P<pname>\"[^\"]+\"|\w+)\s+on\s+(?P<table>[\w.\"]+)(?P<body>[^;]*);", re.I)

_FIREBASE_OPEN = re.compile(r"allow\s+[\w\s,]+:\s*if\s+(?:true\s*;|request\.time\s*<\s*timestamp\.date)")
_RTDB_OPEN = re.compile(r"""["']\.(?:read|write)["']\s*:\s*(?:true|["']true["'])""")

_DEBUG = [
    ("Flask", re.compile(r"\.run\([^)]*\bdebug\s*=\s*True")),
    ("Django", re.compile(r"(?m)^DEBUG\s*=\s*True\b")),
    ("FastAPI/Uvicorn", re.compile(r"uvicorn\.run\((?=[^)]*\breload\s*=\s*True)(?=[^)]*\bhost\s*=\s*['\"]0\.0\.0\.0)")),
]
_JWT_NOVERIFY = re.compile(
    r"""verify_signature["']?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*[=:]\s*\[\s*["']none["']""", re.I)

# Tabela com dado de pessoa ou dinheiro: leitura pública ainda é vazamento. Catálogo (products, prices, posts) não é.
_SENSITIVE_TABLE = re.compile(
    r"user|profile|account|order|payment|message|customer|subscription|invoice|billing|card|address|email|phone|"
    r"session|token|secret|key|credential|password|auth|private|admin|member|employee|patient|medical|health|"
    r"transaction|wallet|chat|conversation|contact|lead|salar|payroll|bank|document|upload|file|note")

_CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".astro", ".py", ".go", ".rb", ".php", ".cs", ".java", ".kt")


def _table(name: str) -> str:
    name = name.replace('"', "").lower()
    return name if "." in name else "public." + name


def _policy_sev(op: str, table: str) -> str:
    if op != "select":
        return "high"
    return "medium" if _SENSITIVE_TABLE.search(_table(table).split(".", 1)[1]) else "low"


def _uses_supabase(ctx) -> bool:
    if any(r.startswith("supabase/") or "/supabase/" in r for r in ctx.files):
        return True
    return any(r.endswith("package.json") and "@supabase/" in ctx.read(r) for r in ctx.files)


def check(ctx):
    out = []
    supabase = None
    sql_tables, sql_rls = {}, set()
    for rel in ctx.files:
        if not is_text_source(rel):
            continue
        name = rel.rsplit("/", 1)[-1]
        text = ctx.read(rel)
        if not text:
            continue

        seen = set()
        is_doc = name.lower().endswith((".md", ".mdx", ".txt", ".rst", ".html"))
        for m in ([] if is_doc else _PUBLIC.finditer(text)):
            var = m.group(0)
            rest = m.group(2)
            if var in seen or not _SECRET_WORDS.search(rest):
                continue
            if _SAFE_WORDS.search(rest) and not _DB_URL.search(rest):
                continue
            seen.add(var)
            out.append(Finding("APP001", "critical", rel, line_of(text, m.start()), {"var": var, "prefix": m.group(1)}))

        is_code = rel.endswith(_CODE_EXT)
        if is_code:
            m = _BROWSER_AI.search(text)
            if m:
                out.append(Finding("APP002", "high", rel, line_of(text, m.start())))
            for rx in _CORS:
                m = rx.search(text)
                if m:
                    if rx.pattern.startswith(r"\borigin") and "cors" not in text.lower():
                        continue
                    cred = bool(_CORS_CRED.search(text))
                    out.append(Finding("APP003", "high" if cred else "medium", rel, line_of(text, m.start()), {
                        "cred_pt": " e com cookies/credenciais" if cred else "",
                        "cred_en": " with credentials" if cred else "",
                        "cred_why_pt": " Com credenciais liberadas, ela age como o usuário logado." if cred else "",
                        "cred_why_en": " With credentials allowed it acts as the signed-in user." if cred else "",
                    }))
                    break
            for fw, rx in _DEBUG:
                m = rx.search(text)
                if m and not re.search(r"(?i)(^|/)(tests?|examples?)/", rel):
                    out.append(Finding("APP007", "medium", rel, line_of(text, m.start()), {"framework": fw}))
            m = _JWT_NOVERIFY.search(text)
            if m:
                out.append(Finding("APP008", "high", rel, line_of(text, m.start())))

        if name.endswith(".rules") or name in ("firestore.rules", "storage.rules"):
            for m in _FIREBASE_OPEN.finditer(text):
                out.append(Finding("APP006", "high", rel, line_of(text, m.start())))
        if name == "database.rules.json":
            m = _RTDB_OPEN.search(text)
            if m:
                out.append(Finding("APP006", "high", rel, line_of(text, m.start())))

        if name.endswith(".sql"):
            if supabase is None:
                supabase = _uses_supabase(ctx)
            if not supabase:
                continue
            clean = _SQL_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
            for m in _CREATE_TABLE.finditer(clean):
                t = _table(m["name"])
                if t.startswith("public.") and t not in sql_tables:
                    sql_tables[t] = (rel, line_of(clean, m.start()))
            for m in _ENABLE_RLS.finditer(clean):
                sql_rls.add(_table(m["name"]))
            for m in _POLICY.finditer(clean):
                body = m["body"].lower()
                if re.search(r"\b(using|with\s+check)\s*\(\s*true\s*\)", body):
                    op = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", body)
                    op = op.group(1) if op else "all"
                    out.append(Finding("APP005", _policy_sev(op, m["table"]), rel,
                                       line_of(clean, m.start()), {"policy": f"{m['pname'].strip(chr(34))} ({op})"}))
    for t, (rel, ln) in sql_tables.items():
        if t not in sql_rls:
            out.append(Finding("APP004", "high", rel, ln, {"table": t.split(".", 1)[1]}))
    # APP009 em diante (IA no código: saída do modelo, prompt de sistema, rota pública) vêm da análise de código.
    return drop_inline_ignored(ctx, out) + ai_check(ctx)
