"""Segredos no código e arquivos .env no git. Usa os padrões do motor de mascaramento (_redact)."""
from __future__ import annotations

import base64
import fnmatch
import json
import re
import subprocess

from .. import _redact as cv
from ..model import Finding
from . import is_text_source

# Formatos que identificam o serviço com certeza: severidade crítica.
_CRITICAL = {"private_key", "aws_access_key", "github_token", "slack_token", "anthropic_key",
             "openai_key", "npm_token"}
_PLACEHOLDER = re.compile(
    r"(?i)example|exemplo|xxxx|\.\.\.|your[_-]?|seu[_-]?|sua[_-]?|placeholder|dummy|fake|redacted|changeme|"
    r"\*{3,}|0{8,}|<[^>]*>|\$\{|\{\{|process\.env|os\.environ|getenv|import\.meta\.env")
_ASSIGN = re.compile(r"""(?P<key>[A-Za-z_][\w.-]{1,63})["']?\s*(?::|=|:=|=>)\s*(?P<q>["'`])(?P<val>[^"'`\s]{8,200})(?P=q)""")
KIND = {
    "private_key": ("chave privada", "private key"), "aws_access_key": ("chave de acesso AWS", "AWS access key"),
    "github_token": ("token do GitHub", "GitHub token"), "slack_token": ("token do Slack", "Slack token"),
    "anthropic_key": ("chave da API da Anthropic", "Anthropic API key"), "openai_key": ("chave da API da OpenAI", "OpenAI API key"),
    "stripe_key": ("chave do Stripe", "Stripe key"), "google_api_key": ("chave de API do Google", "Google API key"),
    "meta_token": ("token da Meta/Facebook", "Meta/Facebook token"), "twilio_key": ("chave do Twilio", "Twilio key"),
    "npm_token": ("token do npm", "npm token"), "discord_webhook": ("webhook do Discord", "Discord webhook"),
    "slack_webhook": ("webhook do Slack", "Slack webhook"), "url_password": ("senha dentro de URL", "password in URL"),
    "jwt": ("token JWT", "JWT"),
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
    except (IndexError, ValueError, AttributeError):
        return None


def scan_text(text: str, rel: str, generic: bool = True):
    """Achados de segredo num texto. Nunca guarda o valor, só o tipo e a linha."""
    low_conf = bool(re.search(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|examples?|mocks?|docs?)(/|$)|\.(test|spec)\.", rel))
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000 or "stingward:ignore" in line:
            continue
        spans = []
        for kind, rx in cv._TOKEN_PATTERNS:
            for m in rx.finditer(line):
                val = m.group(0)
                if any(a < m.end() and m.start() < b for a, b in spans):
                    continue
                spans.append(m.span())
                if _PLACEHOLDER.search(val) or (kind != "private_key" and len(set(val)) < 6):
                    continue
                if kind == "jwt":
                    role = _jwt_role(val)
                    if role == "service_role":
                        out.append(Finding("SEC004", "critical", rel, n))
                    elif role not in ("anon", "authenticated") and not low_conf:
                        out.append(Finding("SEC001", "medium", rel, n, _kind("jwt")))
                    continue
                sev = "critical" if kind in _CRITICAL else "high"
                if kind == "stripe_key":
                    sev = "critical" if "_live_" in val else "low"
                if kind == "google_api_key":
                    sev = "medium"  # chaves do Firebase/Maps são públicas por desenho, mas vale restringir
                if low_conf:
                    sev = "low"
                out.append(Finding("SEC001", sev, rel, n, _kind(kind)))
        for rx, kind in ((cv._DISCORD_HOOK, "discord_webhook"), (cv._SLACK_HOOK, "slack_webhook")):
            if rx.search(line) and not _PLACEHOLDER.search(line):
                out.append(Finding("SEC001", "low" if low_conf else "high", rel, n, _kind(kind)))
        for m in cv._URL_CREDS.finditer(line):
            pw = m["pw"]
            if _PLACEHOLDER.search(pw) or pw.lower() in {"password", "pass", "senha", "postgres", "root", "admin", "secret", "user"} or pw.startswith("$"):
                continue
            out.append(Finding("SEC001", "low" if low_conf else "high", rel, n, _kind("url_password")))
        if not generic:
            continue
        for m in _ASSIGN.finditer(line):
            key, val = m["key"].rsplit(".", 1)[-1], m["val"]
            if not cv.is_sensitive_key(key) or _PLACEHOLDER.search(val) or cv._PH_RE.search(val):
                continue
            if cv._entropy(val) < 3.3 or not re.search(r"\d", val) or re.fullmatch(r"[\w-]+\.(?:js|ts|py|json|html)", val):
                continue
            if any(f.line == n for f in out):
                continue
            out.append(Finding("SEC001", "low" if low_conf else "high", rel, n, _kind(None, key)))
    return out


def _ignored_by_gitignore(ctx, rel: str) -> bool:
    if ctx.git_tracked is not None:
        try:
            r = subprocess.run(["git", "-C", ctx.root, "check-ignore", "-q", rel], capture_output=True, timeout=10)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
    name = rel.rsplit("/", 1)[-1]
    patterns = [p.strip() for p in ctx.read(".gitignore").splitlines() if p.strip() and not p.startswith("#")]
    return any(fnmatch.fnmatch(name, p.lstrip("/")) or fnmatch.fnmatch(rel, p.lstrip("/")) for p in patterns)


def check(ctx):
    findings = []
    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if ENV_NAME.match(name) and not ENV_TEMPLATE.search(name):
            if ctx.mode == "agents":
                continue
            if ctx.git_tracked is not None and rel in ctx.git_tracked:
                findings.append(Finding("SEC002", "high", rel, None, {"name": name}))
            elif not _ignored_by_gitignore(ctx, rel):
                findings.append(Finding("SEC003", "medium", rel, None, {"name": name}))
            continue
        if not is_text_source(rel):
            continue
        findings.extend(scan_text(ctx.read(rel), rel))
    return findings
