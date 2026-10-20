"""Saídas: texto para o terminal, Markdown para PR, JSON e SARIF."""
from __future__ import annotations

import json
import re
from collections import Counter
from urllib.parse import quote

from . import __version__
from .model import SEV_RANK, SEVERITIES
from .rules import RULES, STANDARDS, texts

REPO_URL = "https://github.com/HiveControlAgents/StingWard"

LABEL = {
    "pt": {"critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO", "low": "BAIXO", "info": "INFO"},
    "en": {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"},
}
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[37m"}
GRADE_COLOR = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}

T = {
    "pt": {
        "title": "Auditoria de segurança", "where": "onde", "why": "por quê", "fix": "como corrigir",
        "none": "Nada encontrado. Isso não prova que está seguro, mas os erros mais comuns não estão aqui.",
        "summary": "Resumo", "grade": "Nota", "sources": "Bases consultadas",
        "offline": "modo offline: dependências não foram checadas",
        "pkgs": "{n} pacote(s) verificado(s)", "osv_fail": "OSV.dev não respondeu: dependências não foram checadas",
        "badge": "Selo para o README",
        "verdict_bad": "🔴 Não instale ainda: há problemas graves.",
        "verdict_mid": "🟡 Instale só depois de ler os itens abaixo.",
        "verdict_ok": "🟢 Nada grave encontrado. Leia o código mesmo assim: nenhuma ferramenta pega tudo.",
        "more": "e mais {n} item(ns) de severidade baixa",
    },
    "en": {
        "title": "Security audit", "where": "where", "why": "why", "fix": "how to fix",
        "none": "Nothing found. That does not prove it is safe, but the most common mistakes are not here.",
        "summary": "Summary", "grade": "Grade", "sources": "Sources",
        "offline": "offline mode: dependencies were not checked",
        "pkgs": "{n} package(s) checked", "osv_fail": "OSV.dev did not respond: dependencies were not checked",
        "badge": "README badge",
        "verdict_bad": "🔴 Do not install yet: serious problems found.",
        "verdict_mid": "🟡 Install only after reading the items below.",
        "verdict_ok": "🟢 Nothing serious found. Still read the code: no tool catches everything.",
        "more": "and {n} more low-severity item(s)",
    },
}


def grade(findings):
    c = Counter(f.severity for f in findings)
    if c["critical"]:
        return "F"
    if c["high"] > 2:
        return "D"
    if c["high"]:
        return "C"
    return "B" if c["medium"] else "A"


# Nome de servidor, caminho e trecho vêm do código auditado: sem isso, um ESC[1A apagaria o veredito no terminal.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def _clean(s):
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}", str(s))


def badge_md(g):
    return f"[![stingward: {g}](https://img.shields.io/badge/stingward-{g}-{GRADE_COLOR[g]})]({REPO_URL})"


def verdict(findings, lang):
    worst = max((SEV_RANK[f.severity] for f in findings), default=0)
    key = "verdict_bad" if worst >= SEV_RANK["high"] else "verdict_mid" if worst == SEV_RANK["medium"] else "verdict_ok"
    return T[lang][key]


def _where(f):
    return f"{f.file}:{f.line}" if f.line else f.file


def _sources_line(ctx, lang):
    t = T[lang]
    if ctx.offline:
        return t["offline"]
    if ctx.sources.get("osv_error"):
        return t["osv_fail"]
    parts = [t["pkgs"].format(n=ctx.sources.get("packages", 0))]
    if ctx.sources.get("osv"):
        parts.append("OSV.dev")
    if ctx.sources.get("kev"):
        kv = ctx.sources["kev"]
        parts.append(f"CISA KEV {kv}" if isinstance(kv, str) else "CISA KEV")
    if ctx.sources.get("epss"):
        parts.append("EPSS (FIRST)")
    if ctx.sources.get("nvd"):
        parts.append("NVD")
    return " · ".join(parts)


def counts_line(findings, lang):
    c = Counter(f.severity for f in findings)
    return ", ".join(f"{c[s]} {LABEL[lang][s].lower()}" for s in reversed(SEVERITIES) if c[s])


def text(ctx, findings, lang="pt", color=False, target=None, show_verdict=False, max_low=15):
    t = T[lang]
    out = [f"stingward {__version__} · {t['title']}: {_clean(target or ctx.root)}", f"{t['sources']}: {_sources_line(ctx, lang)}", ""]
    if show_verdict:
        out += [verdict(findings, lang), ""]
    if not findings:
        out.append(t["none"])
    shown_low = 0
    hidden = 0
    for f in findings:
        if f.severity in ("low", "info"):
            shown_low += 1
            if shown_low > max_low:
                hidden += 1
                continue
        title, why, fix = (_clean(x) for x in texts(f.rule, lang, f.params))
        lab = LABEL[lang][f.severity]
        head = f"{ICON[f.severity]} {lab:<8} {title}"
        if color:
            head = f"{COLOR[f.severity]}{head}\033[0m"
        out.append(head)
        out.append(f"   {t['where']}: {_clean(_where(f))}  [{' · '.join([f.rule] + STANDARDS.get(f.rule, []))}]")
        out.append(f"   {t['why']}: {why}")
        out.append(f"   {t['fix']}: {fix}")
        if f.refs:
            out.append(f"   {_clean(f.refs[0])}")
        out.append("")
    if hidden:
        out += [t["more"].format(n=hidden), ""]
    g = grade(findings)
    out.append(f"{t['summary']}: {counts_line(findings, lang) or '0'} · {t['grade']}: {g}")
    out.append(f"{t['badge']}: {badge_md(g)}")
    return "\n".join(out) + "\n"


def markdown(ctx, findings, lang="pt", target=None, show_verdict=False):
    t = T[lang]
    g = grade(findings)
    out = ["<!-- stingward-report -->", f"### {badge_md(g)} {t['title']}", ""]
    if show_verdict:
        out += [verdict(findings, lang), ""]
    if not findings:
        out += [t["none"], ""]
    else:
        out += [f"**{t['summary']}:** {counts_line(findings, lang)} · {t['sources']}: {_sources_line(ctx, lang)}", "",
                "| | | |", "|---|---|---|"]
        for f in findings[:50]:
            title, _, fix = texts(f.rule, lang, f.params)
            out.append(f"| {ICON[f.severity]} {LABEL[lang][f.severity]} | {_esc(title)}<br><sub>{_esc(_where(f))}</sub> | {_esc(fix)} |")
        if len(findings) > 50:
            out.append(f"| | {t['more'].format(n=len(findings) - 50)} | |")
        out.append("")
    out.append(f"<sub>stingward {__version__} · [{REPO_URL.split('//')[1]}]({REPO_URL})</sub>")
    return "\n".join(out) + "\n"


_MD = {"\\": "\\\\", "|": "\\|", "<": "&lt;", ">": "&gt;", "&": "&amp;", "[": "\\[", "]": "\\]", "`": "\\`",
       "*": "\\*", "_": "\\_", "!": "\\!", "\n": " ", "\r": " ", "@": "@&#8203;"}


def _esc(s):
    """Texto do código auditado vira texto puro no comentário do PR: sem imagem, link, HTML ou @menção."""
    return "".join(_MD.get(ch, ch) for ch in _clean(s))


def as_json(ctx, findings, lang="pt"):
    items = []
    for f in findings:
        title, why, fix = texts(f.rule, lang, f.params)
        items.append({"rule": f.rule, "severity": f.severity, "file": f.file, "line": f.line, "title": title,
                      "why": why, "fix": fix, "refs": f.refs, "tags": f.tags, "standards": STANDARDS.get(f.rule, []),
                      "data": {k: v for k, v in f.params.items() if not k.endswith(("_pt", "_en"))}})
    return json.dumps({"tool": "stingward", "version": __version__, "grade": grade(findings),
                       "sources": ctx.sources, "findings": items}, ensure_ascii=False, indent=2) + "\n"


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def sarif(ctx, findings, lang="pt", prefix=""):
    """prefix: caminho da pasta auditada dentro do repositório, para os alertas do GitHub apontarem o arquivo certo."""
    first = {}
    for f in findings:  # já vêm da mais grave para a menos grave
        first.setdefault(f.rule, f)
    rules = []
    for r, f in sorted(first.items()):
        title, why, fix = texts(r, lang, f.params)
        rules.append({"id": r, "name": r, "shortDescription": {"text": title}, "fullDescription": {"text": why},
                      "help": {"text": fix}, "helpUri": f"{REPO_URL}#{r.lower()}",
                      "properties": {"tags": ["security", RULES[r]["group"]] + STANDARDS.get(r, []),
                                     "security-severity": _SARIF_SCORE[f.severity]}})
    results = []
    for f in findings:
        title, why, fix = texts(f.rule, lang, f.params)
        loc = {"physicalLocation": {"artifactLocation": {"uri": quote(prefix + f.file, safe="/")}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({"ruleId": f.rule, "level": _SARIF_LEVEL[f.severity],
                        "message": {"text": f"{title}. {why} {fix}"}, "locations": [loc],
                        "properties": {"security-severity": _SARIF_SCORE[f.severity], "tags": f.tags}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "stingward", "version": __version__, "informationUri": REPO_URL, "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
