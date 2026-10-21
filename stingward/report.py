"""Saídas: texto para o terminal, Markdown para PR, JSON e SARIF. O relatório em HTML fica em report_html.py.

Texto, Markdown e HTML juntam achados repetidos (mesma regra, mesmos textos) num item só com todos os lugares e
abrem com o que corrigir primeiro. JSON e SARIF continuam com um registro por achado: são lidos por máquinas.
"""
from __future__ import annotations

import json
import re
import string
from collections import Counter
from urllib.parse import quote

from . import __version__
from .checks import code, secrets
from .model import SEV_RANK, SEVERITIES
from .rules import RULES, STANDARDS, fill, standards, texts

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
        "kev_fail": "CISA KEV não respondeu: uma falha que atacantes já exploram pode aparecer com severidade abaixo da real",
        "osv_partial": "checagem de dependências incompleta: {detail}",
        "too_big": "Fora da auditoria: {n} arquivo(s) acima de {mb} MB não foram lidos: {files}",
        "truncated": "Fora da auditoria: a pasta tem mais de {n} arquivos; a leitura parou aí e o resto não foi lido.",
        "badge": "Selo para o README",
        "verdict_bad": "🔴 Não instale ainda: há problemas graves.",
        "verdict_mid": "🟡 Instale só depois de ler os itens abaixo.",
        "verdict_ok": "🟢 Nada grave encontrado. Leia o código mesmo assim: nenhuma ferramenta pega tudo.",
        "verdict_incomplete": "⚠️ Auditoria incompleta: {why}, então isto não mostra que a skill é segura. Leia o que ficou "
                              "de fora antes de instalar.",
        "why_big": "o limite de {mb} MB deixou {n} arquivo(s) sem ler ({files})", "why_many": "a leitura parou em {n} arquivos",
        "and": " e ",
        "more": "e mais {n} item(ns) de severidade baixa",
        "more_md": "e mais {n} item(ns): {counts}",
        "first": "Corrija primeiro", "and_more": "e mais {n}",
        "client": "Preparado para", "notes": "Parecer do analista", "review": "revisão",
        "reviewed_by": "Revisado por {name}", "reviewed": "Revisado por uma pessoa",
        "reviewed_ai": "Revisado por IA", "notes_ai": "Resumo",
        "status": {"confirmed": "Confirmado", "false_positive": "Alarme falso", "accepted_risk": "Risco aceito",
                   "fixed": "Corrigido", "": "Não revisado"},
        "n_status": {"confirmed": ("{n} confirmado", "{n} confirmados"),
                     "false_positive": ("{n} alarme falso descartado", "{n} alarmes falsos descartados"),
                     "accepted_risk": ("{n} risco aceito", "{n} riscos aceitos"),
                     "fixed": ("{n} corrigido durante a auditoria", "{n} corrigidos durante a auditoria"),
                     "": ("{n} ainda não revisado", "{n} ainda não revisados")},
        "discarded": "Descartados como alarme falso ({n})",
        "gone": "Corrigidos durante a auditoria, já fora desta varredura ({n})",
        "grade_rule": "A nota não conta alarmes falsos nem o que foi corrigido durante a auditoria.",
        "sarif_help": "A correção depende do caso: cada alerta diz o que mudar. Mais sobre esta regra: {url}",
        "nothing_read": "Nenhum arquivo foi lido (0 arquivos), então não há o que avaliar e não há nota. Confira o caminho: a pasta "
                        "está vazia ou tudo nela foi pulado (binários, arquivos grandes demais, pastas como node_modules).",
        "nothing_read_agents": "Nenhuma configuração de agente foi encontrada nesta máquina (0 arquivos lidos), então não há o que "
                               "avaliar e não há nota.",
        "summary_none": "Resumo: 0 arquivos lidos · sem nota", "no_grade": "sem nota",
    },
    "en": {
        "title": "Security audit", "where": "where", "why": "why", "fix": "how to fix",
        "none": "Nothing found. That does not prove it is safe, but the most common mistakes are not here.",
        "summary": "Summary", "grade": "Grade", "sources": "Sources",
        "offline": "offline mode: dependencies were not checked",
        "pkgs": "{n} package(s) checked", "osv_fail": "OSV.dev did not respond: dependencies were not checked",
        "kev_fail": "CISA KEV did not respond: a vulnerability attackers already exploit may show a lower severity than it should",
        "osv_partial": "dependency check incomplete: {detail}",
        "too_big": "Not covered: {n} file(s) over {mb} MB were not read: {files}",
        "truncated": "Not covered: the folder has more than {n} files; reading stopped there and the rest was not read.",
        "badge": "README badge",
        "verdict_bad": "🔴 Do not install yet: serious problems found.",
        "verdict_mid": "🟡 Install only after reading the items below.",
        "verdict_ok": "🟢 Nothing serious found. Still read the code: no tool catches everything.",
        "verdict_incomplete": "⚠️ Incomplete audit: {why}, so this does not show the skill is safe. Read what was left out "
                              "before you install it.",
        "why_big": "the {mb} MB size limit left {n} file(s) unread ({files})", "why_many": "reading stopped at {n} files",
        "and": " and ",
        "more": "and {n} more low-severity item(s)",
        "more_md": "and {n} more item(s): {counts}",
        "first": "Fix these first", "and_more": "and {n} more",
        "client": "Prepared for", "notes": "Analyst summary", "review": "review",
        "reviewed_by": "Reviewed by {name}", "reviewed": "Reviewed by a person",
        "reviewed_ai": "Reviewed by AI", "notes_ai": "Summary",
        "status": {"confirmed": "Confirmed", "false_positive": "False positive", "accepted_risk": "Accepted risk",
                   "fixed": "Fixed", "": "Not reviewed"},
        "n_status": {"confirmed": ("{n} confirmed", "{n} confirmed"),
                     "false_positive": ("{n} false positive discarded", "{n} false positives discarded"),
                     "accepted_risk": ("{n} accepted risk", "{n} accepted risks"),
                     "fixed": ("{n} fixed during the audit", "{n} fixed during the audit"),
                     "": ("{n} not reviewed yet", "{n} not reviewed yet")},
        "discarded": "Discarded as false positives ({n})",
        "gone": "Fixed during the audit, no longer in this scan ({n})",
        "grade_rule": "The grade leaves out false positives and what was fixed during the audit.",
        "sarif_help": "The fix depends on the case: each alert says what to change. More about this rule: {url}",
        "nothing_read": "No file was read (0 files), so there is nothing to grade. Check the path: the folder is empty, or "
                        "everything in it was skipped (binary files, files that are too large, folders such as node_modules).",
        "nothing_read_agents": "No agent configuration was found on this machine (0 files read), so there is nothing to grade.",
        "summary_none": "Summary: 0 files read · no grade", "no_grade": "no grade",
    },
}


# Revisão humana. Contam para a nota, o veredito e o --fail-on: confirmados, riscos aceitos e o que ainda não foi
# revisado. Alarme falso e o que foi corrigido e conferido durante a auditoria não contam. "Corrija primeiro" e as
# faixas do plano só têm o que ainda é para fazer: confirmados e não revisados.
STATUS_ORDER = ("confirmed", "false_positive", "accepted_risk", "fixed", "")   # ordem das contagens
_GROUP = {"": 0, "confirmed": 0, "accepted_risk": 1, "fixed": 2, "false_positive": 3}  # ordem dos itens
TODO = ("", "confirmed")
NOT_COUNTED = ("false_positive", "fixed")


def counted(findings, review=None):
    """Os achados que valem para a nota depois da revisão."""
    if review is None:
        return list(findings)
    return [f for f in findings if review.status(f) not in NOT_COUNTED]


def review_parts(findings, review, lang):
    """["14 confirmados", "2 alarmes falsos descartados"]: só os status que aparecem."""
    from .review import counts
    c = counts(findings, review)
    forms = T[lang]["n_status"]
    return [(forms[k][0] if c[k] == 1 else forms[k][1]).format(n=c[k]) for k in STATUS_ORDER if c[k]]


def review_counts(findings, review, lang):
    return ", ".join(review_parts(findings, review, lang))


def nothing_read(ctx, findings):
    """Nenhum arquivo lido e nada achado: não há o que avaliar. Pasta vazia, caminho errado ou checkout esquecido no CI
    não podem sair como um A limpo, com selo e veredito verde."""
    return not ctx.files and not findings


def nothing_read_text(ctx, lang):
    return T[lang]["nothing_read_agents" if ctx.mode == "agents" else "nothing_read"]


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
# A quebra de linha também (\n, U+2028, U+2029): um arquivo chamado "x\nResumo: 0 · Nota: A" criaria uma linha falsa.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _clean(s):
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}", str(s))


def shown_target(target):
    """O alvo como a pessoa digitou, sem credencial: https://x-access-token:<token>@github.com/... (skill privada) sai
    com o token mascarado no texto e na capa do HTML."""
    return secrets.mask(str(target))


def badge_md(g):
    return f"[![stingward: {g}](https://img.shields.io/badge/stingward-{g}-{GRADE_COLOR[g]})]({REPO_URL})"


def verdict(findings, lang, ctx=None):
    """O veredito de `stingward skill`. Com arquivo sem ler (ctx), "nada grave" e "leia os itens abaixo" viram "auditoria
    incompleta": o que não foi lido pode ser justamente o que a skill faz. Problema grave continua com o veredito grave.
    A nota não muda: ela é das severidades encontradas."""
    worst = max((SEV_RANK[f.severity] for f in findings), default=0)
    key = "verdict_bad" if worst >= SEV_RANK["high"] else "verdict_mid" if worst == SEV_RANK["medium"] else "verdict_ok"
    if key != "verdict_bad" and incomplete(ctx):
        return incomplete_verdict(ctx, lang)
    return T[lang][key]


def incomplete(ctx):
    """A varredura deixou arquivos sem ler: acima do limite de tamanho ou depois do limite de arquivos."""
    return ctx is not None and bool(ctx.too_big or ctx.truncated)


def incomplete_verdict(ctx, lang):
    """O veredito de auditoria incompleta, com o limite e os arquivos. Os nomes saem crus: cada formato limpa ou escapa."""
    from . import scan
    t, why = T[lang], []
    if ctx.too_big:
        why.append(t["why_big"].format(mb=size_cap(ctx.mode) // 1_000_000, n=len(ctx.too_big), files=_file_list(ctx.too_big, lang)))
    if ctx.truncated:
        why.append(t["why_many"].format(n=thousands(scan.MAX_FILES, lang)))
    return t["verdict_incomplete"].format(why=t["and"].join(why))


def _where(f):
    return f"{f.file}:{f.line}" if f.line else f.file


def _sources_line(ctx, lang):
    t = T[lang]
    if ctx.offline:
        return t["offline"]
    if ctx.sources.get("osv_error") and not ctx.sources.get("osv"):
        return t["osv_fail"]
    parts = [t["pkgs"].format(n=ctx.sources.get("packages", 0))]
    if ctx.sources.get("osv"):
        parts.append("OSV.dev")
    if osv_partial(ctx):  # respondeu, mas faltaram detalhes de alguns avisos: a mensagem vem de checks/deps.py
        parts.append(t["osv_partial"].format(detail=_clean(ctx.sources["osv_error"])))
    if ctx.sources.get("kev"):
        kv = ctx.sources["kev"]
        parts.append(f"CISA KEV {_clean(kv)}" if isinstance(kv, str) else "CISA KEV")  # a versão vem da rede
    elif ctx.sources.get("kev_error"):  # sem a KEV, uma falha explorada agora não sobe para crítica
        parts.append(t["kev_fail"])
    if ctx.sources.get("epss"):
        parts.append("EPSS (FIRST)")
    if ctx.sources.get("nvd"):
        parts.append("NVD")
    return " · ".join(parts)


def size_cap(mode):
    """O limite de tamanho de arquivo da varredura neste modo, em bytes (scan.list_files)."""
    from . import scan
    return scan.SKILL_MAX_BYTES if mode == "skill" else scan.MAX_BYTES


def not_read_lines(ctx, lang, limit=5):
    """O que a varredura deixou sem ler, em frases curtas: código e texto acima do limite de tamanho e o resto da pasta
    depois do limite de arquivos. Os nomes vêm do projeto auditado e saem crus: cada formato limpa ou escapa a frase."""
    from . import scan
    t, out = T[lang], []
    if ctx.too_big:
        out.append(t["too_big"].format(n=len(ctx.too_big), mb=size_cap(ctx.mode) // 1_000_000, files=_file_list(ctx.too_big, lang, limit)))
    if ctx.truncated:
        out.append(t["truncated"].format(n=thousands(scan.MAX_FILES, lang)))
    return out


def _file_list(files, lang, limit=5):
    """a.js, b.js e mais 3: os primeiros pelo nome, como no stderr."""
    extra = len(files) - limit
    return ", ".join(files[:limit]) + (" " + T[lang]["and_more"].format(n=extra) if extra > 0 else "")


def thousands(n, lang):
    """50.000 em português, 50,000 em inglês."""
    text = f"{n:,}"
    return text.replace(",", ".") if lang == "pt" else text


def osv_partial(ctx):
    """O OSV.dev respondeu, mas a checagem ficou incompleta (osv e osv_error juntos): não é o mesmo que não responder."""
    return bool(ctx.sources.get("osv") and ctx.sources.get("osv_error"))


def source_failed(ctx):
    """Alguma base não respondeu (OSV ou KEV): o relatório diz isso mesmo quando não há achado."""
    return not ctx.offline and bool(ctx.sources.get("osv_error") or ctx.sources.get("kev_error"))


def counts_line(findings, lang):
    c = Counter(f.severity for f in findings)
    # "2 críticos", "1 alto": em português o rótulo concorda com o número; em inglês ele funciona como adjetivo.
    plural = lambda s: "s" if lang == "pt" and c[s] > 1 and s != "info" else ""
    return ", ".join(f"{c[s]} {LABEL[lang][s].lower()}{plural(s)}" for s in reversed(SEVERITIES) if c[s])


# --------------------------------------------------------------------------- itens: achados repetidos juntos

class Entry:
    """Um problema do relatório: achados com a mesma regra, os mesmos textos e a mesma severidade, em um ou mais lugares."""

    def __init__(self, finding, title, why, fix, status="", comment=""):
        self.rule, self.severity = finding.rule, finding.severity
        self.title, self.why, self.fix = title, why, fix
        self.status, self.comment = status, comment  # da revisão humana; vazio sem revisão
        self.findings = [finding]

    @property
    def params(self):
        return self.findings[0].params

    @property
    def group(self):
        return RULES[self.rule]["group"]

    @property
    def places(self):
        return [_where(f) for f in self.findings]

    @property
    def refs(self):
        out = []
        for r in (r for f in self.findings for r in f.refs):
            if r not in out:
                out.append(r)
        return out


# Ordem dos itens, de "corrija primeiro" e do plano: depois da severidade, o que um atacante aproveita mais rápido.
# 0 falha com ataque em uso (KEV); 1 chave ou segredo exposto, que qualquer um usa sem esforço; 2 execução de código
# ou comando, que entrega o servidor ou a máquina; 3 acesso aberto aos dados; 4 o resto. No empate, a ordem da
# varredura: regra, arquivo e linha. Por regra ou prefixo; regra sem entrada fica no fim (4).
PRIORITY = {
    "SEC": 1, "APP001": 1, "APP002": 1,
    "COD002": 2, "COD003": 2, "COD004": 2, "APP012": 2, "APP013": 2, "AGT002": 2, "SKL002": 2, "SKL009": 2, "SKL011": 2,
    "APP004": 3, "APP005": 3, "APP006": 3, "APP008": 3, "COD001": 3,
}
# APP009 e APP014 dependem de onde chega o que o modelo escreveu.
PRIORITY_BY_SINK = {
    "APP009": {"code": 2, "shell": 2, "template": 2, "sql": 3},
    "APP014": {"shell": 2, "code": 2, "template": 2, "deserialize": 2, "sql": 3},
}
_LLM_KIND = {v[1]: k for k, v in code._LLM_SINK.items()}  # a APP009 guarda o destino só como texto: "a shell command"


def priority(entry):
    if any("kev" in f.tags for f in entry.findings):
        return 0
    by_sink = PRIORITY_BY_SINK.get(entry.rule)
    if by_sink is not None:
        return by_sink.get(entry.params.get("kind") or _LLM_KIND.get(entry.params.get("sink_en"), ""), 4)
    return PRIORITY.get(entry.rule, PRIORITY.get(entry.rule[:3], 4))


def merge(findings, lang, review=None):
    """Mesma regra e mesmo título viram um item só, do pior para o menos grave e, na mesma severidade, pela PRIORITY.

    O "por quê" e o "como corrigir" também entram na chave: na SKL001 o "por quê" traz a mensagem escondida, e
    duas mensagens diferentes não podem virar uma. A severidade também: o mesmo segredo dentro de tests/ fica baixo
    e não pode aparecer como crítico ao lado do achado real. Com revisão, o status e o comentário também: um lugar
    confirmado e outro descartado são dois itens."""
    entries, index = [], {}
    for f in findings:
        title, why, fix = texts(f.rule, lang, f.params)
        status, comment = review.get(f) if review is not None else ("", "")
        key = (f.rule, f.severity, title, why, fix, status, comment)
        if key in index:
            index[key].findings.append(f)
        else:
            index[key] = Entry(f, title, why, fix, status, comment)
            entries.append(index[key])
    entries.sort(key=lambda e: (-SEV_RANK[e.severity], priority(e)))  # estável: o empate fica na ordem da varredura
    return entries


def split(entries):
    """(itens do relatório, alarmes falsos). Primeiro o que ainda é para fazer, depois riscos aceitos e o que já foi
    corrigido, cada grupo do pior para o menos grave. Alarmes falsos vão para o apêndice."""
    shown = sorted((e for e in entries if e.status != "false_positive"), key=lambda e: _GROUP[e.status])
    return shown, [e for e in entries if e.status == "false_positive"]


def places(entry, lang, limit=10):
    """Todos os lugares até o limite, depois "e mais N": a.js:1, b.js:4 e mais 3."""
    shown = ", ".join(entry.places[:limit])
    extra = len(entry.places) - limit
    return shown + (" " + T[lang]["and_more"].format(n=extra) if extra > 0 else "")


def _first_place(entry):
    n = len(entry.findings)
    return entry.places[0] + (f" (+{n - 1})" if n > 1 else "")


def urgent(entries, n=3):
    """Os primeiros itens críticos ou altos que ainda são para fazer: o que corrigir antes de tudo."""
    return [e for e in entries if e.status in TODO and SEV_RANK[e.severity] >= SEV_RANK["high"]][:n]


def _fix_first(entries):
    # Se a lista inteira cabe no bloco, ele só repetiria os itens logo abaixo.
    top = urgent(entries)
    return top if len(entries) > len(top) else []


# Esforço aproximado para corrigir, por regra ou pelo prefixo dela. Regra nova sem entrada cai no padrão.
EFFORT = {
    "DEP": "hours", "DEP003": "quick",
    "SEC": "hours", "SEC003": "quick",
    "APP": "hours", "APP003": "quick", "APP007": "quick", "APP008": "quick",
    "AGT": "quick",
    "SKL": "quick", "SKL004": "hours", "SKL007": "hours", "SKL011": "hours",
    "COD": "hours", "COD006": "quick", "COD010": "quick", "COD011": "days",
    "APP012": "quick",
}
DEFAULT_EFFORT = "hours"


def _major(version):
    m = re.match(r"\D*(\d+)", str(version or ""))
    return int(m.group(1)) if m else None


def effort(rule, params=None):
    """quick, hours ou days. Pacote sem versão corrigida, ou cuja correção muda a versão major, leva dias: tem teste."""
    if rule == "DEP001" and params is not None:
        fixed = params.get("fixed")
        if not fixed or _major(fixed) != _major(params.get("version")):
            return "days"
    return EFFORT.get(rule) or EFFORT.get(rule[:3]) or DEFAULT_EFFORT


# O que um atacante (ou a fatura) consegue fazer, em uma ou duas frases, para o resumo de quem não é da área.
# Por regra ou prefixo; sem entrada, vale o "por quê" da regra.
IMPACT = {
    "DEP001": ("Esta versão de {pkg} tem uma falha pública e documentada: quem ataca não precisa descobrir nada, só reaproveitar um ataque pronto.{exploit}",
               "This version of {pkg} has a public, documented flaw: an attacker does not need to discover anything, only reuse a known attack.{exploit}"),
    "DEP002": ("O pacote foi feito para roubar dados ou rodar código de um atacante: toda máquina e servidor que o instalou pode já ter entregado as chaves.",
               "The package was built to steal data or run an attacker's code: every machine and server that installed it may already have handed over its keys."),
    "SEC": ("Quem vê o código ou o histórico do git pode usar essa credencial como se fosse você: gastar seu dinheiro, ler seus dados ou agir em seu nome.",
            "Anyone who sees the code or its git history can use this credential as you: spend your money, read your data or act in your name."),
    "SEC002": ("Toda cópia do repositório leva as chaves desse arquivo, inclusive clones e forks antigos que você não controla mais.",
               "Every copy of the repository carries the keys in this file, including old clones and forks you no longer control."),
    "SEC003": ("Um git add descuidado publica as chaves desse arquivo junto com o código.",
               "One careless git add publishes the keys in this file along with the code."),
    "SEC004": ("Quem tiver essa chave lê, altera e apaga o banco inteiro, passando por cima de todas as regras de acesso.",
               "Anyone with this key can read, change and delete the whole database, skipping every access rule."),
    "APP001": ("Qualquer visitante do site pode copiar {var} e usar como se fosse você: estourar a fatura do serviço ou chegar aos dados que a chave protege.",
               "Any visitor to your site can copy {var} and use it as you: run up the bill for that service or reach the data the key protects."),
    "APP002": ("Qualquer pessoa copia a chave de IA no navegador e usa a sua conta até estourar a fatura ou a cota.",
               "Anyone can copy the AI key from the browser and use your account until the bill or the quota runs out."),
    "APP003": ("Uma página de qualquer outro site consegue chamar a sua API pelo navegador dos seus visitantes.{cred_why}",
               "A page on any other website can call your API from your visitors' browsers.{cred_why}"),
    "APP004": ("Qualquer pessoa com a chave anon, que vai junto com o app, lê e altera todas as linhas de {table}, inclusive dados de outros usuários.",
               "Anyone with the anon key, which ships inside your app, can read and change every row of {table}, other users' data included."),
    "APP005": ("Qualquer pessoa, logada ou não, faz o que essa política permite ({policy}), então um usuário chega aos dados dos outros.",
               "Anyone, signed in or not, can do what this policy allows ({policy}), so one user can reach everyone else's data."),
    "APP006": ("Qualquer pessoa lê, altera ou apaga os dados e arquivos do seu Firebase.",
               "Anyone can read, change or delete the data and files in your Firebase."),
    "APP007": ("Quando algo falha em produção, o visitante vê código e configurações e, às vezes, ganha um console que roda comandos no servidor.",
               "When something fails in production, visitors see code and settings, and sometimes get a console that runs commands on the server."),
    "APP008": ("Qualquer pessoa monta um token dizendo que é outro usuário, ou admin, e o servidor aceita.",
               "Anyone can make a token that says they are another user, or an admin, and the server accepts it."),
    "AGT001": ("Uma instrução escondida em qualquer arquivo, issue ou página que o agente leia pode rodar comandos na sua máquina sem perguntar: apagar arquivos ou mandar suas chaves para fora.",
               "A hidden instruction in any file, issue or page the agent reads can run commands on your machine without asking: delete files or send your keys out."),
    "AGT002": ("Quem controla aquele endereço roda código na sua máquina toda vez que o hook dispara ou o servidor MCP inicia.",
               "Whoever controls that address runs code on your machine every time the hook fires or the MCP server starts."),
    "AGT003": ("Se alguém tomar conta desse pacote, na próxima vez que o agente iniciar ele roda o código dessa pessoa com o seu acesso.",
               "If someone takes over that package, the next time the agent starts it runs their code with your access."),
    "AGT004": ("Quem vir esse arquivo de configuração, no repositório, num backup ou numa cópia, pode usar a credencial.",
               "Anyone who sees this config file, in the repository, in a backup or in a copy, can use the credential."),
    "AGT005": ("Quem estiver na mesma rede, como um Wi-Fi público, lê os tokens enviados a esse servidor.",
               "Anyone on the same network, such as public Wi-Fi, can read the tokens sent to this server."),
    "AGT006": ("Abrir um repositório clonado já liga os servidores MCP que ele declarar, com o seu acesso.",
               "Opening a cloned repository is enough to start the MCP servers it declares, with your access."),
    "SKL": ("Esse conteúdo pode virar o agente contra você: rodar comandos, ler suas chaves ou mandar dados para fora sem você perceber.",
            "This content can turn the agent against you: run commands, read your keys or send data out without you noticing."),
    "SKL001": ("O texto leva instruções que você não vê, mas a IA lê e pode seguir.",
               "The text carries instructions you cannot see but the AI reads and may follow."),
    "SKL002": ("O que estiver naquele endereço roda na sua máquina, e pode mudar depois que você revisou.",
               "Whatever is at that address runs on your machine, and it can change after you review it."),
    "SKL004": ("Suas chaves de SSH, de nuvem ou de APIs podem ser lidas e enviadas para outra pessoa.",
               "Your SSH, cloud or API keys can be read and sent to someone else."),
    "SKL008": ("Dados da sua máquina vão para um receptor anônimo que qualquer pessoa cria em segundos.",
               "Data from your machine goes to an anonymous receiver anyone can set up in seconds."),
    "SKL009": ("Código roda na sua máquina assim que o pacote é instalado, antes de você usar.",
               "Code runs on your machine as soon as the package is installed, before you use it."),
    "SKL011": ("Quem estiver do outro lado ganha um terminal no seu computador.",
               "Whoever is on the other end gets a terminal on your computer."),
    "COD001": ("Quem ataca lê, altera ou apaga o banco de dados inteiro só mandando um texto montado na requisição, inclusive senhas e dados de outros clientes.",
               "An attacker can read, change or delete the whole database just by sending crafted text in a request, other customers' data and passwords included."),
    "COD002": ("Quem ataca roda qualquer comando no seu servidor: rouba as chaves do ambiente, apaga dados ou instala um programa dele.",
               "An attacker can run any command on your server: steal the keys in its environment, delete data or install their own software."),
    "COD003": ("Quem ataca roda o código que quiser dentro do seu app, com acesso a tudo o que ele acessa.",
               "An attacker can run any code inside your app, with access to everything it can reach."),
    "COD004": ("Um arquivo ou uma requisição preparada por alguém de fora basta para rodar comandos no servidor quando os dados são carregados.",
               "A file or request crafted by an outsider is enough to run commands on the server when the data is loaded."),
    "COD005": ("Um texto com script roda no navegador de quem abre a página: dá para roubar a sessão e agir como aquela pessoa no seu app.",
               "Text carrying a script runs in the browser of whoever opens the page: it can steal their session and act as them in your app."),
    "COD006": ("Quem estiver no caminho da conexão, como um Wi-Fi público, lê e altera o que o servidor manda e recebe, tokens incluídos.",
               "Anyone on the connection path, such as public Wi-Fi, can read and change what the server sends and receives, tokens included."),
    "COD007": ("Um nome de arquivo como ../../.env deixa qualquer pessoa ler as chaves do servidor ou sobrescrever arquivos dele.",
               "A file name like ../../.env lets anyone read the server's keys or overwrite its files."),
    "COD008": ("Qualquer pessoa usa o seu servidor para chegar à rede interna e à nuvem, onde costumam estar credenciais com acesso a tudo.",
               "Anyone can use your server to reach the internal network and the cloud, where credentials with broad access usually live."),
    "COD009": ("Um link com o endereço do seu site leva as pessoas para uma página falsa, e o seu nome dá credibilidade ao golpe.",
               "A link with your site's address sends people to a fake page, and your name makes the scam believable."),
    "COD010": ("Quem ataca consegue adivinhar o próximo token ou código e entrar em contas que não são dele.",
               "An attacker can guess the next token or code and get into accounts that are not theirs."),
    "COD011": ("Se o banco vazar, as senhas são descobertas em pouco tempo, e quem repete a senha em outros sites perde essas contas também.",
               "If the database leaks, the passwords are cracked quickly, and people who reuse them lose those other accounts too."),
    "APP009": ("Uma instrução escondida numa página, num arquivo ou numa mensagem que o modelo leia vira comando no seu servidor ou no navegador dos seus usuários.",
               "A hidden instruction in any page, file or message the model reads becomes a command on your server or in your users' browsers."),
    "APP010": ("Qualquer usuário reescreve as regras do seu assistente: tira os limites, vaza o prompt ou faz o modelo agir contra os seus clientes.",
               "Any user can rewrite your assistant's rules: remove its limits, leak the prompt or turn the model against your customers."),
    "APP011": ("Qualquer pessoa que achar essa URL usa a sua conta de IA sem limite: a fatura dispara e o seu app vira um proxy de IA de graça.",
               "Anyone who finds this URL can use your AI account without limit: the bill spikes and your app becomes a free AI proxy."),
    "APP012": ("Baixar ou carregar o modelo roda o código de quem o publicou, com acesso à sua máquina e às suas chaves.",
               "Downloading or loading the model runs its publisher's code, with access to your machine and your keys."),
    "APP013": ("Uma prompt injection vira execução de código: o que o modelo escrever roda na sua máquina ou no seu servidor.",
               "A prompt injection becomes code execution: whatever the model writes runs on your machine or server."),
    "APP014": ("Uma instrução escondida em qualquer página, arquivo ou mensagem que o modelo leia faz esta ferramenta {impact}.",
               "A hidden instruction in any page, file or message the model reads makes this tool {impact}."),
    "DEP004": ("Sem lockfile, uma instalação pode ficar com {pkg} {floor}, que tem falhas públicas com ataque pronto. Subir o mínimo da faixa fecha essa porta.{exploit}",
               "Without a lockfile, an install can stay on {pkg} {floor}, which has public flaws with ready-made attacks. Raising the range's minimum closes that door.{exploit}"),
}


def impact(entry, lang):
    spec = IMPACT.get(entry.rule) or IMPACT.get(entry.rule[:3])
    if not spec:
        return entry.why
    return fill(spec[0] if lang == "pt" else spec[1], lang, entry.params)


# --------------------------------------------------------------------------- texto e Markdown

def _status_tag(e, lang):
    return f" [{T[lang]['status'][e.status]}]"


def _review_head(audit, findings, lang):
    """Cliente, quem revisou e as contagens: o que aparece no topo do texto e do Markdown."""
    t, out = T[lang], []
    if audit is None:
        return out
    if audit.client:
        out.append((t["client"], audit.client))
    if audit.review is not None:
        who = (t["reviewed_by"].format(name=audit.reviewer) if audit.reviewer
               else t["reviewed_ai"] if audit.review.kind == "ai" else t["reviewed"])
        out.append((who, review_counts(findings, audit.review, lang) or "0"))
    return out


def _notes_label(audit, t):
    """O título do parecer: "Resumo" quando quem revisou foi uma IA."""
    return t["notes_ai"] if audit.review is not None and audit.review.kind == "ai" else t["notes"]


def text(ctx, findings, lang="pt", color=False, target=None, show_verdict=False, max_low=15, audit=None):
    t = T[lang]
    rv = audit.review if audit else None
    valid = counted(findings, rv)
    shown, discarded = split(merge(findings, lang, rv))
    empty = nothing_read(ctx, findings)
    out = [f"stingward {__version__} · {t['title']}: {_clean(shown_target(target or ctx.root))}",
           f"{t['sources']}: {_sources_line(ctx, lang)}"]
    out += [_clean(x) for x in not_read_lines(ctx, lang)]
    out += [f"{_clean(k)}: {_clean(v)}" for k, v in _review_head(audit, findings, lang)]
    out.append("")
    if audit and audit.notes:
        out.append(f"{_notes_label(audit, t)}:")
        from .review import plain
        out += [f"  {_clean(line)}" if line else "" for line in plain(audit.notes, gap=True)]
        out.append("")
    if show_verdict and not empty:
        out += [_clean(verdict(valid, lang, ctx)), ""]
    first = _fix_first(shown)
    if first:
        out.append(f"{t['first']}:")
        out += [f" {i}. {ICON[e.severity]} {_clean(e.title)} · {_clean(_first_place(e))}" for i, e in enumerate(first, 1)]
        out.append("")
    if empty:
        out.append("⚠️ " + nothing_read_text(ctx, lang))
    elif not shown:
        out.append(t["none"])
    shown_low = 0
    hidden = 0
    for e in shown:
        if e.severity in ("low", "info"):
            shown_low += 1
            if shown_low > max_low:
                hidden += 1
                continue
        title, why, fix = (_clean(x) for x in (e.title, e.why, e.fix))
        lab = LABEL[lang][e.severity]
        head = f"{ICON[e.severity]} {lab:<8} {title}" + (_status_tag(e, lang) if rv is not None else "")
        if color:
            head = f"{COLOR[e.severity]}{head}\033[0m"
        out.append(head)
        out.append(f"   {t['where']}: {_clean(places(e, lang))}  [{' · '.join([e.rule] + standards(e.rule, e.params))}]")
        out.append(f"   {t['why']}: {why}")
        out.append(f"   {t['fix']}: {fix}")
        if e.refs:
            out.append(f"   {_clean(e.refs[0])}")
        out += _comment_lines(audit, e, lang)
        out.append("")
    if hidden:
        out += [t["more"].format(n=hidden), ""]
    gone = audit.gone if audit else []
    if gone:  # do arquivo de revisão: o problema foi corrigido e sumiu da varredura
        if not shown:
            out.append("")  # depois de "Nada encontrado."
        out.append(t["gone"].format(n=len(gone)) + ":")
        for e in gone:
            out.append(f" - {ICON[e.severity]} {_clean(e.title)}" + (f" · {_clean(e.where)}" if e.where else "")
                       + (f"  [{e.rule}]" if e.rule else ""))
            out += _comment_lines(audit, e, lang, label=False)
        out.append("")
    if discarded:
        out.append(t["discarded"].format(n=sum(len(e.findings) for e in discarded)) + ":")
        for e in discarded:
            out.append(f" - {_clean(e.title)} · {_clean(places(e, lang))}  [{e.rule}]")
            out += _comment_lines(audit, e, lang, label=False)
        out.append("")
    if empty:  # sem nota e sem selo
        out.append(t["summary_none"])
        return "\n".join(out) + "\n"
    g = grade(valid)
    out.append(f"{t['summary']}: {counts_line(valid, lang) or '0'} · {t['grade']}: {g}")
    if rv is not None:
        out.append(t["grade_rule"])
    if ctx.mode != "agents":  # a auditoria da própria máquina não tem README onde pôr o selo
        out.append(f"{t['badge']}: {badge_md(g)}")
    return "\n".join(out) + "\n"


def _comment_lines(audit, e, lang, label=True):
    """O comentário de quem revisou, embaixo do item. label: começa com "revisão: <status>" (no apêndice não precisa)."""
    if audit is None or audit.review is None:
        return []
    from .review import plain
    lines = [_clean(x) for x in plain(audit.comment(e.comment))]
    if not label:
        return [f"     {x}" for x in lines]
    head = f"   {T[lang]['review']}: {T[lang]['status'][e.status]}"
    return [head + (f" · {lines[0]}" if lines else "")] + [f"     {x}" for x in lines[1:]]


def _md_inline(nodes):
    out = []
    for style, text in nodes:
        piece = _esc(text)
        if "c" in style:
            piece = f"<code>{piece}</code>"
        if "b" in style:
            piece = f"<b>{piece}</b>"
        out.append(piece)
    return "".join(out)


def _md_blocks(blocks):
    out = []
    for kind, body in blocks:
        if kind == "p":
            out += [_md_inline(body), ""]
        else:
            out += [f"- {_md_inline(item)}" for item in body] + [""]
    return out


def _md_comment(audit, e, lang):
    """O status e o comentário numa linha só, para caber na célula da tabela."""
    parts = [_md_inline(item) for kind, body in audit.comment(e.comment) for item in (body if kind == "ul" else [body])]
    return f"<b>{_esc(T[lang]['status'][e.status])}</b>" + "".join(f" · {p}" for p in parts)


def markdown(ctx, findings, lang="pt", target=None, show_verdict=False, audit=None):
    t = T[lang]
    rv = audit.review if audit else None
    valid = counted(findings, rv)
    g = grade(valid)
    shown, discarded = split(merge(findings, lang, rv))
    empty = nothing_read(ctx, findings)
    plain = empty or ctx.mode == "agents"  # sem nota, ou a própria máquina: sem selo
    out = ["<!-- stingward-report -->", f"### {t['title']}" if plain else f"### {badge_md(g)} {t['title']}", ""]
    head = _review_head(audit, findings, lang)
    if head:
        out += [" · ".join(f"**{_esc(k)}:** {_esc(v)}" for k, v in head), ""]
    if audit and audit.notes:
        out += [f"**{_esc(_notes_label(audit, t))}**", ""] + _md_blocks(audit.notes)
    if show_verdict and not empty:
        out += [_esc(verdict(valid, lang, ctx)), ""]
    unread = [f"⚠️ {_esc(x)}" for x in not_read_lines(ctx, lang)]  # perto da linha das bases, em todo caso
    if empty:
        out += ["⚠️ " + nothing_read_text(ctx, lang), ""] + ([*unread, ""] if unread else [])
    elif not shown:
        out += [t["none"], ""]
        if source_failed(ctx):  # "nada encontrado" com o OSV fora do ar não é um comentário limpo
            out += [f"**{t['sources']}:** {_esc(_sources_line(ctx, lang))}", ""]
        out += [*unread, ""] if unread else []
    else:
        first = _fix_first(shown)
        if first:
            out += [f"**{t['first']}**", ""]
            out += [f"{i}. {ICON[e.severity]} {_esc(e.title)} · <sub>{_esc(_first_place(e))}</sub>" for i, e in enumerate(first, 1)]
            out.append("")
        out += [f"**{t['summary']}:** {counts_line(valid, lang) or '0'} · {t['sources']}: {_esc(_sources_line(ctx, lang))}", ""]
        out += [*unread, ""] if unread else []
        out += ["| | | |", "|---|---|---|"]
        for e in shown[:50]:
            note = f"<br><sub>{_md_comment(audit, e, lang)}</sub>" if rv is not None else ""
            out.append(f"| {ICON[e.severity]} {LABEL[lang][e.severity]} | {_esc(e.title)}<br><sub>{_esc(places(e, lang, limit=5))}</sub>{note} "
                       f"| {_esc(e.fix)} |")
        if len(shown) > 50:  # os que sobram podem ser de qualquer severidade: a linha diz quais são
            rest = shown[50:]
            out.append(f"| | {t['more_md'].format(n=len(rest), counts=counts_line(rest, lang))} | |")
        out.append("")
    gone = audit.gone if audit else []
    if gone:
        out += [f"**{_esc(t['gone'].format(n=len(gone)))}**", ""]
        out += [f"- {ICON[e.severity]} {_esc(e.title)}" + (f" · <sub>{_esc(e.where)}</sub>" if e.where else "")
                + f"<br><sub>{_md_comment(audit, e, lang)}</sub>" for e in gone[:50]]
        out.append("")
    if discarded:
        out += [f"**{_esc(t['discarded'].format(n=sum(len(e.findings) for e in discarded)))}**", ""]
        out += [f"- {_esc(e.title)} · <sub>{_esc(places(e, lang, limit=5))}</sub><br><sub>{_md_comment(audit, e, lang)}</sub>"
                for e in discarded[:50]]
        out.append("")
    if rv is not None:
        out += [f"<sub>{_esc(t['grade_rule'])}</sub>", ""]
    out.append(f"<sub>stingward {__version__} · [{REPO_URL.split('//')[1]}]({REPO_URL})</sub>")
    return "\n".join(out) + "\n"


_MD = {"\\": "\\\\", "|": "\\|", "<": "&lt;", ">": "&gt;", "&": "&amp;", "[": "\\[", "]": "\\]", "`": "\\`",
       "*": "\\*", "_": "\\_", "!": "\\!", "@": "@&#8203;", "\u200b": "&#8203;"}
# O GitHub também faz link de endereço solto (https://..., www....) e de #12 ou dono/repo#3, que ainda aparece na
# issue citada. Um espaço de largura zero depois de ":", "www" e "#" desfaz os três sem mudar o que se lê.
_AUTOLINK = re.compile(r"(?i)(?<=:)(?=//)|(?<=www)(?=\.)|(?<=#)(?=\d)")


def _esc(s):
    """Texto do código auditado vira texto puro no comentário do PR: sem imagem, link, HTML, @menção ou #referência."""
    return "".join(_MD.get(ch, ch) for ch in _AUTOLINK.sub("\u200b", _clean(s)))


# --------------------------------------------------------------------------- JSON e SARIF: um registro por achado

def as_json(ctx, findings, lang="pt", audit=None):
    from .review import counts, ensure
    ensure(ctx, findings)
    rv = audit.review if audit else None
    items = []
    for f in findings:
        title, why, fix = texts(f.rule, lang, f.params)
        item = {"rule": f.rule, "severity": f.severity, "file": f.file, "line": f.line, "fingerprint": f.fingerprint, "title": title,
                "why": why, "fix": fix, "refs": f.refs, "tags": f.tags, "standards": standards(f.rule, f.params),
                "data": {k: v for k, v in f.params.items() if not k.endswith(("_pt", "_en"))}}
        if rv is not None:
            status, comment = rv.get(f)
            item["review"] = {"status": status or None, "comment": audit.mask.lines(comment)}
        items.append(item)
    empty = nothing_read(ctx, findings)
    doc = {"tool": "stingward", "version": __version__, "grade": None if empty else grade(counted(findings, rv))}
    if empty:
        doc["warning"] = "nothing_read"  # nenhum arquivo lido: não há nota
    # Sempre presente, mesmo vazio: quem lê o JSON não precisa testar se a chave existe.
    doc.update(sources=ctx.sources, not_read={"too_big": list(ctx.too_big), "truncated": bool(ctx.truncated)}, findings=items)
    if rv is not None:
        # masked: algo nos comentários, no parecer ou nos nomes parecia segredo e saiu mascarado (os comentários já
        # passaram pelo mascarador no laço acima). Quem gera o relatório sem uma pessoa olhar usa isso para não entregar.
        doc["review"] = {"reviewer": audit.reviewer or None, "kind": rv.kind, "masked": audit.mask.changed,
                         "counts": {k or "unreviewed": v for k, v in counts(findings, rv).items()}}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# Nome genérico de cada regra, o da tabela de docs/rules.md e docs/rules.pt-BR.md (um teste confere). O SARIF
# descreve a regra uma vez só para todos os alertas dela: o título de um achado fala do pacote ou do destino dele.
RULE_NAME = {
    "DEP001": ("Versão de dependência com falhas conhecidas", "Dependency version with known vulnerabilities"),
    "DEP002": ("Pacote malicioso", "Malicious package"),
    "DEP003": ("Manifesto sem lockfile", "Manifest without a lockfile"),
    "DEP004": ("Faixa de versão aceita versões com falhas", "Version range allows vulnerable versions"),
    "SEC001": ("Segredo no código", "Secret in code"),
    "SEC002": (".env no git", ".env committed to git"),
    "SEC003": (".env fora do .gitignore", ".env missing from .gitignore"),
    "SEC004": ("Chave service_role do Supabase no código", "Supabase service_role key in code"),
    "APP001": ("Segredo exposto ao navegador por prefixo público",
               "Secret exposed to the browser through a public env prefix"),
    "APP002": ("SDK de IA rodando no navegador", "AI SDK running in the browser"),
    "APP003": ("CORS aberto para qualquer origem", "CORS open to any origin"),
    "APP004": ("Tabela do Supabase sem Row Level Security", "Supabase table without Row Level Security"),
    "APP005": ("Política do Supabase que libera para todos", "Supabase policy that allows everyone"),
    "APP006": ("Regras do Firebase abertas", "Open Firebase rules"),
    "APP007": ("Modo debug ligado", "Debug mode enabled"),
    "APP008": ("JWT aceito sem verificar a assinatura", "JWT accepted without verifying the signature"),
    "APP009": ("Saída do modelo chega a código, shell, SQL ou HTML", "Model output reaches code, a shell, SQL or HTML"),
    "APP010": ("Dado da requisição entra no prompt de sistema", "Request input goes into the system prompt"),
    "APP011": ("Rota de IA sem login e sem limite de uso", "AI endpoint with no login and no rate limit"),
    "APP012": ("Carregar o modelo pode executar código", "Loading the model can run code"),
    "APP013": ("Agente pode executar o que o modelo escrever", "Agent can run whatever the model writes"),
    "APP014": ("Argumento que o modelo escreve na ferramenta chega a shell, código, SQL, caminho ou URL",
               "Tool argument written by the model reaches a shell, code, SQL, a path or a URL"),
    "COD001": ("Consulta SQL montada com dado de fora", "SQL query built from outside input"),
    "COD002": ("Comando de shell montado com dado de fora", "Shell command built from outside input"),
    "COD003": ("Código montado com dado de fora é executado", "Code built from outside input is executed"),
    "COD004": ("Dados carregados com pickle ou YAML inseguro", "Data loaded with pickle or unsafe YAML"),
    "COD005": ("HTML inserido sem limpar", "HTML inserted without sanitizing"),
    "COD006": ("Verificação do certificado TLS desligada", "TLS certificate check turned off"),
    "COD007": ("Caminho de arquivo montado com dados da requisição", "File path built from request input"),
    "COD008": ("Servidor busca uma URL que veio da requisição", "Server fetches a URL taken from the request"),
    "COD009": ("Redirecionamento para um endereço que veio da requisição",
               "Redirect to an address taken from the request"),
    "COD010": ("Número aleatório previsível usado num segredo", "Predictable random number used for a secret"),
    "COD011": ("Senha guardada com hash rápido", "Password hashed with a fast hash"),
    "AGT001": ("Permissão de agente ampla demais", "Agent permission too broad"),
    "AGT002": ("Hook ou servidor MCP que baixa e executa código", "Hook or MCP server downloads and runs remote code"),
    "AGT003": ("Servidor MCP sem versão fixa", "MCP server without a pinned version"),
    "AGT004": ("Credencial escrita na configuração do MCP", "Credential hard-coded in MCP config"),
    "AGT005": ("Servidor MCP remoto sem HTTPS", "Remote MCP server over plain HTTP"),
    "AGT006": ("Todos os servidores MCP do projeto aprovados automaticamente",
               "Every project MCP server auto-approved"),
    "SKL001": ("Caracteres Unicode invisíveis", "Invisible Unicode characters"),
    "SKL002": ("Baixa um script e passa direto para o shell", "Downloads a script and pipes it into a shell"),
    "SKL003": ("Injeção de prompt ou envenenamento de ferramenta", "Prompt injection phrasing or tool poisoning"),
    "SKL004": ("Lê credenciais da máquina", "Reads machine credentials"),
    "SKL005": ("Executa instruções vindas de arquivos ou páginas",
               "Executes instructions taken from files or web pages"),
    "SKL006": ("Skill pede shell sem restrição", "Skill requests unrestricted shell"),
    "SKL007": ("Código ofuscado", "Obfuscated code"),
    "SKL008": ("Envia dados para serviço de captura anônimo", "Sends data to an anonymous capture service"),
    "SKL009": ("Script de instalação executa comandos", "Install script runs commands"),
    "SKL010": ("Skill manda o agente não parar para falar com você", "Skill tells the agent not to pause for you"),
    "SKL011": ("Reverse shell", "Reverse shell"),
}


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def _fields(template):
    return any(field for _, field, _, _ in string.Formatter().parse(template))


def sarif(ctx, findings, lang="pt", prefix=""):
    """prefix: caminho da pasta auditada dentro do repositório, para os alertas do GitHub apontarem o arquivo certo."""
    from .review import ensure
    ensure(ctx, findings)
    first = {}
    for f in findings:  # já vêm da mais grave para a menos grave
        first.setdefault(f.rule, f)
    lang = lang if lang in ("pt", "en") else "en"
    doc_page = "rules.pt-BR.md" if lang == "pt" else "rules.md"
    rules = []
    for r, f in sorted(first.items()):
        # Texto da regra com campo a preencher depende do achado: no lugar dele vai o nome, ou a ajuda genérica.
        name = RULE_NAME[r][0 if lang == "pt" else 1]
        _, why, fix = RULES[r][lang]
        uri = f"{REPO_URL}/blob/main/docs/{doc_page}#{r.lower()}"
        rules.append({"id": r, "name": r, "shortDescription": {"text": name},
                      "fullDescription": {"text": fill(why, lang, {}) if not _fields(why) else name},
                      "help": {"text": fill(fix, lang, {}) if not _fields(fix) else T[lang]["sarif_help"].format(url=uri)},
                      "helpUri": uri,
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
                        "properties": {"security-severity": _SARIF_SCORE[f.severity],
                                       "tags": f.tags + [s for s in standards(f.rule, f.params) if s not in STANDARDS.get(f.rule, [])],
                                       "fingerprint": f.fingerprint}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "stingward", "version": __version__, "informationUri": REPO_URL, "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
