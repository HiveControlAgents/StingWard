"""Saídas: texto para o terminal, Markdown para PR, JSON e SARIF. O relatório em HTML fica em report_html.py.

Texto, Markdown e HTML juntam achados repetidos (mesma regra, mesmos textos) num item só com todos os lugares e
abrem com o que corrigir primeiro. JSON e SARIF continuam com um registro por achado: são lidos por máquinas.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from urllib.parse import quote

from . import __version__
from .model import SEV_RANK, SEVERITIES
from .rules import RULES, STANDARDS, fill, texts

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
        "first": "Corrija primeiro", "and_more": "e mais {n}",
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
        "first": "Fix these first", "and_more": "and {n} more",
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
    # "2 críticos", "1 alto": em português o rótulo concorda com o número; em inglês ele funciona como adjetivo.
    plural = lambda s: "s" if lang == "pt" and c[s] > 1 and s != "info" else ""
    return ", ".join(f"{c[s]} {LABEL[lang][s].lower()}{plural(s)}" for s in reversed(SEVERITIES) if c[s])


# --------------------------------------------------------------------------- itens: achados repetidos juntos

class Entry:
    """Um problema do relatório: achados com a mesma regra, os mesmos textos e a mesma severidade, em um ou mais lugares."""

    def __init__(self, finding, title, why, fix):
        self.rule, self.severity = finding.rule, finding.severity
        self.title, self.why, self.fix = title, why, fix
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


def merge(findings, lang):
    """Mesma regra e mesmo título viram um item só, na ordem em que os achados vêm (o pior primeiro).

    O "por quê" e o "como corrigir" também entram na chave: na SKL001 o "por quê" traz a mensagem escondida, e
    duas mensagens diferentes não podem virar uma. A severidade também: o mesmo segredo dentro de tests/ fica baixo
    e não pode aparecer como crítico ao lado do achado real."""
    entries, index = [], {}
    for f in findings:
        title, why, fix = texts(f.rule, lang, f.params)
        key = (f.rule, f.severity, title, why, fix)
        if key in index:
            index[key].findings.append(f)
        else:
            index[key] = Entry(f, title, why, fix)
            entries.append(index[key])
    return entries


def places(entry, lang, limit=10):
    """Todos os lugares até o limite, depois "e mais N": a.js:1, b.js:4 e mais 3."""
    shown = ", ".join(entry.places[:limit])
    extra = len(entry.places) - limit
    return shown + (" " + T[lang]["and_more"].format(n=extra) if extra > 0 else "")


def _first_place(entry):
    n = len(entry.findings)
    return entry.places[0] + (f" (+{n - 1})" if n > 1 else "")


def urgent(entries, n=3):
    """Os primeiros itens críticos ou altos: o que corrigir antes de tudo."""
    return [e for e in entries if SEV_RANK[e.severity] >= SEV_RANK["high"]][:n]


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
    "AGT002": ("Quem controla aquele endereço roda código na sua máquina toda vez que o hook dispara.",
               "Whoever controls that address runs code on your machine every time the hook fires."),
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
    "DEP004": ("Sem lockfile, uma instalação pode ficar com {pkg} {floor}, que tem falhas públicas com ataque pronto. Subir o mínimo da faixa fecha essa porta.{exploit}",
               "Without a lockfile, an install can stay on {pkg} {floor}, which has public flaws with ready-made attacks. Raising the range's minimum closes that door.{exploit}"),
}


def impact(entry, lang):
    spec = IMPACT.get(entry.rule) or IMPACT.get(entry.rule[:3])
    if not spec:
        return entry.why
    return fill(spec[0] if lang == "pt" else spec[1], lang, entry.params)


# --------------------------------------------------------------------------- texto e Markdown

def text(ctx, findings, lang="pt", color=False, target=None, show_verdict=False, max_low=15):
    t = T[lang]
    entries = merge(findings, lang)
    out = [f"stingward {__version__} · {t['title']}: {_clean(target or ctx.root)}", f"{t['sources']}: {_sources_line(ctx, lang)}", ""]
    if show_verdict:
        out += [verdict(findings, lang), ""]
    first = _fix_first(entries)
    if first:
        out.append(f"{t['first']}:")
        out += [f" {i}. {ICON[e.severity]} {_clean(e.title)} · {_clean(_first_place(e))}" for i, e in enumerate(first, 1)]
        out.append("")
    if not findings:
        out.append(t["none"])
    shown_low = 0
    hidden = 0
    for e in entries:
        if e.severity in ("low", "info"):
            shown_low += 1
            if shown_low > max_low:
                hidden += 1
                continue
        title, why, fix = (_clean(x) for x in (e.title, e.why, e.fix))
        lab = LABEL[lang][e.severity]
        head = f"{ICON[e.severity]} {lab:<8} {title}"
        if color:
            head = f"{COLOR[e.severity]}{head}\033[0m"
        out.append(head)
        out.append(f"   {t['where']}: {_clean(places(e, lang))}  [{' · '.join([e.rule] + STANDARDS.get(e.rule, []))}]")
        out.append(f"   {t['why']}: {why}")
        out.append(f"   {t['fix']}: {fix}")
        if e.refs:
            out.append(f"   {_clean(e.refs[0])}")
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
    entries = merge(findings, lang)
    out = ["<!-- stingward-report -->", f"### {badge_md(g)} {t['title']}", ""]
    if show_verdict:
        out += [verdict(findings, lang), ""]
    if not findings:
        out += [t["none"], ""]
    else:
        first = _fix_first(entries)
        if first:
            out += [f"**{t['first']}**", ""]
            out += [f"{i}. {ICON[e.severity]} {_esc(e.title)} · <sub>{_esc(_first_place(e))}</sub>" for i, e in enumerate(first, 1)]
            out.append("")
        out += [f"**{t['summary']}:** {counts_line(findings, lang)} · {t['sources']}: {_sources_line(ctx, lang)}", "",
                "| | | |", "|---|---|---|"]
        for e in entries[:50]:
            out.append(f"| {ICON[e.severity]} {LABEL[lang][e.severity]} | {_esc(e.title)}<br><sub>{_esc(places(e, lang, limit=5))}</sub> "
                       f"| {_esc(e.fix)} |")
        if len(entries) > 50:
            out.append(f"| | {t['more'].format(n=len(entries) - 50)} | |")
        out.append("")
    out.append(f"<sub>stingward {__version__} · [{REPO_URL.split('//')[1]}]({REPO_URL})</sub>")
    return "\n".join(out) + "\n"


_MD = {"\\": "\\\\", "|": "\\|", "<": "&lt;", ">": "&gt;", "&": "&amp;", "[": "\\[", "]": "\\]", "`": "\\`",
       "*": "\\*", "_": "\\_", "!": "\\!", "\n": " ", "\r": " ", "@": "@&#8203;"}


def _esc(s):
    """Texto do código auditado vira texto puro no comentário do PR: sem imagem, link, HTML ou @menção."""
    return "".join(_MD.get(ch, ch) for ch in _clean(s))


# --------------------------------------------------------------------------- JSON e SARIF: um registro por achado

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
                      "help": {"text": fix}, "helpUri": f"{REPO_URL}/blob/main/docs/rules.md#{r.lower()}",
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
