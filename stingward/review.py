"""Revisão humana: a impressão digital de cada achado, o arquivo de revisão e o parecer de quem revisou.

O arquivo de revisão é JSON e quem revisa edita à mão. `--review-template ARQ` cria (ou atualiza) um item por achado:

    {"stingward_review": 1, "reviewer": "Nome", "findings": [
      {"fingerprint": "3f9c0a1b2c3d4e5f", "status": "confirmed", "comment": "Conferido no painel do Supabase.",
       "finding": {"rule": "APP004", "severity": "high", "where": "supabase/x.sql:1", "title": "..."}}]}

O bloco "finding" diz a quem revisa de qual achado se trata: o Stingward lê fingerprint, status e comment. Só de um
item "fixed" que sumiu da varredura ele lê também o bloco, para listar o problema como corrigido durante a auditoria;
como o arquivo é editado à mão, esse texto é conferido, escapado e mascarado como um comentário.

A impressão digital não usa o número da linha: é a regra, o arquivo, alguns dados do achado (pacote, variável,
tabela) e o texto da linha marcada, já mascarado e sem diferença de espaços. Mexer em outras partes do arquivo não
muda nada; mudar a própria linha muda, porque aí o achado pode ser outro.

Como a linha entra já mascarada, nada derivado do segredo vai para o arquivo de revisão. É de propósito, e tem um
efeito: trocar a chave por outra na mesma linha mantém a impressão digital e, com ela, o status (um "fixed" ou
"false_positive" passa a valer para a chave nova). Quando uma chave for trocada, confira essa linha de novo antes de
reaproveitar a revisão.

Comentários e parecer vêm de quem revisou, mas vão para o cliente: passam pelo mesmo mascaramento dos trechos de
código e, além disso, por uma lista dos valores que esse mascaramento tirou das linhas dos achados deste projeto.
Assim um segredo achado no código não volta pelo comentário, nem inteiro nem em pedaços.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from types import SimpleNamespace

from . import _redact as redact
from . import report_html
from .model import decode_text

STATUSES = ("confirmed", "false_positive", "accepted_risk", "fixed")
# Quem revisou: uma pessoa (o padrão) ou uma IA. Na revisão por IA, "accepted_risk" não vale (só o cliente aceita um
# risco) e "fixed" só vale para achado que sumiu da varredura: quem diz que foi corrigido é a nova varredura.
KINDS = ("person", "ai")
MAX_FILE = 5_000_000      # arquivo de revisão
MAX_NOTES = 200_000       # parecer
MAX_NAME = 200            # cliente e quem revisou
_FP = re.compile(r"[0-9a-f]{16}")
# Dados que identificam o assunto do achado. Fica de fora o que muda sozinho: severidade, EPSS, versão corrigida.
_IDENTITY = ("pkg", "version", "var", "table", "policy", "server", "host", "name", "manifest", "framework", "script")


class ReviewError(ValueError):
    """Arquivo de revisão ou parecer que não dá para usar: a mensagem diz onde."""


# --------------------------------------------------------------------------- impressão digital

def _line(ctx, f, cache):
    if not f.line:
        return ""
    if f.file not in cache:
        cache[f.file] = ctx.read(f.file).split("\n")
    lines = cache[f.file]
    if f.line > len(lines):
        return ""
    raw = lines[f.line - 1].rstrip("\r")
    if len(raw) > report_html.MAX_LINE:  # código minificado: a linha inteira não é âncora útil
        return "#long"
    return " ".join(report_html.mask_line(raw).split())


def _digest(*parts):
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def assign(ctx, findings):
    """Preenche f.fingerprint. Achados iguais no mesmo arquivo (mesma regra, mesma linha de texto) ganham um número
    de ordem, do primeiro para o último."""
    cache, groups = {}, defaultdict(list)
    for f in findings:
        ident = "\x1e".join(f"{k}={f.params[k]}" for k in _IDENTITY if isinstance(f.params.get(k), (str, int)))
        groups[_digest("v1", f.rule, f.file, ident, _line(ctx, f, cache))].append(f)
    for base, group in groups.items():
        for i, f in enumerate(sorted(group, key=lambda x: x.line or 0)):
            f.fingerprint = base if i == 0 else _digest(base, str(i + 1))
    return findings


def ensure(ctx, findings):
    if any(not f.fingerprint for f in findings):
        assign(ctx, findings)
    return findings


# --------------------------------------------------------------------------- o que quem revisou escreveu

_CHUNK = re.compile(r"[^\s\"'`,;:=(){}\[\]<>|&]+")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"  # o PGP termina em "KEY BLOCK-----"
                          r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")
_WINDOW = 12   # pedaço de segredo que já conta como vazamento
_MIN_SECRET = 6
_WHOLE_FILE = 2000  # linhas: arquivo maior que isso marcado inteiro não entra linha a linha
# Em texto corrido, "Sessão: nenhuma rota confere quem chama" é frase, não segredo: depois de um nome sensível, uma
# palavra só de letras seguida de outra palavra não é mascarada. Valor com número, símbolo ou aspas, ou no fim da
# frase, continua mascarado; e os segredos achados no projeto são mascarados de qualquer jeito, antes.
_PROSE = re.compile(r"(?P<key>[^\W\d][\w.-]{0,63})(?P<sep>[ \t]*:(?:\*\*)?[ \t]*)(?=[^\W\d_]+[ \t]+[^\W\d_])")
_COLON = "\ue000"
_MARKER = re.compile(r"[A-Z_-]+")  # -----BEGIN, PRIVATE, KEY-----: some do trecho, mas não é o segredo


class Masker:
    """Mascara comentários e parecer. Guarda em changed se mascarou algo, para avisar quem revisou."""

    def __init__(self, ctx=None, findings=()):
        known, cache, spots = set(), {}, set()
        for f in findings if ctx is not None else ():
            if f.file not in cache:
                cache[f.file] = ctx.read(f.file).split("\n")
            lines = cache[f.file]
            if f.line:
                spots.add((f.file, f.line))
            elif len(lines) <= _WHOLE_FILE:  # achado do arquivo inteiro (.env fora do .gitignore): vale cada linha
                spots.update((f.file, n) for n in range(1, len(lines) + 1))
        for rel, n in spots:
            lines = cache[rel]
            if n > len(lines) or len(lines[n - 1]) > report_html.MAX_LINE:
                continue
            raw = lines[n - 1]
            masked = report_html.mask_line(raw)
            known.update(c for c in _CHUNK.findall(raw) if len(c) >= _MIN_SECRET and c not in masked and not _MARKER.fullmatch(c))
        self.known = sorted(known, key=len, reverse=True)
        # Os pedaços de cada segredo, por tamanho: procurar no texto fica proporcional ao tamanho do texto.
        self._pieces = defaultdict(set)
        for s in self.known:
            w = min(_WINDOW, len(s))
            self._pieces[w].update(s[i:i + w] for i in range(len(s) - w + 1))
        self.changed = False

    def _known(self, text):
        """Troca por [REDACTED] qualquer trecho de 12 caracteres (ou o valor inteiro, se for menor) de um segredo do projeto."""
        hit = [False] * len(text)
        for w, pieces in self._pieces.items():
            for i in range(len(text) - w + 1):
                if text[i:i + w] in pieces:
                    hit[i:i + w] = [True] * w
        if not any(hit):
            return text
        out, i = [], 0
        while i < len(text):
            if hit[i]:
                while i < len(text) and hit[i]:
                    i += 1
                out.append("[REDACTED:secret_field]")
            else:
                out.append(text[i])
                i += 1
        return "".join(out)

    def pre(self, text):
        """Chave privada colada em várias linhas some inteira antes de o texto ser quebrado em blocos."""
        out = _PRIVATE_KEY.sub("[REDACTED:private_key]", str(text))
        self.changed = self.changed or out != text
        return out

    def __call__(self, text):
        s = self._known(self.pre(text)).replace(_COLON, "\ufffd")
        s = _PROSE.sub(lambda m: m.group(0).replace(":", _COLON) if redact.is_sensitive_key(m.group("key")) else m.group(0), s)
        out = report_html.mask_line(s).replace(_COLON, ":")
        self.changed = self.changed or out != text
        return out

    def lines(self, text):
        """Texto de várias linhas, linha a linha (o JSON guarda o comentário como foi escrito, só que mascarado)."""
        return "\n".join(self(line) for line in self.pre(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"))


# Markdown pequeno: parágrafos, listas com - * ou +, **negrito** e `código`. Todo o resto vira texto.
_BULLET = re.compile(r"^[ \t]{0,3}[-*+][ \t]+(\S.*)$")


def _blocks(text):
    out, para, items = [], [], None
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        m = _BULLET.match(raw)
        if not line:
            kind = None
        elif m:
            kind = "item"
        elif items is not None and raw[:1] in (" ", "\t"):
            kind = "cont"
        else:
            kind = "text"
        if kind in (None, "item") and para:
            out.append(("p", " ".join(para)))
            para = []
        if kind in (None, "text") and items is not None:
            out.append(("ul", items))
            items = None
        if kind == "item":
            items = (items or []) + [m.group(1).strip()]
        elif kind == "cont":
            items[-1] += " " + line
        elif kind == "text":
            para.append(line)
    if para:
        out.append(("p", " ".join(para)))
    if items is not None:
        out.append(("ul", items))
    return out


def inline(s):
    """[(estilo, texto)] com estilo "", "b" (negrito), "c" (código) ou "bc". \\*, \\` e \\\\ escapam o caractere."""
    toks, buf, i = [], [], 0

    def flush():
        if buf:
            toks.append(("t", "".join(buf)))
            buf.clear()
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in "\\`*":
            buf.append(s[i + 1])
            i += 2
        elif ch == "`" and s.find("`", i + 1) > i + 1:
            j = s.find("`", i + 1)
            flush()
            toks.append(("c", s[i + 1:j]))
            i = j + 1
        elif s.startswith("**", i):
            flush()
            toks.append(("**", ""))
            i += 2
        else:
            buf.append(ch)
            i += 1
    flush()
    marks = [k for k, (kind, _) in enumerate(toks) if kind == "**"]
    if len(marks) % 2:  # o último ** sem par fica como texto
        toks[marks[-1]] = ("t", "**")
    out, bold = [], False
    for kind, text in toks:
        if kind == "**":
            bold = not bold
            continue
        style = ("b" if bold else "") + ("c" if kind == "c" else "")
        if out and out[-1][0] == style:
            out[-1] = (style, out[-1][1] + text)
        elif text:
            out.append((style, text))
    return out


def _masked(nodes, mask):
    """O texto que aparece é sempre mask(texto visível inteiro). Se um segredo atravessa uma marca (**, `), mascarar
    pedaço por pedaço não bastaria: o bloco perde a formatação e sai como texto mascarado."""
    plain = "".join(t for _, t in nodes)
    want = mask(plain)
    got = [(st, mask(t)) for st, t in nodes]
    return got if "".join(t for _, t in got) == want else [("", want)]


def parse(text, mask):
    """[("p", nós) | ("ul", [nós, ...])], já mascarado por mask (um Masker). nós: [(estilo, texto)]."""
    out = []
    for kind, body in _blocks(mask.pre(text or "")):
        if kind == "p":
            out.append(("p", _masked(inline(body), mask)))
        else:
            out.append(("ul", [_masked(inline(item), mask) for item in body]))
    return out


def plain(blocks, gap=False):
    """Linhas de texto puro (terminal): sem as marcas, listas com "- ". gap: linha em branco entre os blocos."""
    out = []
    for kind, body in blocks:
        if gap and out:
            out.append("")
        if kind == "p":
            out.append("".join(t for _, t in body))
        else:
            out += ["- " + "".join(t for _, t in item) for item in body]
    return out


# --------------------------------------------------------------------------- arquivo de revisão

class Review:
    """O que quem revisou decidiu: fingerprint -> (status, comentário). Status vazio é "ainda não revisado"."""

    def __init__(self, entries=None, reviewer="", raw=None, path="", kind="person"):
        self.entries = entries or {}
        self.reviewer = reviewer
        self.raw = raw or []
        self.path = path
        self.kind = kind

    def get(self, f):
        return self.entries.get(f.fingerprint, ("", ""))

    def status(self, f):
        return self.get(f)[0]

    def check(self, findings, ctx):
        """Regras da revisão por IA que dependem da varredura: "fixed" só vale para achado que sumiu dela de verdade.
        Continuar nela, ou sumir porque a varredura não olhou (limite de arquivos, arquivo grande demais, linha do
        .stingwardignore, comentário stingward:ignore), é recusado."""
        if self.kind != "ai":
            return
        for f in findings:
            if self.status(f) == "fixed":
                raise ReviewError(f'{self.path}: {f.fingerprint}: "fixed" numa revisão por IA só vale para achado que '
                                  f'sumiu da varredura / in an AI review "fixed" only applies to a finding that is gone '
                                  f'from the scan')
        for fp, rule, _, where, _, _ in self.gone_fixed(findings):
            why = _hidden(ctx, rule, where)
            if why:
                raise ReviewError(f'{self.path}: {fp}: "fixed" numa revisão por IA precisa que a varredura mostre que o '
                                  f'achado sumiu, e {why[0]} / in an AI review "fixed" needs the scan to show the finding '
                                  f'is gone, and {why[1]}')

    def stale(self, findings):
        """Itens do arquivo que não batem com nenhum achado desta varredura (o código mudou ou o achado sumiu) e pedem
        atenção. Um "fixed" que sumiu é o esperado: vai para o relatório como corrigido (gone_fixed), sem aviso."""
        current = {f.fingerprint for f in findings}
        return [fp for fp, (status, _) in self.entries.items() if fp not in current and status != "fixed"]

    def gone_fixed(self, findings):
        """Itens "fixed" que não batem com nenhum achado: o problema foi corrigido e sumiu da nova varredura. Vêm com o
        bloco "finding" que o arquivo guardou, escrito à mão: é texto não confiável, conferido aqui e mascarado no Audit.
        [(fingerprint, regra ou "", severidade, onde, título, comentário)]"""
        from .model import SEVERITIES
        from .rules import RULES
        current = {f.fingerprint for f in findings}
        out = []
        for item in self.raw:
            fp = str(item.get("fingerprint") or "").strip().lower()
            if fp in current or self.entries.get(fp, ("", ""))[0] != "fixed":
                continue
            block = item.get("finding") if isinstance(item.get("finding"), dict) else {}
            rule = one_line(block.get("rule")).upper()
            severity = one_line(block.get("severity")).lower()
            out.append((fp, rule if rule in RULES else "", severity if severity in SEVERITIES else "info",
                        one_line(block.get("where")), one_line(block.get("title")) or fp, self.entries[fp][1]))
        return out


_WHERE = re.compile(r"(.+):\d+")


def _hidden(ctx, rule, where):
    """Por que esta varredura pode não ter visto o achado de `where` (o "arquivo:linha" do bloco "finding", escrito
    à mão), em pt e en, ou None. O arquivo só é lido se está na lista desta varredura, e o caminho não vai para a
    mensagem: o fingerprint já diz qual item é."""
    from . import scan  # aqui e não no topo: scan importa este módulo
    if ctx.truncated:
        return ("a varredura parou no limite de arquivos", "the scan stopped at the file limit")
    m = _WHERE.fullmatch(where)
    rel = m.group(1) if m else where
    if rel in ctx.too_big:
        return ("o arquivo ficou fora dela por ser grande demais", "the file was too big to read")
    if ctx.mode != "project" or not ctx.honor_ignores:
        return None
    if scan._ignored(SimpleNamespace(rule=rule, file=rel), scan.load_ignore(ctx.root)):
        return ("uma linha do .stingwardignore esconde o arquivo", "a .stingwardignore line hides the file")
    if rel in ctx.files and "stingward:ignore" in ctx.read(rel):
        return ("o arquivo tem um comentário stingward:ignore", "the file has a stingward:ignore comment")
    return None


def _status(value, where):
    v = re.sub(r"[\s-]+", "_", str(value or "").strip().lower())
    if v in ("", "todo", "pending", "unreviewed", "not_reviewed"):
        return ""
    if v not in STATUSES:
        raise ReviewError(f"{where}: status {value!r} não existe / does not exist (use {', '.join(STATUSES)})")
    return v


def _read(path, limit, what):
    try:
        if os.path.getsize(path) > limit:
            raise ReviewError(f"{path}: {what} grande demais / too large")
        # UTF-16 pelo BOM: o PowerShell 5 grava assim com > (o Bloco de Notas, com "Unicode").
        with open(path, "rb") as fh:
            return decode_text(fh.read(), errors="strict")
    except OSError as e:
        raise ReviewError(f"{path}: {e.strerror or e}") from None
    except UnicodeDecodeError:
        raise ReviewError(f"{path}: não é UTF-8 / not UTF-8") from None


def load(path):
    text = _read(path, MAX_FILE, "arquivo de revisão / review file")
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise ReviewError(f"{path}: JSON inválido / invalid JSON ({e})") from None
    if isinstance(doc, list):
        doc = {"findings": doc}
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise ReviewError(f'{path}: falta a lista "findings" / missing the "findings" list')
    if doc.get("stingward_review", 1) != 1:
        raise ReviewError(f"{path}: stingward_review {doc.get('stingward_review')!r} não é suportado / is not supported")
    reviewer = doc.get("reviewer") or ""
    if not isinstance(reviewer, str):
        raise ReviewError(f'{path}: "reviewer" tem que ser texto / must be a string')
    kind = doc.get("review_kind", "person")
    if not isinstance(kind, str):
        raise ReviewError(f'{path}: "review_kind" tem que ser texto / must be a string')
    if kind.strip().lower() not in KINDS:
        raise ReviewError(f'{path}: "review_kind" {kind!r} não existe / does not exist (use {", ".join(KINDS)})')
    kind = kind.strip().lower()
    entries, raw = {}, []
    for i, item in enumerate(doc["findings"], 1):
        where = f"{path}: findings[{i}]"
        if not isinstance(item, dict):
            raise ReviewError(f"{where}: tem que ser um objeto / must be an object")
        fp = str(item.get("fingerprint") or "").strip().lower()
        if not _FP.fullmatch(fp):
            raise ReviewError(f"{where}: fingerprint {item.get('fingerprint')!r} inválido / invalid")
        if fp in entries:
            raise ReviewError(f"{where}: fingerprint {fp} repetido / repeated")
        comment = item.get("comment") or ""
        if not isinstance(comment, str):
            raise ReviewError(f'{where}: "comment" tem que ser texto / must be a string')
        status = _status(item.get("status"), where)
        if kind == "ai" and status == "accepted_risk":
            raise ReviewError(f"{where}: accepted_risk não vale numa revisão por IA: só o cliente aceita um risco / "
                              f"is not allowed in an AI review: only the client can accept a risk")
        entries[fp] = (status, comment.strip())
        raw.append(item)
    return Review(entries, one_line(reviewer), raw, path, kind)


def load_notes(path):
    return _read(path, MAX_NOTES, "parecer / notes file")


HELP = {
    "pt": ("status: confirmed (confirmado), false_positive (alarme falso), accepted_risk (risco aceito) ou fixed "
           "(corrigido durante a auditoria); vazio = ainda não revisado. comment: texto livre que vai para o relatório, "
           "com **negrito** e `código`. Não cole segredos: eles saem mascarados. O bloco finding ajuda você a se "
           "localizar; o Stingward lê fingerprint, status e comment (e o bloco finding de um item fixed que sumiu, para "
           "listá-lo como corrigido). \"stale\": true marca um item que não bate mais "
           "com nenhum achado: ele fica no fim, com o seu comentário, e a marca sai se o achado voltar. review_kind: person "
           "(uma pessoa revisou) ou ai (uma IA revisou; aí accepted_risk não vale, e fixed só vale para achado que sumiu)."),
    "en": ("status: confirmed, false_positive, accepted_risk or fixed (fixed during the audit); empty = not reviewed "
           "yet. comment: free text that goes into the report, with **bold** and `code`. Do not paste secrets: they "
           "come out masked. The finding block helps you find your way; Stingward reads fingerprint, status and "
           "comment (and the finding block of a fixed item that is gone, to list it as fixed). \"stale\": true marks an item that no longer matches any finding: it stays at the end, with your "
           "comment, and the mark goes away if the finding comes back. review_kind: person (a person reviewed) or ai (an AI "
           "reviewed; then accepted_risk is not allowed, and fixed only applies to a finding that is gone)."),
}


def template(findings, lang, old=None, target=""):
    """O arquivo para quem revisa: um item por achado, na ordem do relatório. Com um arquivo anterior, mantém status
    e comentário do que já foi revisado e guarda no fim, marcados "stale": true, os itens que não batem mais com
    nenhum achado: o comentário de quem revisou está neles. Um item que volta a bater é reescrito, sem a marca."""
    from .rules import texts
    lang = lang if lang in HELP else "en"
    old = old or Review()
    items, seen = [], set()
    for f in findings:
        status, comment = old.entries.get(f.fingerprint, ("", ""))
        seen.add(f.fingerprint)
        items.append({"fingerprint": f.fingerprint, "status": status, "comment": comment,
                      "finding": {"rule": f.rule, "severity": f.severity, "where": f"{f.file}:{f.line}" if f.line else f.file,
                                  "title": texts(f.rule, lang, f.params)[0]}})
    kept = sum(1 for f in findings if any(old.entries.get(f.fingerprint, ("", ""))))
    stale = [dict(item, stale=True) for item in old.raw if str(item.get("fingerprint", "")).strip().lower() not in seen]
    doc = {"stingward_review": 1, "help": HELP[lang], "target": str(target or ""), "reviewer": old.reviewer,
           "review_kind": old.kind, "findings": items + stale}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n", kept, len(stale)


def counts(findings, review):
    """Achados por status, para a capa, o resumo e o escopo. O que foi corrigido e sumiu da varredura conta como fixed."""
    c = dict.fromkeys(("confirmed", "false_positive", "accepted_risk", "fixed", ""), 0)
    for f in findings:
        c[review.status(f)] += 1
    c["fixed"] += len(review.gone_fixed(findings))
    return c


def one_line(value):
    """Nome do cliente ou de quem revisou: uma linha só, até MAX_NAME caracteres."""
    return " ".join(str(value or "").split())[:MAX_NAME]


class Gone:
    """Um problema corrigido durante a auditoria que não aparece mais na varredura, com os campos que o relatório usa
    de um item (Entry): regra, severidade, título, lugares, status e comentário."""
    status = "fixed"

    def __init__(self, rule, severity, where, title, comment):
        self.rule, self.severity, self.where, self.title, self.comment = rule, severity, where, title, comment

    @property
    def places(self):
        return [self.where] if self.where else []


class Audit:
    """O que a revisão acrescenta a um relatório: as decisões, o cliente e o parecer, com o mascarador deste projeto.
    Vale para qualquer formato; cada um mostra o que cabe nele."""

    def __init__(self, ctx, findings, review=None, client="", notes=""):
        self.review = review
        self.mask = Masker(ctx, findings)
        # Nomes também vão para o cliente: passam pelo mesmo mascaramento.
        self.client = self.mask(one_line(client)) if client else ""
        self.reviewer = self.mask(review.reviewer) if review is not None and review.reviewer else ""
        self.notes = parse(notes, self.mask) if notes and str(notes).strip() else []
        self._comments = {}
        # O bloco "finding" de um item do arquivo vai para o cliente como o comentário: mascarado do mesmo jeito.
        self.gone = [Gone(rule, sev, self.mask(where), self.mask(title), comment)
                     for _, rule, sev, where, title, comment in (review.gone_fixed(findings) if review is not None else [])]
        # Cada comentário que algum formato mostra passa já aqui pelos dois mascaradores (blocos e linha a linha):
        # masked no JSON e o aviso no fim valem para todos, qualquer que seja o formato e a ordem em que saem.
        for text in [review.get(f)[1] for f in findings] + [g.comment for g in self.gone] if review is not None else []:
            self.comment(text)
            self.mask.lines(text)

    def comment(self, text):
        """O comentário de um item em blocos, já mascarado."""
        if text not in self._comments:
            self._comments[text] = parse(text, self.mask) if text else []
        return self._comments[text]
