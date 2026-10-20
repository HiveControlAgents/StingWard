"""Bases de vulnerabilidade: OSV.dev, CISA KEV, EPSS (FIRST) e NVD.

OSV.dev já agrega GitHub Advisories, NVD, PyPA, RustSec, Go e os pacotes maliciosos
(MAL-*), então é a fonte principal. KEV diz o que está sendo explorado de verdade e
EPSS a probabilidade de exploração nos próximos 30 dias. A NVD só entra para dar nota
a CVEs que o OSV trouxe sem severidade.
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor

from .net import NetError, fetch_json

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"

HOUR = 3600
# Páginas por pacote no querybatch (cada uma traz até ~1000 IDs): um token que nunca acaba não prende a varredura.
OSV_MAX_PAGES = 10


def _list_of(d, key):
    """d[key] quando d é objeto e d[key] é lista; senão None (resposta fora da forma)."""
    v = d.get(key) if isinstance(d, dict) else None
    return v if isinstance(v, list) else None


def _osv_batch_ok(n):
    """Lote do OSV com a forma certa: uma resposta por pergunta, cada falha com seu ID. Sem isso, um {} de um proxy
    viraria "nenhuma falha" (e passaria no portão de CI) e ficaria seis horas no cache."""
    def ok(d):
        results = _list_of(d, "results")
        if results is None or len(results) != n or not all(isinstance(r, dict) for r in results):
            return False
        for r in results:
            vulns = r.get("vulns") or []
            if not isinstance(vulns, list) or not all(isinstance(v, dict) and isinstance(v.get("id"), str) for v in vulns):
                return False
            if not isinstance(r.get("next_page_token") or "", str):
                return False
        return True
    return ok


def _texts(x):
    return x is None or (isinstance(x, list) and all(isinstance(i, str) for i in x))


def _objs(x):
    return x is None or (isinstance(x, list) and all(isinstance(i, dict) for i in x))


def _osv_record_ok(d):
    """Registro do OSV com os campos que a verificação de dependências usa na forma do esquema. Fora dela (alias que
    não é texto, affected que não é lista...), conta como detalhe que não baixou em vez de derrubar a verificação."""
    if not isinstance(d, dict) or not isinstance(d.get("id", ""), str) or not _texts(d.get("aliases")):
        return False
    if not all(isinstance(d.get(k) or "", str) for k in ("summary", "details")):
        return False
    if not isinstance(d.get("database_specific") or {}, dict) or not _objs(d.get("severity")) or not _objs(d.get("affected")):
        return False
    for a in d.get("affected") or []:
        pkg = a.get("package") or {}
        if not isinstance(pkg, dict) or not all(isinstance(pkg.get(k, ""), str) for k in ("ecosystem", "name")):
            return False
        if not all(isinstance(a.get(k) or {}, dict) for k in ("database_specific", "ecosystem_specific")):
            return False
        if not _objs(a.get("ranges")):
            return False
        for r in a.get("ranges") or []:
            if not _objs(r.get("events")) or not all(isinstance(v, str) for ev in r.get("events") or [] for v in ev.values()):
                return False
    return True


def osv_query(pkgs):
    """pkgs: lista de (ecossistema, nome, versão). Devolve lista de listas de IDs, na mesma ordem.

    Pacote com muitas falhas vem em páginas: a resposta traz next_page_token, e a página seguinte é a mesma pergunta
    com page_token. Lidas até OSV_MAX_PAGES por pacote; passado o teto, os IDs já lidos bastam para avisar."""
    out = []
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]
        ids = [[] for _ in chunk]
        todo, tokens = list(range(len(chunk))), {}
        for _ in range(OSV_MAX_PAGES):
            batch = [dict(queries[j], page_token=tokens[j]) if j in tokens else queries[j] for j in todo]
            ok = _osv_batch_ok(len(batch))
            res = fetch_json(OSV_BATCH, {"queries": batch}, ttl=6 * HOUR, valid=ok)
            if not ok(res):  # respostas fora de ordem atribuiriam a falha ao pacote errado
                raise NetError(f"{OSV_BATCH}: unexpected response")
            pending = []
            for j, r in zip(todo, res["results"]):
                ids[j] += [v["id"] for v in r.get("vulns") or [] if v["id"] not in ids[j]]
                if r.get("next_page_token"):
                    tokens[j] = r["next_page_token"]
                    pending.append(j)
            todo = pending
            if not todo:
                break
        out += ids
    return out


def osv_vulns(ids):
    ids = sorted(set(ids))
    with ThreadPoolExecutor(8) as ex:
        docs = list(ex.map(lambda i: _safe(fetch_json, OSV_VULN.format(i), ttl=24 * HOUR, valid=_osv_record_ok), ids))
    return {i: d for i, d in zip(ids, docs) if d}


def kev():
    """Catálogo vazio ou fora da forma é falha (NetError), não "nada sendo explorado"."""
    d = fetch_json(KEV_URL, ttl=12 * HOUR, timeout=60, valid=lambda d: bool(_list_of(d, "vulnerabilities")))
    if not _list_of(d, "vulnerabilities"):
        raise NetError(f"{KEV_URL}: unexpected response")
    return ({v["cveID"]: v for v in d["vulnerabilities"] if isinstance(v, dict) and isinstance(v.get("cveID"), str)},
            str(d.get("catalogVersion") or ""))


def epss(cves):
    cves = sorted({c for c in cves if c.startswith("CVE-")})
    out = {}
    for i in range(0, len(cves), 80):
        d = _safe(fetch_json, EPSS_URL.format(",".join(cves[i:i + 80])), ttl=24 * HOUR,
                  valid=lambda d: _list_of(d, "data") is not None)
        for row in (d or {}).get("data", []):
            try:
                pair = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
            # Probabilidade e percentil ficam entre 0 e 1: "NaN", "inf" ou 1.5 não são nota de ninguém.
            if all(0.0 <= x <= 1.0 for x in pair):
                out[row["cve"]] = pair
    return out


def nvd_severity(cve):
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else None
    d = _safe(fetch_json, NVD_URL.format(cve), ttl=7 * 24 * HOUR, headers=headers,
              valid=lambda d: _list_of(d, "vulnerabilities") is not None)
    for item in (d or {}).get("vulnerabilities", []):
        m = (item.get("cve") if isinstance(item, dict) else None) or {}
        m = m.get("metrics") if isinstance(m, dict) else None
        if not isinstance(m, dict):
            continue
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            metrics = m.get(key)
            for metric in metrics if isinstance(metrics, list) else []:
                data = metric.get("cvssData") if isinstance(metric, dict) else None
                if isinstance(data, dict) and "baseScore" in data:
                    try:
                        return float(data["baseScore"])
                    except (TypeError, ValueError):
                        continue
    return None


def _safe(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except NetError:
        return None


# --------------------------------------------------------------------------- severidade

_GHSA_SEV = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def score_to_sev(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def severity_of(vuln: dict):
    """(severidade, nota CVSS ou None). CVSS 4.0 não é calculado aqui: fica o rótulo do aviso ou a nota da NVD."""
    score = None
    for s in vuln.get("severity", []) or []:
        if isinstance(s, dict) and s.get("type") in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
            score = cvss3_score(s.get("score"))
            if score is not None:
                break
    label = (vuln.get("database_specific") or {}).get("severity")
    if not label:
        for a in vuln.get("affected", []) or []:
            if not isinstance(a, dict):
                continue
            label = (a.get("database_specific") or {}).get("severity") or (a.get("ecosystem_specific") or {}).get("severity")
            if label:
                break
    if isinstance(label, str) and label.upper() in _GHSA_SEV:
        return _GHSA_SEV[label.upper()], score
    if score is not None:
        return score_to_sev(score), score
    return None, None


_MALWARE = re.compile(r"\bmalware\b|^(embedded )?malicious (package|code|version|module)", re.I)


def is_malicious(vuln: dict) -> bool:
    """Pacote malicioso, não falha comum: registro MAL- do OSV ou aviso do GitHub de código malicioso (CWE-506)."""
    if str(vuln.get("id", "")).startswith("MAL-"):
        return True
    cwes = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    return "CWE-506" in cwes or _MALWARE.search(vuln.get("summary") or "") is not None


_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss3_score(vector: str):
    """Nota base CVSS 3.x a partir do vetor (especificação FIRST 3.1). O prefixo CVSS:3.x/ é opcional."""
    if not isinstance(vector, str):
        return None
    segs = vector.split("/")
    if segs[0].startswith("CVSS:"):
        if not segs[0].startswith("CVSS:3."):
            return None
        segs = segs[1:]
    try:
        parts = dict(p.split(":", 1) for p in segs)
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _W["C"][parts["C"]]) * (1 - _W["I"][parts["I"]]) * (1 - _W["A"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, IndexError):
        return None


# --------------------------------------------------------------------------- versão corrigida

_PRE = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "pre": 3, "preview": 3, "rc": 3}
_POST = ("post", "rev", "r")


def _int(digits: str) -> int:
    """int() de um pedaço de versão. A versão vem do lockfile (de uma skill de terceiros, inclusive) e o OSV responde
    com falhas até para "1.0.0-999...9": com mais de 4300 dígitos o int() do Python 3.11+ levanta ValueError."""
    try:
        return int(digits[:30])
    except ValueError:  # "²".isdigit() é True, mas int("²") não existe
        return 0


# PEP 440 (apêndice B), sem diferenciar maiúsculas: as grafias alternativas (alpha, c, pre, -1, rev...) valem o mesmo.
_PEP440 = re.compile(
    r"v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?"
    r"(?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?")
_PEP_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
# semver 2.0: o que vem depois do "-" é pré-lançamento, com identificadores separados por ponto; "+..." é build.
_SEMVER = re.compile(r"v?(?P<release>[0-9]+(?:\.[0-9]+)*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]*)?")
_SEMVER_ECOS = {"npm", "Go", "crates.io"}


def _release(text: str):
    release = [_int(x) for x in text.split(".")]
    while release and release[-1] == 0:  # 1.0 == 1.0.0
        release.pop()
    return release


def _pep440(v: str):
    """(época, release, pré, pós, dev) da PEP 440, ou None se a versão não segue a PEP."""
    m = _PEP440.fullmatch(v.strip().lower())
    if not m:
        return None

    def n(group):
        return _int(m[group]) if m[group] else 0

    pre = (_PEP_PRE[m["pre_l"]], n("pre_n")) if m["pre_l"] else None
    post = n("post_n1") if m["post_n1"] else n("post_n2") if m["post_l"] else None
    dev = n("dev_n") if m["dev_l"] else None
    if pre is None:
        # 1.0.dev1 vem antes de 1.0a1; sem pré, a versão final vem depois de todos os pré-lançamentos.
        pre = (-1, 0) if post is None and dev is not None else (3, 0)
    # Sem dev, depois de qualquer dev do mesmo ponto: 1.0a1.dev1 < 1.0a1 e 1.0.post1.dev1 < 1.0.post1.
    return (n("epoch"), _release(m["release"]), pre, -1 if post is None else post, (1, 0) if dev is None else (0, dev))


def _semver(v: str):
    """(release, pré-lançamento) do semver 2.0, ou None se a versão não segue o semver."""
    m = _SEMVER.fullmatch(v.strip())
    if not m:
        return None
    if not m["pre"]:
        return _release(m["release"]), (1,)
    ids = [(0, _int(i), "") if i.isdigit() else (1, 0, i) for i in m["pre"].split(".")]
    return _release(m["release"]), (0, ids)


def _vkey(v: str, eco=None):
    """Chave para ordenar versões. Com o ecossistema, PyPI segue a PEP 440 e npm, Go e crates.io o semver (lá,
    "1.0-1" é pós-lançamento; aqui, pré-lançamento); versão fora dessas regras fica abaixo das que seguem e é
    comparada pela ordem genérica. Sem ecossistema (ou nos outros), vale só a ordem genérica."""
    if eco is None:
        return _generic_vkey(v)
    k = _pep440(v) if eco == "PyPI" else _semver(v) if eco in _SEMVER_ECOS else None
    return (1, k) if k is not None else (0, _generic_vkey(v))


def _generic_vkey(v: str):
    """Ordem de semver, PEP 440, RubyGems e Go: pré-lançamento (dev, alpha, rc...) antes da final, post depois."""
    v = v.strip().lstrip("vV").split("+", 1)[0].lower()
    epoch, _, v = v.rpartition("!")
    m = re.match(r"\d+(?:\.\d+)*", v)
    release = [_int(x) for x in m.group().split(".")] if m else []
    while release and release[-1] == 0:  # 1.0 == 1.0.0
        release.pop()
    rest = re.findall(r"\d+|[a-z]+", v[m.end():] if m else v)
    phase = 1 if not rest else 2 if rest[0] in _POST else 0
    tags = [(0, _int(t), "") if t.isdigit() else (1, _PRE.get(t, 2), t) for t in rest]
    return _int(epoch) if epoch.isdigit() else 0, release, phase, tags


def _is_prerelease(v: str, eco) -> bool:
    """dev, alpha, beta, rc... (pós-lançamento é final). Pela PEP 440 no PyPI e pelo semver em npm, Go e crates.io."""
    if eco == "PyPI" and _pep440(v) is not None:
        _, _, pre, _, dev = _pep440(v)
        return pre[0] < 3 or dev[0] == 0
    if eco in _SEMVER_ECOS and _semver(v) is not None:
        return _semver(v)[1][0] == 0
    _, _, phase, tags = _generic_vkey(v)
    return phase == 0 and any(t[0] == 1 and t[2] in _PRE for t in tags)


def _major(v: str):
    m = re.match(r"\d+", v.strip().lstrip("vV"))
    return _int(m.group()) if m else None


def fixed_version(vuln: dict, ecosystem: str, name: str, version: str):
    """Menor versão corrigida acima da atual, preferindo uma final e, entre elas, a mesma versão major."""
    fixes = []
    for a in vuln.get("affected", []) or []:
        pkg = a.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem or _norm(pkg.get("name", ""), ecosystem) != _norm(name, ecosystem):
            continue
        for r in a.get("ranges", []) or []:
            if r.get("type") == "GIT":
                continue
            for ev in r.get("events", []):
                if "fixed" in ev:
                    fixes.append(ev["fixed"])
    cur = _vkey(version, ecosystem)
    above = sorted({f for f in fixes if _vkey(f, ecosystem) > cur}, key=lambda f: _vkey(f, ecosystem))
    if not above:
        return None
    # Um rc listado como correção não é o que se instala em produção: a final acima da atual vem antes.
    pool = [f for f in above if not _is_prerelease(f, ecosystem)] or above
    same = [f for f in pool if _major(f) == _major(version)]
    fix = (same or pool)[0]
    # O OSV guarda as versões do Go sem o "v", mas go get exige: go get mod@v0.17.0
    if ecosystem == "Go" and version.startswith("v") and not fix.startswith("v"):
        fix = "v" + fix
    return fix


def affects_whole_range(vuln: dict, ecosystem: str, name: str, floor: str, upper=None, inclusive=False) -> bool:
    """A falha, que atinge o piso, vale para toda a faixa: nenhum fim dela (fixed, last_affected, limit) cai
    entre o piso e o teto. Aviso sem faixa de versões (só a lista de versões) não permite afirmar isso."""
    lo = _vkey(floor, ecosystem)
    hi = _vkey(upper, ecosystem) if upper else None
    ranged = False
    for a in vuln.get("affected", []) or []:
        pkg = (a.get("package") or {}) if isinstance(a, dict) else {}
        if str(pkg.get("ecosystem", "")).split(":")[0] != ecosystem or _norm(pkg.get("name", ""), ecosystem) != _norm(name, ecosystem):
            continue
        for r in a.get("ranges", []) or []:
            if r.get("type") == "GIT":
                continue
            ranged = True
            for ev in r.get("events", []) or []:
                for kind in ("fixed", "limit", "last_affected"):
                    if kind not in ev:
                        continue
                    k = _vkey(str(ev[kind]), ecosystem)
                    # fixed/limit: a própria versão já escapa; last_affected: escapa o que vem depois dela.
                    escapes = k > lo if kind != "last_affected" else k >= lo
                    below = hi is None or k < hi or (kind != "last_affected" and inclusive and k == hi)
                    if escapes and below:
                        return False
    return ranged


def _norm(name: str, eco: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name
