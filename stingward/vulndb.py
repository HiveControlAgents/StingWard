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


def osv_query(pkgs):
    """pkgs: lista de (ecossistema, nome, versão). Devolve lista de listas de IDs, na mesma ordem."""
    out = []
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        res = fetch_json(OSV_BATCH, body, ttl=6 * HOUR)
        for r in res.get("results", []):
            ids = [v["id"] for v in r.get("vulns", [])]
            # A resposta pode vir paginada para pacotes com muitas falhas; os IDs da primeira página bastam
            # para avisar, e o detalhe de cada uma vem de osv_vulns.
            out.append(ids)
    return out


def osv_vulns(ids):
    ids = sorted(set(ids))
    with ThreadPoolExecutor(8) as ex:
        docs = list(ex.map(lambda i: _safe(fetch_json, OSV_VULN.format(i), ttl=24 * HOUR), ids))
    return {i: d for i, d in zip(ids, docs) if d}


def kev():
    d = fetch_json(KEV_URL, ttl=12 * HOUR, timeout=60)
    return {v["cveID"]: v for v in d.get("vulnerabilities", [])}, d.get("catalogVersion", "")


def epss(cves):
    cves = sorted({c for c in cves if c.startswith("CVE-")})
    out = {}
    for i in range(0, len(cves), 80):
        d = _safe(fetch_json, EPSS_URL.format(",".join(cves[i:i + 80])), ttl=24 * HOUR)
        for row in (d or {}).get("data", []):
            out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return out


def nvd_severity(cve):
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else None
    d = _safe(fetch_json, NVD_URL.format(cve), ttl=7 * 24 * HOUR, headers=headers)
    for item in (d or {}).get("vulnerabilities", []):
        m = item.get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            for metric in m.get(key, []):
                data = metric.get("cvssData", {})
                if "baseScore" in data:
                    return float(data["baseScore"])
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


def _vkey(v: str):
    """Ordem de semver, PEP 440, RubyGems e Go: pré-lançamento (dev, alpha, rc...) antes da final, post depois."""
    v = v.strip().lstrip("vV").split("+", 1)[0].lower()
    epoch, _, v = v.rpartition("!")
    m = re.match(r"\d+(?:\.\d+)*", v)
    release = [int(x) for x in m.group().split(".")] if m else []
    while release and release[-1] == 0:  # 1.0 == 1.0.0
        release.pop()
    rest = re.findall(r"\d+|[a-z]+", v[m.end():] if m else v)
    phase = 1 if not rest else 2 if rest[0] in _POST else 0
    tags = [(0, int(t), "") if t.isdigit() else (1, _PRE.get(t, 2), t) for t in rest]
    return int(epoch) if epoch.isdigit() else 0, release, phase, tags


def _major(v: str):
    m = re.match(r"\d+", v.strip().lstrip("vV"))
    return int(m.group()) if m else None


def fixed_version(vuln: dict, ecosystem: str, name: str, version: str):
    """Menor versão corrigida acima da atual, preferindo a mesma versão major."""
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
    cur = _vkey(version)
    above = sorted({f for f in fixes if _vkey(f) > cur}, key=_vkey)
    if not above:
        return None
    same = [f for f in above if _major(f) == _major(version)]
    fix = (same or above)[0]
    # O OSV guarda as versões do Go sem o "v", mas go get exige: go get mod@v0.17.0
    if ecosystem == "Go" and version.startswith("v") and not fix.startswith("v"):
        fix = "v" + fix
    return fix


def _norm(name: str, eco: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name
