"""Dependências com falha conhecida (OSV.dev), priorizadas por CISA KEV e EPSS."""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from .. import lockfiles, vulndb
from ..model import SEV_RANK, Finding, bump
from ..net import NetError
from .agents import mcp_packages

_LOCK_FOR = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"),
    "requirements.txt": ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
}


def _glob_match(path, pattern):
    """Glob de workspace por pedaço do caminho: "*" fica num pedaço só e "**" vale por qualquer número deles.
    Programação dinâmica: o glob vem do repositório auditado, e "**/a/**/a/**..." não pode virar busca exponencial."""
    ok = {len(path)}  # posições de path que casam com o resto do glob, do último pedaço do glob para o primeiro
    for seg in reversed(pattern):
        if seg == "**":  # começa em qualquer posição até a última que casa com o resto
            ok = set(range(max(ok) + 1)) if ok else set()
        else:
            ok = {i for i in range(len(path)) if i + 1 in ok and fnmatch.fnmatchcase(path[i], seg)}
    return 0 in ok


def _workspace_globs(ctx, d):
    """Globs de workspace declarados na pasta d: "workspaces" do package.json (npm, Yarn, Bun) e pnpm-workspace.yaml."""
    globs = []
    try:
        pkg = json.loads(ctx.read(d + "package.json") or "{}")
    except (ValueError, RecursionError):
        pkg = {}
    ws = pkg.get("workspaces") if isinstance(pkg, dict) else None
    if isinstance(ws, dict):
        ws = ws.get("packages")
    if isinstance(ws, list):
        globs += [g for g in ws if isinstance(g, str)]
    in_packages = False
    for line in ctx.read(d + "pnpm-workspace.yaml").split("\n"):
        if line and not line[0].isspace():
            in_packages = re.match(r"packages\s*:", line) is not None
        elif in_packages:
            m = re.match(r"\s*-\s*([\"']?)([^\"'#]+)\1", line)
            if m:
                globs.append(m.group(2).strip())
    return globs


def _workspace_members(ctx, files):
    """Pastas de pacote que o lockfile de um monorepo, numa pasta acima delas, já trava (membros de workspace)."""
    dirs = {rel.rsplit("/", 1)[0] + "/" if "/" in rel else "" for rel in files if rel.rsplit("/", 1)[-1] == "package.json"}
    covered = set()
    for top in dirs:
        if not any(top + lk in files for lk in _LOCK_FOR["package.json"]):
            continue
        yes, no = [], []
        for g in _workspace_globs(ctx, top):
            g = g.strip()
            neg = g.startswith("!")
            g = re.sub(r"^(?:\./)+", "", g[1:].strip() if neg else g).rstrip("/")
            if g:
                (no if neg else yes).append(g.split("/"))
        for d in dirs:
            if d == top or not d.startswith(top):
                continue
            sub = d[len(top):].rstrip("/").split("/")
            if any(_glob_match(sub, g) for g in yes) and not any(_glob_match(sub, g) for g in no):
                covered.add(d)
    return covered


def collect(ctx):
    """Pacotes fixados (eco, nome, versão, arquivo, linha) sem repetição, os manifestos sem lockfile e as faixas
    de versão (lockfiles.Range) desses manifestos, menos as de pacotes que o projeto já fixa em outro lugar."""
    root = Path(ctx.root)
    files = set(ctx.files)
    pkgs, seen, open_manifests, ranges = [], set(), [], []
    members = _workspace_members(ctx, files)

    def add(item):
        if item[:3] not in seen:
            seen.add(item[:3])
            pkgs.append(item)

    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        if "node_modules/" in rel or not (name == "pyproject.toml" or lockfiles.is_dependency_file(rel)):
            continue
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        locks = _LOCK_FOR.get("requirements.txt" if name.startswith("requirements") else name, ())
        # Num monorepo o lockfile fica na raiz e trava também os pacotes dos workspaces.
        has_lock = any(d + lk in files for lk in locks) or (name == "package.json" and d in members)
        if name in ("package.json", "pyproject.toml") and has_lock:
            continue
        if name in ("package.json", "pyproject.toml") or (name.startswith("requirements") and not has_lock):
            # pyproject.toml fica fora do DEP003: biblioteca declara faixa de propósito.
            n = lockfiles.open_ranges(root, rel) if name != "pyproject.toml" else 0
            if n:
                open_manifests.append((rel, n))
            for r in lockfiles.ranges(root, rel):
                if r.exact:  # Pillow (==10.0.0) também é versão fixada
                    add((r.eco, r.name, r.floor, r.file, r.line))
                else:
                    ranges.append(r)
        if name != "pyproject.toml":
            for item in lockfiles.parse(root, rel):
                add(item)
    for item in mcp_packages(ctx):
        add(item)
    # O que está fixado é o que se instala, e o DEP001 já cuida dele: o piso da faixa não acrescenta nada.
    pinned = {(e, vulndb._norm(n, e)) for e, n, *_ in pkgs}
    ranges = [r for r in ranges if (r.eco, vulndb._norm(r.name, r.eco)) not in pinned]
    return pkgs, open_manifests, ranges


def _floor_key(r):
    return r.eco, vulndb._norm(r.name, r.eco), r.floor


def _summary(v):
    s = (v.get("summary") or v.get("details") or "").strip().splitlines()
    s = s[0] if s else ""
    return s if len(s) <= 90 else s[:87] + "..."


def check(ctx):
    pkgs, open_manifests, ranges = collect(ctx)
    out = [Finding("DEP003", "low", rel, None, {"manifest": rel.rsplit("/", 1)[-1], "count": n}) for rel, n in open_manifests]
    floors = {}  # faixas com o mesmo pacote e o mesmo piso viram uma consulta só
    for r in ranges:
        floors.setdefault(_floor_key(r), (r.eco, r.name, r.floor))
    ctx.sources["packages"] = len(pkgs) + len(floors)
    if not (pkgs or floors) or ctx.offline:
        return out
    try:
        # Versões fixadas e pisos das faixas vão no mesmo lote.
        found = vulndb.osv_query([(e, n, v) for e, n, v, _, _ in pkgs] + list(floors.values()))
    except NetError as e:
        ctx.sources["osv_error"] = str(e)
        return out
    ctx.sources["osv"] = True
    ids_per_pkg, ids_per_floor = found[:len(pkgs)], dict(zip(floors, found[len(pkgs):]))
    all_ids = sorted({i for ids in found for i in ids})
    docs = vulndb.osv_vulns(all_ids) if all_ids else {}

    cves = {a for d in docs.values() for a in [d.get("id", "")] + (d.get("aliases") or []) if a.startswith("CVE-")}
    try:
        kev, kev_version = vulndb.kev() if cves else ({}, "")
        if cves:
            ctx.sources["kev"] = kev_version or True
    except NetError as e:
        kev = {}
        ctx.sources["kev_error"] = str(e)
    scores = vulndb.epss(cves) if cves else {}
    if cves:
        ctx.sources["epss"] = bool(scores)
    nvd_budget = 10

    def assess(ids, eco, name, version):
        """(falhas, avisos de malware) de uma versão, com a severidade já ajustada por KEV e EPSS."""
        nonlocal nvd_budget
        seen_alias = set()
        vulns, malware = [], []
        # Malicioso primeiro, depois GHSA (texto melhor), depois o resto.
        order = sorted(ids, key=lambda i: (not i.startswith("MAL-"), not i.startswith("GHSA-"), i))
        for vid in order:
            v = docs.get(vid)
            if not v or v.get("withdrawn"):
                continue
            aliases = {vid, *(v.get("aliases") or [])}
            if aliases & seen_alias:
                continue
            seen_alias |= aliases
            # Avisos de malware do GitHub (CWE-506) nem sempre citam o MAL- como alias: todos vão para um DEP002 só.
            if vid.startswith("MAL-") or vulndb.is_malicious(v):
                malware.append(vid)
                continue
            vcves = sorted(a for a in aliases if a.startswith("CVE-"))
            sev, score = vulndb.severity_of(v)
            if sev is None and vcves and nvd_budget > 0:
                nvd_budget -= 1
                score = vulndb.nvd_severity(vcves[0])
                sev = vulndb.score_to_sev(score) if score is not None else None
                if score is not None:
                    ctx.sources["nvd"] = True
            sev = sev or "medium"
            in_kev = [c for c in vcves if c in kev]
            best = max((scores[c] for c in vcves if c in scores), default=None)
            if in_kev:
                sev = "critical"
            elif best and best[0] >= 0.5:
                sev = bump(sev)
            vulns.append({"id": vcves[0] if vcves else vid, "osv": vid, "severity": sev, "cvss": score,
                          "summary": _summary(v), "kev": in_kev[0] if in_kev else None,
                          "epss": best[0] if best else None, "fixed": vulndb.fixed_version(v, eco, name, version)})
        return vulns, malware

    def malicious(name, version, rel, line, advisories):
        return Finding("DEP002", "critical", rel, line, {"pkg": name, "version": version, "vuln_id": advisories[0],
                                                         "advisories": advisories},
                       [f"https://osv.dev/vulnerability/{advisories[0]}"], ["malicious"])

    for (eco, name, version, rel, line), ids in zip(pkgs, ids_per_pkg):
        vulns, malware = assess(ids, eco, name, version)
        if malware:
            out.append(malicious(name, version, rel, line, malware))
        if vulns:
            out.append(_package_finding(eco, name, version, rel, line, vulns, kev))

    at_floor = {}
    for r in ranges:
        key = _floor_key(r)
        if key not in at_floor:
            at_floor[key] = assess(ids_per_floor.get(key, []), r.eco, r.name, r.floor)
        vulns, malware = at_floor[key]
        if malware:
            out.append(malicious(r.name, r.floor, r.file, r.line, malware))
        if vulns:
            vulns = [dict(x, spans=vulndb.affects_whole_range(docs[x["osv"]], r.eco, r.name, r.floor, r.upper, r.inclusive))
                     for x in vulns]
            out.append(_range_finding(r, vulns, kev))
    return out


def _rank(x):
    return -SEV_RANK[x["severity"]], not x["kev"], -(x["epss"] or 0)


def _exploit(vulns, kev):
    """Tags e frases sobre exploração de verdade (KEV) e provável (EPSS)."""
    tags = []
    exploit_pt = exploit_en = ""
    kev_hit = next((x for x in vulns if x["kev"]), None)
    if kev_hit:
        tags.append("kev")
        ransom = kev[kev_hit["kev"]].get("knownRansomwareCampaignUse") == "Known"
        exploit_pt = f" A {kev_hit['id']} está na lista da CISA de falhas exploradas por atacantes agora (KEV)" + (", inclusive por ransomware." if ransom else ".")
        exploit_en = f" {kev_hit['id']} is on CISA's list of vulnerabilities attackers are exploiting now (KEV)" + (", including ransomware." if ransom else ".")
    top = max(vulns, key=lambda x: x["epss"] or 0)
    if top["epss"] and top["epss"] >= 0.1:
        tags.append("epss")
        pct = f"{top['epss'] * 100:.0f}%"
        exploit_pt += f" Chance de a {top['id']} ser explorada nos próximos 30 dias: {pct} (EPSS)."
        exploit_en += f" Probability {top['id']} gets exploited in the next 30 days: {pct} (EPSS)."
    return tags, exploit_pt, exploit_en


def _others(vulns):
    n = len(vulns)
    others_pt = ", ".join(x["id"] for x in vulns[1:6]) + (f" e mais {n - 6}" if n > 6 else "")
    others_en = ", ".join(x["id"] for x in vulns[1:6]) + (f" and {n - 6} more" if n > 6 else "")
    return others_pt, others_en


def _target(vulns):
    """A menor versão que corrige tudo o que tem correção, e quantas falhas ainda não têm."""
    fixes = [x["fixed"] for x in vulns if x["fixed"]]
    return (max(fixes, key=vulndb._vkey) if fixes else None), len(vulns) - len(fixes)


_UNFIXED = (" {n} falha(s) ainda sem correção: veja se dá para trocar de pacote.",
            " {n} issue(s) still unfixed: consider replacing the package.")
_NO_FIX = ("Ainda não há versão corrigida. Veja se dá para trocar de pacote ou aplicar a mitigação do aviso.",
           "No fixed version yet. Consider replacing the package or applying the advisory's mitigation.")


def _refs(v):
    refs = [f"https://osv.dev/vulnerability/{v['osv']}"]
    if v["id"].startswith("CVE-"):
        refs.append(f"https://nvd.nist.gov/vuln/detail/{v['id']}")
    return refs


def _package_finding(eco, name, version, rel, line, vulns, kev):
    """Um achado por pacote: dá para corrigir tudo com uma atualização só."""
    vulns.sort(key=_rank)
    worst = vulns[0]
    tags, exploit_pt, exploit_en = _exploit(vulns, kev)
    n = len(vulns)
    if n == 1:
        head_pt = head_en = f"{worst['id']} ({worst['summary']})"
        why_pt, why_en = "Esta versão tem uma falha pública conhecida.", "This version has a publicly known vulnerability."
    else:
        head_pt = f"{n} falhas conhecidas; a pior é {worst['id']} ({worst['summary']})"
        head_en = f"{n} known vulnerabilities; worst is {worst['id']} ({worst['summary']})"
        others_pt, others_en = _others(vulns)
        why_pt, why_en = f"Esta versão tem falhas públicas. Outras: {others_pt}.", f"This version has public vulnerabilities. Others: {others_en}."
    target, unfixed = _target(vulns)
    if target:
        fix_pt, fix_en = f"Atualize {name} para {target} ou mais nova.", f"Upgrade {name} to {target} or later."
        if unfixed:
            fix_pt += _UNFIXED[0].format(n=unfixed)
            fix_en += _UNFIXED[1].format(n=unfixed)
    else:
        fix_pt, fix_en = _NO_FIX
    return Finding("DEP001", worst["severity"], rel, line, {
        "pkg": name, "version": version, "ecosystem": eco, "fixed": target or "", "vulns": vulns,
        "headline_pt": head_pt, "headline_en": head_en, "why_pt": why_pt, "why_en": why_en,
        "exploit_pt": exploit_pt, "exploit_en": exploit_en, "fix_pt": fix_pt, "fix_en": fix_en,
    }, _refs(worst), tags)


def _range_finding(r, vulns, kev):
    """Um achado por faixa cujo piso tem falha. Quem instala hoje costuma levar versão mais nova que o piso, então
    a severidade fica em médio (baixo se a pior falha do piso não chega a alta). A exceção é a falha que vale
    para a faixa inteira: essa está em qualquer versão instalada e entra com a severidade cheia."""
    vulns.sort(key=_rank)
    worst = vulns[0]
    tags, exploit_pt, exploit_en = _exploit(vulns, kev)
    whole = [x for x in vulns if x["spans"]]
    sev = "medium" if SEV_RANK[worst["severity"]] >= SEV_RANK["high"] else "low"
    if whole and SEV_RANK[whole[0]["severity"]] > SEV_RANK[sev]:
        sev = whole[0]["severity"]
    n, floor = len(vulns), r.floor
    lead = whole[0] if whole else worst
    if whole:
        head_pt = f"toda versão aceita tem a {lead['id']} ({lead['summary']})"
        head_en = f"every version it allows has {lead['id']} ({lead['summary']})"
        why_pt = f"Toda versão que essa faixa aceita tem a {lead['id']}, então a que estiver instalada também tem."
        why_en = f"Every version this range allows has {lead['id']}, so whichever one is installed has it too."
        if n > 1:
            why_pt += f" A versão {floor}, a menor, tem {n} falhas conhecidas" + (f"; a pior é {worst['id']}." if worst is not lead else ".")
            why_en += f" Version {floor}, the lowest, has {n} known vulnerabilities" + (f"; worst is {worst['id']}." if worst is not lead else ".")
    else:
        if n == 1:
            head_pt = f"a menor versão aceita ({floor}) tem a {worst['id']} ({worst['summary']})"
            head_en = f"the lowest version it allows ({floor}) has {worst['id']} ({worst['summary']})"
        else:
            head_pt = f"a menor versão aceita ({floor}) tem {n} falhas conhecidas; a pior é {worst['id']} ({worst['summary']})"
            head_en = f"the lowest version it allows ({floor}) has {n} known vulnerabilities; worst is {worst['id']} ({worst['summary']})"
        why_pt = (f"Sem lockfile, a faixa é a única regra: quem já tem a versão {floor} instalada continua com ela, porque ela "
                  "cabe na faixa, e a instalação pode escolhê-la para atender outros pacotes.")
        why_en = (f"Without a lockfile the range is the only rule: a machine that already has version {floor} keeps it, "
                  "because it fits, and an install can pick it to satisfy other packages.")
        if n > 1:
            others_pt, others_en = _others(vulns)
            why_pt += f" Outras falhas na versão {floor}: {others_pt}."
            why_en += f" Other issues in version {floor}: {others_en}."
    target, unfixed = _target(vulns)
    if target:
        new = lockfiles.raised(r, target)
        if lockfiles.in_range(r, target):
            fix_pt = (f"Suba a versão mínima para {target}: troque {r.req} por {new}. "
                      "Na próxima instalação, quem tem versão antiga recebe a nova.")
            fix_en = f"Raise the minimum to {target}: replace {r.req} with {new}. The next install then upgrades older copies."
        else:
            fix_pt = (f"Nenhuma versão dessa faixa tem a correção. Amplie a faixa para aceitar a {target} ou mais nova: "
                      f"troque {r.req} por {new}.")
            fix_en = f"No version in this range has the fix. Widen it to allow {target} or later: replace {r.req} with {new}."
        if unfixed:
            fix_pt += _UNFIXED[0].format(n=unfixed)
            fix_en += _UNFIXED[1].format(n=unfixed)
    else:
        fix_pt, fix_en = _NO_FIX
    return Finding("DEP004", sev, r.file, r.line, {
        "pkg": r.name, "spec": r.spec, "floor": floor, "upper": r.upper or "", "ecosystem": r.eco,
        "fixed": target or "", "whole_range": bool(whole), "vulns": vulns,
        "headline_pt": head_pt, "headline_en": head_en, "why_pt": why_pt, "why_en": why_en,
        "exploit_pt": exploit_pt, "exploit_en": exploit_en, "fix_pt": fix_pt, "fix_en": fix_en,
    }, _refs(lead), tags)
