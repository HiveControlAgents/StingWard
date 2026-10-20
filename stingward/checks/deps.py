"""Dependências com falha conhecida (OSV.dev), priorizadas por CISA KEV e EPSS."""
from __future__ import annotations

from pathlib import Path

from .. import lockfiles, vulndb
from ..model import SEV_RANK, Finding, bump
from ..net import NetError
from .agents import mcp_packages

_LOCK_FOR = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"),
    "requirements.txt": ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"),
}


def collect(ctx):
    """Pacotes (eco, nome, versão, arquivo, linha) sem repetição, e os manifestos sem lockfile."""
    root = Path(ctx.root)
    files = set(ctx.files)
    pkgs, seen, open_manifests = [], set(), []
    dep_files = [r for r in ctx.files if lockfiles.is_dependency_file(r) and "node_modules/" not in r]
    for rel in dep_files:
        name = rel.rsplit("/", 1)[-1]
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        locks = _LOCK_FOR.get("requirements.txt" if name.startswith("requirements") else name, ())
        has_lock = any(d + lk in files for lk in locks)
        if name == "package.json" and has_lock:
            continue
        if name in ("package.json",) or (name.startswith("requirements") and not has_lock):
            n = lockfiles.open_ranges(root, rel)
            if n:
                open_manifests.append((rel, n))
        for item in lockfiles.parse(root, rel):
            key = item[:3]
            if key not in seen:
                seen.add(key)
                pkgs.append(item)
    for item in mcp_packages(ctx):
        if item[:3] not in seen:
            seen.add(item[:3])
            pkgs.append(item)
    return pkgs, open_manifests


def _summary(v):
    s = (v.get("summary") or v.get("details") or "").strip().splitlines()
    s = s[0] if s else ""
    return s if len(s) <= 90 else s[:87] + "..."


def check(ctx):
    pkgs, open_manifests = collect(ctx)
    out = [Finding("DEP003", "low", rel, None, {"manifest": rel.rsplit("/", 1)[-1], "count": n}) for rel, n in open_manifests]
    ctx.sources["packages"] = len(pkgs)
    if not pkgs or ctx.offline:
        return out
    try:
        ids_per_pkg = vulndb.osv_query([(e, n, v) for e, n, v, _, _ in pkgs])
    except NetError as e:
        ctx.sources["osv_error"] = str(e)
        return out
    ctx.sources["osv"] = True
    all_ids = sorted({i for ids in ids_per_pkg for i in ids})
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

    for (eco, name, version, rel, line), ids in zip(pkgs, ids_per_pkg):
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
        if malware:
            out.append(Finding("DEP002", "critical", rel, line,
                               {"pkg": name, "version": version, "vuln_id": malware[0], "advisories": malware},
                               [f"https://osv.dev/vulnerability/{malware[0]}"], ["malicious"]))
        if vulns:
            out.append(_package_finding(eco, name, version, rel, line, vulns, kev))
    return out


def _package_finding(eco, name, version, rel, line, vulns, kev):
    """Um achado por pacote: dá para corrigir tudo com uma atualização só."""
    vulns.sort(key=lambda x: (-SEV_RANK[x["severity"]], not x["kev"], -(x["epss"] or 0)))
    worst = vulns[0]
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
    n = len(vulns)
    if n == 1:
        head_pt = head_en = f"{worst['id']} ({worst['summary']})"
        why_pt, why_en = "Esta versão tem uma falha pública conhecida.", "This version has a publicly known vulnerability."
    else:
        head_pt = f"{n} falhas conhecidas; a pior é {worst['id']} ({worst['summary']})"
        head_en = f"{n} known vulnerabilities; worst is {worst['id']} ({worst['summary']})"
        others = ", ".join(x["id"] for x in vulns[1:6]) + (f" e mais {n - 6}" if n > 6 else "")
        others_en = ", ".join(x["id"] for x in vulns[1:6]) + (f" and {n - 6} more" if n > 6 else "")
        why_pt, why_en = f"Esta versão tem falhas públicas. Outras: {others}.", f"This version has public vulnerabilities. Others: {others_en}."
    fixes = [x["fixed"] for x in vulns if x["fixed"]]
    target = max(fixes, key=vulndb._vkey) if fixes else None
    unfixed = n - len(fixes)
    if target:
        fix_pt, fix_en = f"Atualize {name} para {target} ou mais nova.", f"Upgrade {name} to {target} or later."
        if unfixed:
            fix_pt += f" {unfixed} falha(s) ainda sem correção: veja se dá para trocar de pacote."
            fix_en += f" {unfixed} issue(s) still unfixed: consider replacing the package."
    else:
        fix_pt = "Ainda não há versão corrigida. Veja se dá para trocar de pacote ou aplicar a mitigação do aviso."
        fix_en = "No fixed version yet. Consider replacing the package or applying the advisory's mitigation."
    refs = [f"https://osv.dev/vulnerability/{worst['osv']}"]
    if worst["id"].startswith("CVE-"):
        refs.append(f"https://nvd.nist.gov/vuln/detail/{worst['id']}")
    return Finding("DEP001", worst["severity"], rel, line, {
        "pkg": name, "version": version, "ecosystem": eco, "fixed": target or "", "vulns": vulns,
        "headline_pt": head_pt, "headline_en": head_en, "why_pt": why_pt, "why_en": why_en,
        "exploit_pt": exploit_pt, "exploit_en": exploit_en, "fix_pt": fix_pt, "fix_en": fix_en,
    }, refs, tags)
