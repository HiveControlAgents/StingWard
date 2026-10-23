"""Dependências e versão do PHP e do Node.js com falha conhecida (OSV.dev), priorizadas por CISA KEV e EPSS."""
from __future__ import annotations

import datetime
import fnmatch
import json
import re
from pathlib import Path

from .. import lockfiles, runtimes, vulndb
from ..model import SEV_RANK, SEVERITIES, Finding, bump
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


def _requirement_files(ctx, files):
    """requirements*.txt e os .txt de uma pasta requirements/, mais o que eles incluem com -r ou -c, com
    qualquer nome (constraints.txt, dev-requirements.txt), desde que o arquivo esteja no projeto."""
    todo = [rel for rel in ctx.files if "node_modules/" not in rel and lockfiles.is_requirements(rel)]
    found = set(todo)
    while todo:
        for inc in lockfiles.requirement_includes(Path(ctx.root), todo.pop()):
            # Um lockfile ou package.json citado por engano continua sendo lido pelo leitor dele.
            if inc in files and inc not in found and not lockfiles.is_dependency_file(inc) and not inc.endswith("pyproject.toml"):
                found.add(inc)
                todo.append(inc)
    return found


def collect(ctx):
    """Pacotes fixados (eco, nome, versão, arquivo, linha) sem repetição, os manifestos sem lockfile e as faixas
    de versão (lockfiles.Range) desses manifestos, menos as de pacotes que o projeto já fixa em outro lugar."""
    root = Path(ctx.root)
    files = set(ctx.files)
    pkgs, seen, open_manifests, ranges = [], set(), [], []
    members = _workspace_members(ctx, files)
    reqs = _requirement_files(ctx, files)

    def add(item):
        if item[:3] not in seen:
            seen.add(item[:3])
            pkgs.append(item)

    for rel in ctx.files:
        name = rel.rsplit("/", 1)[-1]
        is_req = rel in reqs
        if "node_modules/" in rel or not (name == "pyproject.toml" or is_req or lockfiles.is_dependency_file(rel)):
            continue
        d = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        locks = _LOCK_FOR.get("requirements.txt" if is_req else name, ())
        # Num monorepo o lockfile fica na raiz e trava também os pacotes dos workspaces.
        has_lock = any(d + lk in files for lk in locks) or (name == "package.json" and d in members)
        if name in ("package.json", "pyproject.toml") and has_lock:
            continue
        if name in ("package.json", "pyproject.toml") or (is_req and not has_lock):
            # pyproject.toml fica fora do DEP003: biblioteca declara faixa de propósito.
            n = lockfiles.open_ranges(root, rel, is_req) if name != "pyproject.toml" else 0
            if n:
                open_manifests.append((rel, n))
            for r in lockfiles.ranges(root, rel, is_req):
                if r.exact:  # Pillow (==10.0.0) também é versão fixada
                    add((r.eco, r.name, r.floor, r.file, r.line))
                else:
                    ranges.append(r)
        if name != "pyproject.toml":
            for item in lockfiles.parse(root, rel, is_req):
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
    rts = runtimes.collect(ctx)
    ctx.sources["packages"] = len(pkgs) + len(floors) + len(rts)
    if not (pkgs or floors or rts) or ctx.offline:
        return out
    try:
        # Versões fixadas, pisos das faixas e versões do PHP e do Node.js vão no mesmo lote.
        found = vulndb.osv_query([(e, n, v) for e, n, v, _, _ in pkgs] + list(floors.values())
                                 + [(runtimes.ECOSYSTEM, rt.lang, rt.query) for rt in rts])
    except NetError as e:
        ctx.sources["osv_error"] = str(e)
        return out
    ctx.sources["osv"] = True
    ids_per_pkg, ids_per_floor = found[:len(pkgs)], dict(zip(floors, found[len(pkgs):len(pkgs) + len(floors)]))
    ids_per_runtime = found[len(pkgs) + len(floors):]
    all_ids = sorted({i for ids in found for i in ids})
    docs = vulndb.osv_vulns(all_ids) if all_ids else {}
    missing = [i for i in all_ids if i not in docs]
    if missing:
        # Verificação incompleta não pode passar no portão de CI: osv_error faz a CLI sair com 3, e os pacotes
        # desses avisos continuam no relatório (assess abaixo).
        ctx.sources["osv_error"] = (f"{len(missing)} vulnerability detail(s) could not be fetched from OSV.dev: "
                                    + ", ".join(missing[:10]) + (" ..." if len(missing) > 10 else ""))

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
        vulns, malware, missing = [], [], []
        # Malicioso primeiro, depois GHSA (texto melhor), depois o resto.
        order = sorted(ids, key=lambda i: (not i.startswith("MAL-"), not i.startswith("GHSA-"), i))
        for vid in order:
            v = docs.get(vid)
            if vid not in docs:
                missing.append(vid)
                continue
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
        # O detalhe que não baixou (a rede falhou depois das novas tentativas) não pode sumir calado: o ID basta
        # para avisar, sem severidade nem correção conhecidas, e um MAL- continua sendo pacote malicioso.
        for vid in missing:
            if vid in seen_alias:
                continue
            seen_alias.add(vid)
            if vid.startswith("MAL-"):
                malware.append(vid)
                continue
            vulns.append({"id": vid, "osv": vid, "severity": "medium", "cvss": None, "summary": "", "kev": None,
                          "epss": None, "fixed": None, "details": False})
        return vulns, malware

    def malicious(name, version, rel, line, advisories, floor_of=None):
        """DEP002. floor_of: a faixa sem lockfile cujo piso (version) é malicioso sem que toda versão dela seja."""
        if floor_of is None:
            severity, (fix_pt, fix_en) = "critical", _REMOVE
        else:
            severity = "high"
            fix_pt, fix_en = (t.format(req=floor_of.req, floor=version) for t in _RAISE_FLOOR)
        return Finding("DEP002", severity, rel, line, {"pkg": name, "version": version, "vuln_id": advisories[0],
                                                       "advisories": advisories, "fix_pt": fix_pt, "fix_en": fix_en},
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
            # O piso malicioso só é crítico quando toda versão da faixa é maliciosa. Uma versão ruim só no piso
            # (release sequestrado, já trocado) quase nunca é a instalada: alto, para revisar a faixa.
            whole = any(vulndb.affects_whole_range(docs.get(m, {}), r.eco, r.name, r.floor, r.upper, r.inclusive)
                        for m in malware)
            out.append(malicious(r.name, r.floor, r.file, r.line, malware, None if whole else r))
        if vulns:
            vulns = [dict(x, spans=vulndb.affects_whole_range(docs.get(x["osv"], {}), r.eco, r.name, r.floor, r.upper, r.inclusive))
                     for x in vulns]
            out.append(_range_finding(r, vulns, kev))
    for rt, ids in zip(rts, ids_per_runtime):
        vulns, _ = assess(ids, runtimes.ECOSYSTEM, rt.lang, rt.query)
        vulns = [dict(x, published=str((docs.get(x["osv"]) or {}).get("published") or "")[:10]) for x in vulns]
        found_rt = _runtime_finding(rt, vulns, kev)
        if found_rt:
            out.append(found_rt)
    return out


def _named(x):
    """ID e resumo do aviso; sem resumo (aviso sem texto ou detalhe que não baixou), só o ID."""
    return f"{x['id']} ({x['summary']})" if x["summary"] else x["id"]


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


def _target(vulns, eco):
    """A menor versão que corrige tudo o que tem correção, e quantas falhas ainda não têm (o aviso sem detalhe
    não conta: dele não se sabe se tem correção). A maior correção vem pela ordem do ecossistema (PEP 440, semver)."""
    fixes = [x["fixed"] for x in vulns if x["fixed"]]
    unfixed = sum(1 for x in vulns if not x["fixed"] and x.get("details", True))
    return (max(fixes, key=lambda v: vulndb._vkey(v, eco)) if fixes else None), unfixed


_MISSING = ("O OSV.dev não mandou os detalhes de {ids}: veja o aviso no link e rode de novo.",
            "OSV.dev did not send the details of {ids}: read the advisory at the link and run again.")


def _with_missing(vulns, fix_pt, fix_en, alone):
    """Junta à correção o aviso dos detalhes que não vieram; alone: não há outra correção a dizer."""
    ids = ", ".join(x["id"] for x in vulns if not x.get("details", True))
    if not ids:
        return fix_pt, fix_en
    pt, en = _MISSING[0].format(ids=ids), _MISSING[1].format(ids=ids)
    return (pt, en) if alone else (f"{fix_pt} {pt}", f"{fix_en} {en}")


# DEP002. A versão maliciosa é a instalada (fixada, no lockfile, ou toda versão da faixa é maliciosa): remover já.
_REMOVE = ("Remova o pacote agora, apague node_modules/venv e troque todas as chaves e senhas da máquina e do projeto.",
           "Remove it now, delete node_modules/venv, and rotate every key and password on this machine and project.")
# Só o piso da faixa (e talvez outras versões, não todas) é malicioso: a instalada provavelmente é outra. Remover o
# pacote não é a correção; subir o piso é, e limpar a máquina só se a instalada for uma das maliciosas.
_RAISE_FLOOR = ("Suba a versão mínima em {req} para depois da {floor}, numa versão que não esteja marcada como maliciosa, "
                "e faça commit do lockfile: assim a versão maliciosa não é instalada. Confira qual versão está instalada "
                "(no lockfile, em node_modules ou no virtualenv). Se for uma das maliciosas, apague node_modules/venv e "
                "troque todas as chaves e senhas da máquina e do projeto.",
                "Raise the minimum in {req} past {floor}, to a version not marked as malicious, and commit a lockfile, "
                "so the malicious version is never installed. Check which version is installed (in the lockfile, "
                "node_modules or the virtualenv). If it is a malicious one, delete node_modules/venv and rotate every "
                "key and password on this machine and project.")
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
        head_pt = head_en = f"{_named(worst)}"
        why_pt, why_en = "Esta versão tem uma falha pública conhecida.", "This version has a publicly known vulnerability."
    else:
        head_pt = f"{n} falhas conhecidas; a pior é {_named(worst)}"
        head_en = f"{n} known vulnerabilities; worst is {_named(worst)}"
        others_pt, others_en = _others(vulns)
        why_pt, why_en = f"Esta versão tem falhas públicas. Outras: {others_pt}.", f"This version has public vulnerabilities. Others: {others_en}."
    target, unfixed = _target(vulns, eco)
    if target:
        fix_pt, fix_en = f"Atualize {name} para {target} ou mais nova.", f"Upgrade {name} to {target} or later."
        if unfixed:
            fix_pt += _UNFIXED[0].format(n=unfixed)
            fix_en += _UNFIXED[1].format(n=unfixed)
    else:
        fix_pt, fix_en = _NO_FIX
    fix_pt, fix_en = _with_missing(vulns, fix_pt, fix_en, alone=not target and not unfixed)
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
        head_pt = f"toda versão aceita tem a {_named(lead)}"
        head_en = f"every version it allows has {_named(lead)}"
        why_pt = f"Toda versão que essa faixa aceita tem a {lead['id']}, então a que estiver instalada também tem."
        why_en = f"Every version this range allows has {lead['id']}, so whichever one is installed has it too."
        if n > 1:
            why_pt += f" A versão {floor}, a menor, tem {n} falhas conhecidas" + (f"; a pior é {worst['id']}." if worst is not lead else ".")
            why_en += f" Version {floor}, the lowest, has {n} known vulnerabilities" + (f"; worst is {worst['id']}." if worst is not lead else ".")
    else:
        if n == 1:
            head_pt = f"a menor versão aceita ({floor}) tem a {_named(worst)}"
            head_en = f"the lowest version it allows ({floor}) has {_named(worst)}"
        else:
            head_pt = f"a menor versão aceita ({floor}) tem {n} falhas conhecidas; a pior é {_named(worst)}"
            head_en = f"the lowest version it allows ({floor}) has {n} known vulnerabilities; worst is {_named(worst)}"
        why_pt = (f"Sem lockfile, a faixa é a única regra: quem já tem a versão {floor} instalada continua com ela, porque ela "
                  "cabe na faixa, e a instalação pode escolhê-la para atender outros pacotes.")
        why_en = (f"Without a lockfile the range is the only rule: a machine that already has version {floor} keeps it, "
                  "because it fits, and an install can pick it to satisfy other packages.")
        if n > 1:
            others_pt, others_en = _others(vulns)
            why_pt += f" Outras falhas na versão {floor}: {others_pt}."
            why_en += f" Other issues in version {floor}: {others_en}."
    target, unfixed = _target(vulns, r.eco)
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
    fix_pt, fix_en = _with_missing(vulns, fix_pt, fix_en, alone=not target and not unfixed)
    return Finding("DEP004", sev, r.file, r.line, {
        "pkg": r.name, "spec": r.spec, "floor": floor, "upper": r.upper or "", "ecosystem": r.eco,
        "fixed": target or "", "whole_range": bool(whole), "vulns": vulns,
        "headline_pt": head_pt, "headline_en": head_en, "why_pt": why_pt, "why_en": why_en,
        "exploit_pt": exploit_pt, "exploit_en": exploit_en, "fix_pt": fix_pt, "fix_en": fix_en,
    }, _refs(lead), tags)


# DEP005 (PHP) e DEP006 (Node.js). Uma tag que acompanha a série (php:8.3-apache, node:24-alpine) só pega a correção
# quando a imagem é montada de novo: contam as falhas corrigidas nesta janela, o tempo em que uma imagem que ninguém
# montou de novo ainda roda a versão antiga.
RECENT_DAYS = 90
_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
# Por linguagem: a regra, o nome, como reiniciar, e o "da série" depois do número (versão 8.3; versão 24 do Node.js).
_LANG = {
    "php": ("DEP005", "PHP", ("reinicie o PHP (PHP-FPM ou Apache)", "restart PHP (PHP-FPM or Apache)"), ("", "")),
    "node": ("DEP006", "Node.js", ("reinicie o app", "restart the app"), (" do Node.js", "Node.js ")),
}
_RUNTIME_UNFIXED = (" {n} falha(s) ainda sem correção: veja a mitigação nos avisos.",
                    " {n} issue(s) still unfixed: see the advisories for a mitigation.")
_RUNTIME_NO_FIX = ("Ainda não saiu versão do {label} que corrija. Aplique a mitigação do aviso e atualize assim que a "
                   "correção sair.",
                   "No {label} release fixes it yet. Apply the advisory's mitigation and update as soon as a fix is out.")


def _today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def _in_branch(fix, branch):
    return bool(fix) and fix.startswith(branch + ".")


def _dates(iso):
    """22/10/2026 e Oct 22, 2026."""
    y, m, d = iso.split("-")
    return f"{d}/{m}/{y}", f"{_MONTHS[int(m) - 1]} {int(d)}, {y}"


def _use(rt, version, arg_value=None):
    """Onde trocar a versão: o ARG de onde ela veio, a imagem, ou o arquivo de versão."""
    if rt.arg:
        v = arg_value or version
        return f"troque o valor do ARG {rt.arg} para {v}", f"set ARG {rt.arg} to {v}"
    new = runtimes.retag(rt, arg_value or version)
    return f"troque a imagem por {new}", f"change the image to {new}"


def _runtime_finding(rt, vulns, kev):
    """DEP005 (PHP) e DEP006 (Node.js), um por lugar que define a versão. Versão exata: como o DEP001, com a severidade
    cheia. Série (php:8.3-apache, node:24-alpine, .php-version com 8.3): a versão instalada é a última da série de quando
    a imagem foi montada ou o PHP ou o Node.js atualizado. Contam a falha que nenhuma versão da série corrige (série sem
    suporte), com a severidade cheia, e as corrigidas nos últimos RECENT_DAYS dias, um nível abaixo: só uma instalação
    de antes da correção as tem."""
    rule, label, restart, (of_pt, of_en) = _LANG[rt.lang]
    recent = False
    if rt.floating:
        known = [x for x in vulns if x.get("details", True)]
        stuck = [x for x in known if not _in_branch(x["fixed"], rt.branch)]
        since = (_today() - datetime.timedelta(days=RECENT_DAYS)).isoformat()
        recent = not stuck
        vulns = stuck or [x for x in known if x["published"] >= since]
    if not vulns:
        return None
    vulns.sort(key=_rank)
    worst = vulns[0]
    tags, exploit_pt, exploit_en = _exploit(vulns, kev)
    target, unfixed = _target(vulns, runtimes.ECOSYSTEM)
    n, branch, where = len(vulns), rt.branch, rt.file.rsplit("/", 1)[-1]
    replit = where == ".replit" and rt.lang == "node"
    others_pt, others_en = _others(vulns)
    severity = worst["severity"]
    if recent:
        severity = SEVERITIES[max(SEV_RANK["low"], SEV_RANK[severity] - 1)]
        day_pt, day_en = _dates(worst["published"])
        if rt.image:
            head_pt = f"se a imagem foi montada antes de {day_pt}, ela tem a {_named(worst)}"
            head_en = f"an image built before {day_en} has {_named(worst)}"
            why_pt = (f"A imagem {rt.image} só acompanha a última versão {branch} do {label} quando é montada de novo: a "
                      f"montada antes de sair o {label} {target} continua com uma {branch} antiga.")
            why_en = (f"The {rt.image} image follows the newest {label} {branch} release only when it is built again: an "
                      f"image built before {label} {target} came out still runs an older {branch}.")
            pin_pt, pin_en = _use(rt, target)
            fix_pt = (f"Monte a imagem de novo com a base mais recente (docker build --pull --no-cache) e publique, "
                      f"ou fixe a versão: {pin_pt}.")
            fix_en = f"Rebuild the image with the newest base (docker build --pull --no-cache) and deploy again, or pin the version: {pin_en}."
        elif replit:
            head_pt = f"se o app foi publicado antes de {day_pt}, ele tem a {_named(worst)}"
            head_en = f"if the app was last deployed before {day_en}, it has {_named(worst)}"
            why_pt = (f"O .replit pede o módulo nodejs-{branch}, então o app publicado roda o Node.js que o módulo tinha na "
                      f"última publicação: o publicado antes de sair o Node.js {target} tem essas falhas.")
            why_en = (f".replit asks for the nodejs-{branch} module, so the deployed app runs the Node.js the module had at "
                      f"the last deploy: one deployed before Node.js {target} came out has these issues.")
            fix_pt = (f"Publique o app de novo na Replit (Deploy) e confira com node --version que ele roda o Node.js "
                      f"{target} ou mais novo.")
            fix_en = f"Deploy the app again on Replit and check with node --version that it runs Node.js {target} or later."
        else:
            head_pt = f"se o {label} foi atualizado pela última vez antes de {day_pt}, ele tem a {_named(worst)}"
            head_en = f"if {label} was last updated before {day_en}, it has {_named(worst)}"
            why_pt = (f"{where} pede o {label} {branch}, então a versão que roda depende de quando o {label} foi atualizado no "
                      f"servidor: o atualizado antes de sair o {label} {target} tem essas falhas.")
            why_en = (f"{where} asks for {label} {branch}, so the version that runs depends on when {label} was last updated on "
                      f"the server: one updated before {label} {target} came out has these issues.")
            fix_pt = f"Atualize o {label} {branch} para {target} ou mais nova onde o app roda e {restart[0]}."
            fix_en = f"Update {label} {branch} to {target} or later where the app runs and {restart[1]}."
        if n > 1:
            why_pt += f" As versões {branch}{of_pt} dos últimos {RECENT_DAYS} dias corrigiram {n} falhas. Outras: {others_pt}."
            why_en += f" The last {RECENT_DAYS} days of {of_en}{branch} releases fixed {n} issues. Others: {others_en}."
    elif rt.floating:
        if target:
            head_pt = f"nenhuma versão {branch}{of_pt} corrige a {_named(worst)}"
            head_en = f"no {of_en}{branch} release fixes {_named(worst)}"
            why_pt = f"Toda versão {branch} do {label} tem a {worst['id']}: a correção só saiu em séries mais novas."
            why_en = f"Every {label} {branch} release has {worst['id']}: the fix only exists in newer branches."
        else:
            head_pt = f"nenhuma versão do {label} corrige ainda a {_named(worst)}"
            head_en = f"no {label} release fixes {_named(worst)} yet"
            why_pt = f"Toda versão {branch} do {label} tem a {worst['id']}, e a correção ainda não saiu."
            why_en = f"Every {label} {branch} release has {worst['id']}, and no fix is out yet."
        if n > 1:
            why_pt += f" Outras: {others_pt}."
            why_en += f" Others: {others_en}."
        if target:
            new_branch = ".".join(target.split(".")[:1 if rt.lang == "node" else 2])
            if rt.image:
                use_pt, use_en = _use(rt, target, new_branch)
                fix_pt = (f"Passe para o {label} {new_branch} ({target} ou mais nova): {use_pt}, teste o app, monte a "
                          "imagem de novo e publique.")
                fix_en = f"Move to {label} {new_branch} ({target} or later): {use_en}, test the app, rebuild the image and deploy again."
            elif replit:
                fix_pt = (f"Passe para o Node.js {new_branch} ({target} ou mais nova): troque nodejs-{branch} por "
                          f"nodejs-{new_branch} em modules no .replit, teste o app e publique de novo.")
                fix_en = (f"Move to Node.js {new_branch} ({target} or later): change nodejs-{branch} to nodejs-{new_branch} "
                          "in modules in .replit, test the app and deploy again.")
            else:
                fix_pt = (f"Passe para o {label} {target} ou mais novo onde o app roda, troque a versão em {where}, teste o "
                          f"app e {restart[0]}.")
                fix_en = f"Move to {label} {target} or later where the app runs, update {where}, test the app and {restart[1]}."
        else:
            fix_pt, fix_en = (t.format(label=label) for t in _RUNTIME_NO_FIX)
    else:
        if n == 1:
            head_pt = head_en = _named(worst)
            why_pt = f"Esta versão do {label} tem uma falha pública conhecida."
            why_en = f"This {label} version has a publicly known vulnerability."
        else:
            head_pt = f"{n} falhas conhecidas; a pior é {_named(worst)}"
            head_en = f"{n} known vulnerabilities; worst is {_named(worst)}"
            why_pt = f"Esta versão do {label} tem falhas públicas. Outras: {others_pt}."
            why_en = f"This {label} version has public vulnerabilities. Others: {others_en}."
        if target and rt.image:
            use_pt, use_en = _use(rt, target)
            fix_pt = f"Use o {label} {target} ou mais novo: {use_pt}, monte a imagem de novo e publique."
            fix_en = f"Use {label} {target} or later: {use_en}, rebuild the image and deploy again."
        elif target:
            fix_pt = f"Instale o {label} {target} ou mais novo onde o app roda, troque a versão em {where} e {restart[0]}."
            fix_en = f"Install {label} {target} or later where the app runs, update {where} and {restart[1]}."
        else:
            fix_pt, fix_en = (t.format(label=label) for t in _RUNTIME_NO_FIX)
    if target and unfixed:
        fix_pt += _RUNTIME_UNFIXED[0].format(n=unfixed)
        fix_en += _RUNTIME_UNFIXED[1].format(n=unfixed)
    fix_pt, fix_en = _with_missing(vulns, fix_pt, fix_en, alone=not target and not unfixed)
    return Finding(rule, severity, rt.file, rt.line, {
        "runtime": rt.image or (f"nodejs-{rt.version}" if replit else f"{label} {rt.version}"), "version": rt.version, "image": rt.image, "floating": rt.floating,
        "fixed": target or "", "vulns": vulns,
        "headline_pt": head_pt, "headline_en": head_en, "why_pt": why_pt, "why_en": why_en,
        "exploit_pt": exploit_pt, "exploit_en": exploit_en, "fix_pt": fix_pt, "fix_en": fix_en,
    }, _refs(worst), tags)
