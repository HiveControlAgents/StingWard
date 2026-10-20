"""Builds the Stingward website into a folder, in Portuguese (the root) and English (en/).

Every report and number on the page comes from this checkout: the script runs Stingward on the README
demos and on its own skill, reads the rules and counts the tests, so the site cannot drift from the code.

    python site/build.py _site            # offline reports, as the tests build it
    python site/build.py _site --online   # with dependency results from OSV.dev, as the Pages workflow builds it
"""
import functools
import html
import json
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import unittest

SITE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SITE)
URL = "https://hivecontrolagents.github.io/StingWard/"
REPO = "https://github.com/HiveControlAgents/StingWard"
ASSETS = ["logo.svg", "social-preview.png"] + [f"demo-{d}-{lang}.{ext}" for d in ("app", "skill") for lang in ("pt", "en") for ext in ("mp4", "png")]
CACHE = os.path.join(tempfile.gettempdir(), "stingward-site-cache")
SEVERITY = {"🔴": "crit", "🟠": "high", "🟡": "med", "🔵": "low", "⚪": "info", "🟢": "ok"}
ROW = r"^   [^ :]+(?: [^ :]+){0,2}: "  # "   where: ...", "   how to fix: ..." under a finding

sys.path.insert(0, ROOT)
from stingward import __version__, lockfiles  # noqa: E402
from stingward import _redact as redact  # noqa: E402
from stingward.rules import RULES  # noqa: E402

e = html.escape


@functools.lru_cache(maxsize=None)
def _cli(args, cwd, lang, fmt, online):
    env = {**os.environ, "PYTHONPATH": ROOT, "PYTHONIOENCODING": "utf-8", "STINGWARD_CACHE": CACHE}
    cmd = [sys.executable, "-m", "stingward", *args, "--lang", lang, "--format", fmt, "--no-color"]
    run = subprocess.run(cmd + ([] if online else ["--offline"]), cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8")
    if online and run.returncode == 3:  # OSV.dev did not answer: the page still gets a real, offline report
        return _cli(args, cwd, lang, fmt, False)
    if run.returncode not in (0, 1):
        raise SystemExit(f"stingward {' '.join(args)} failed:\n{run.stderr}")
    return run.stdout


def cli(args, cwd, lang, fmt="text", online=False):
    return _cli(tuple(args), cwd, lang, fmt, online)


def terminal(text):
    """The CLI's text report as HTML lines, with the severity marks turned into classes."""
    out = []
    for line in text.rstrip("\n").split("\n"):
        mark = line[:1]
        if mark in SEVERITY and line[1:2] == " ":
            rest = line[2:]
            label, _, title = rest.partition(" ")  # "CRITICAL" fills the padded column, so only one space may follow it
            if title and label.isupper() and len(label) > 1:
                out.append(f'<span class="t-find"><b class="sev sev--{SEVERITY[mark]}">{e(label.strip())}</b> {e(title.strip())}</span>')
            else:
                out.append(f'<strong class="t-verdict t-verdict--{SEVERITY[mark]}">{e(rest)}</strong>')
        elif re.match(r"^ \d+\. \S ", line) and line[4:5] in SEVERITY:  # "Fix these first" item
            num, _, rest = line.strip().partition(" ")
            out.append(f'<span class="t-row"><b class="sev sev--{SEVERITY[line[4]]}">{e(num)}</b> {e(rest[2:])}</span>')
        elif re.match(r"^(?:Corrija primeiro|Fix these first):$", line):
            out.append(f'<span class="t-find">{e(line)}</span>')
        elif re.match(ROW, line):
            key, _, val = line.strip().partition(": ")
            out.append(f'<span class="t-row"><i>{e(key)}:</i> {e(val)}</span>')
        elif line.startswith("   http"):
            out.append(f'<span class="t-row t-dim">{e(line.strip())}</span>')
        elif re.match(r"^(?:Resumo|Summary):", line):
            out.append(f'<strong class="t-sum">{e(line)}</strong>')
        else:
            out.append(f'<span class="t-dim">{e(line)}</span>' if line else "")
    return "\n".join(out)


def fill(s, extra=None):
    values = {"version": __version__, "rules": str(len(RULES)), "repo": REPO, **(extra or {})}
    for k, v in values.items():
        s = s.replace("{" + k + "}", v)
    return s


def count_tests():
    return unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), top_level_dir=ROOT).countTestCases()


# The logo without its gradient: a flat honey shield with the two stripes, for the price figure.
SHIELD = ('<svg class="figure__shield" viewBox="0 0 64 64" aria-hidden="true" focusable="false">'
          '<clipPath id="shield-clip"><path d="M32 1.5 L52 13 V30 C52 40.5 45.8 47.2 37 51.2 C35 52.4 33.9 54.8 33.3 57.8 L32 63.5 '
          'L30.7 57.8 C30.1 54.8 29 52.4 27 51.2 C18.2 47.2 12 40.5 12 30 V13 Z"/></clipPath>'
          '<path d="M32 1.5 L52 13 V30 C52 40.5 45.8 47.2 37 51.2 C35 52.4 33.9 54.8 33.3 57.8 L32 63.5 L30.7 57.8 C30.1 54.8 29 52.4 27 '
          '51.2 C18.2 47.2 12 40.5 12 30 V13 Z" fill="#F5B83D"/><g clip-path="url(#shield-clip)" fill="#1B1F27">'
          '<path d="M0 19.5 Q32 25 64 19.5 V26.5 Q32 32 0 26.5 Z"/><path d="M0 33 Q32 38.5 64 33 V40 Q32 45.5 0 40 Z"/></g></svg>')


def video(root, name, label, height):
    """A demo recording as a muted loop; its poster is the final frame, which is all a still page needs."""
    return (f'<video class="demo" src="{root}assets/{name}.mp4" poster="{root}assets/{name}.png" width="974" height="{height}" '
            f'muted loop playsinline preload="none" aria-label="{e(label)}"></video>')


def copy_button(t, command, cls="button"):
    return (f'<button class="{cls}" type="button" data-copy="{e(command)}" data-done="{e(t["copied"])}" '
            f'data-failed="{e(t["copy_failed"])}"><span>{e(t["copy"])}</span></button>')


class Page:
    def __init__(self, lang, t, demo, online, tests):
        self.lang, self.t, self.demo, self.online, self.tests = lang, t, demo, online, tests
        self.root = "" if lang == "pt" else "../"

    # ---------------------------------------------------------------- hero

    def tabs(self):
        targets = ["#why", "#report", "#finds", "#price"]
        back = "\n".join(f'<a class="folder folder--{i + 1}" href="{href}"><span class="folder__tab">{e(name)}</span></a>'
                         for i, (href, name) in enumerate(zip(targets, self.t["tabs"])))
        return back

    def languages(self):
        hrefs = {"pt": "./", "en": "en/"} if self.lang == "pt" else {"pt": "../", "en": "./"}
        links = []
        for key, code, name, short in (("pt", "pt-BR", "Português", "PT"), ("en", "en", "English", "EN")):
            label = f'<span class="lang__long">{name}</span><span class="lang__short">{short}</span>'
            if key == self.lang:  # the page you are on is marked, not linked
                links.append(f'<span lang="{code}" aria-current="page">{label}</span>')
            else:
                links.append(f'<a href="{hrefs[key]}" hreflang="{code}" lang="{code}">{label}</a>')
        return "".join(links)

    # ---------------------------------------------------------------- why

    def why(self):
        return "\n".join(f'<li class="why__fact" data-reveal><p class="why__num">{e(num)}</p><p class="why__text">{e(text)} '
                         f'<a class="why__src link-plain" href="{e(link)}">{e(source)}</a></p></li>'
                         for num, text, source, link in self.t["why_facts"])

    # ---------------------------------------------------------------- report

    def reports(self):
        t, lang = self.t, self.lang
        runs = [(["skill", "./pdf-helper"], self.demo, "stingward skill ./pdf-helper"),
                (["./my-saas"], self.demo, "stingward ./my-saas"),
                (["skill", "skills/stingward"], ROOT, "stingward skill skills/stingward")]
        names, sheets, peek = [], [], ""
        for i, ((args, cwd, shown), item) in enumerate(zip(runs, t["reports"])):
            text = cli(args, cwd, lang, online=self.online)
            if i == 0:  # the hero shows the verdict and the first finding of this report
                blocks = text.split("\n\n")
                first = next(b for b in blocks[2:] if re.match(ROW, (b.split("\n") + [""])[1]))
                opening = "\n\n".join([blocks[1], first])
                peek = (f'<p class="sheet__cmd"><code><span aria-hidden="true">$ </span>{e(shown)}</code></p>'
                        f'<pre class="sheet__out">{terminal(opening)}</pre>')
            grade = re.search(r"(?:Nota|Grade): ([A-F])", text).group(1)
            on = i == 0
            names.append(
                f'<button class="report__name" type="button" role="tab" id="report-tab-{i}" aria-controls="report-sheet-{i}" '
                f'aria-selected="{str(on).lower()}" tabindex="{0 if on else -1}"><span class="report__title">{e(item["name"])}</span>'
                f'<span class="report__note">{e(item["note"])}. {e(t["grade_word"])} {grade}.</span></button>')
            sheets.append(
                f'<div class="sheet" data-ui role="tabpanel" id="report-sheet-{i}" aria-labelledby="report-tab-{i}" tabindex="0"{"" if on else " hidden"}>'
                f'<p class="sheet__cmd"><code><span aria-hidden="true">$ </span>{e(shown)}</code></p><pre class="sheet__out">{terminal(text)}</pre></div>')
        return "\n".join(names), "\n".join(sheets), peek

    # ---------------------------------------------------------------- how it works

    def stages(self):
        t = self.t
        app = os.path.join(self.demo, "my-saas")
        files = sorted(os.path.relpath(os.path.join(d, f), app).replace(os.sep, "/")
                       for d, _, fs in os.walk(app) for f in fs)
        frag_files = (f'<p class="frag__title">{e(fill(t["files_read"], {"n": str(len(files))}))}</p><ul class="frag__files">'
                      + "".join(f"<li><code>{e(f)}</code></li>" for f in files) + "</ul>")
        from pathlib import Path
        pkgs = [(eco, name, ver) for rel in files if lockfiles.is_dependency_file(rel)
                for eco, name, ver, _, _ in lockfiles.parse(Path(app), rel)]
        pkgs = sorted(set(pkgs))
        body = json.dumps({"queries": [{"package": {"ecosystem": eco, "name": n}, "version": v} for eco, n, v in pkgs]}, indent=1)
        frag_osv = f'<p class="frag__title">{e(t["sent_to"])}</p><pre class="frag__code">{e(body)}</pre>'
        groups = {}
        for rule in RULES:
            groups.setdefault(rule[:3], []).append(rule)
        frag_checks = '<ul class="frag__groups">' + "".join(
            f'<li><span class="frag__group">{e(t["groups"][g])} <b>{len(ids)}</b></span>'
            f'<code class="frag__ids">{" ".join(e(i) for i in ids)}</code></li>'
            for g, ids in sorted(groups.items(), key=lambda kv: -len(kv[1]))) + "</ul>"
        grade = json.loads(cli(["./my-saas"], self.demo, self.lang, "json", self.online))["grade"]
        frag_grade = (f'<p class="frag__title">./my-saas</p><ol class="frag__grades">'
                      + "".join(f'<li{" class=is-on" if g == grade else ""}><b>{g}</b> {e(m)}</li>' for g, m in t["grades"]) + "</ol>")
        frags = [frag_files, frag_osv, frag_checks, frag_grade]
        panes, names = [], []
        for i, (stage, frag) in enumerate(zip(t["stages"], frags)):
            hidden = "" if i == 0 else " hidden"
            panes.append(f'<div class="frag" data-ui data-stage="{i}"{hidden}>{frag}</div>')
            names.append(f'<li data-stage="{i}"{" class=is-on" if i == 0 else ""}>{e(stage["name"])}</li>')
        clauses = json.dumps([fill(s["clause"]) for s in t["stages"]], ensure_ascii=False)
        details = json.dumps([fill(s["detail"]) for s in t["stages"]], ensure_ascii=False)
        first = t["stages"][0]
        return {"stage_clause": e(fill(first["clause"])), "stage_detail": e(fill(first["detail"])),
                "stage_names": "\n".join(names), "stage_panes": "\n".join(panes),
                "stage_clauses": e(clauses), "stage_details": e(details), "stage_max": str(len(frags) - 1)}

    # ---------------------------------------------------------------- what it finds

    def finds(self):
        f = self.t["finds"]
        with open(os.path.join(self.demo, "pdf-helper", "SKILL.md"), encoding="utf-8") as fh:
            tags = [c for c in fh.read() if 0xE0000 <= ord(c) <= 0xE007F]
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags)
        points = " ".join(f"U+{ord(c):X}" for c in tags[:4])
        cut = decoded.rfind(" ", 0, len(decoded) // 2 + 4)  # two lines, broken at the space nearest the middle
        masked = redact.sanitize_text("OPENAI_API_KEY=sk-proj-" + "x7Qm2Lp9Vt4Rw8Zk3Hn6Jd1Fs5Gb0Yc")
        ui = {
            "mask": f'<code class="el el--mask">{e(masked)}</code>',
            "kev": '<span class="el el--kev">KEV</span>',
            "hidden": (f'<span class="el el--hidden"><code class="el__points">{e(points)} …</code>'
                       f'<code class="el__msg">{e(decoded[:cut])}</code><code class="el__msg">{e(decoded[cut + 1:])}</code></span>'),
            "public": '<code class="el el--public"><mark>NEXT_PUBLIC_</mark>OPENAI_API_KEY</code>',
            "rls": '<code class="el el--rls">using (true)</code>',
            "curl": '<code class="el el--curl">curl -fsSL https://… | sh</code>',
            "bypass": '<code class="el el--bypass">"defaultMode": "bypassPermissions"</code>',
            "ssh": '<code class="el el--ssh">~/.ssh/id_ed25519</code>',
        }

        def tile(key):
            name, line = f[key]
            return (f'<div class="tile tile--{key}" data-reveal><div class="tile__ui" data-ui aria-hidden="true">{ui[key]}</div>'
                    f'<p class="tile__cap"><strong>{e(name)}</strong><span>{e(line)}</span></p></div>')
        return {k: tile(k) for k in ui}

    # ---------------------------------------------------------------- where it runs

    def where(self):
        t, lang, root = self.t, self.lang, self.root
        rows = t["where"]
        app_text = json.loads(cli(["./my-saas"], self.demo, lang, "json", self.online))
        counts = {}
        for fnd in app_text["findings"]:
            counts[fnd["severity"]] = counts.get(fnd["severity"], 0) + 1
        sev_word = {"pt": {"critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO", "low": "BAIXO"},
                    "en": {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}}[lang]
        sev_cls = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}
        comment_rows = "".join(
            f'<li><b class="sev sev--{sev_cls[f["severity"]]}">{sev_word[f["severity"]]}</b> {e(f["title"])}'
            f'<code>{e(f["file"])}{":" + str(f["line"]) if f.get("line") else ""}</code></li>' for f in app_text["findings"][:5])
        previews = [
            video(root, f"demo-app-{lang}", rows[0]["alt"], 758),
            video(root, f"demo-skill-{lang}", rows[1]["alt"], 858),
            ('<div class="cc" data-ui><p><code>/plugin marketplace add HiveControlAgents/StingWard</code></p>'
             '<p><code>/plugin install stingward@stingward</code></p>'
             f'<p class="cc__ask"><code>&gt; {e(rows[2]["ask1"])}</code></p><p class="cc__ask"><code>&gt; {e(rows[2]["ask2"])}</code></p></div>'),
            (f'<div class="pr" data-ui><p class="pr__head"><span class="pr__grade">stingward {e(app_text["grade"])}</span> '
             f'{e(rows[3]["comment_title"])}</p><ul class="pr__rows">{comment_rows}</ul></div>'),
        ]
        out = []
        for i, (row, prev) in enumerate(zip(rows, previews)):
            out.append(f'<li class="index__item" data-reveal><button class="index__row" type="button" data-pane="{i}">'
                       f'<span class="index__name">{e(row["name"])}</span><code class="index__cmd">{e(row["cmd"])}</code></button>'
                       f'<div class="index__thumb">{prev}</div></li>')
        frame = "".join(f'<div class="index__pane" data-pane="{i}">{p}</div>' for i, p in enumerate(previews))
        return "\n".join(out), frame

    # ---------------------------------------------------------------- the rest

    def proof(self):
        return "\n".join(
            f'<a class="proof__tile" href="{e(fill(link))}" data-reveal><strong>{e(fill(name, {"tests": str(self.tests)}))}</strong>'
            f'<span>{e(line)}</span></a>' for name, line, link in self.t["proof"])

    def faq(self):
        return "\n".join(
            f'<details class="faq__item" name="faq" data-reveal><summary><span>{e(q)}</span><i aria-hidden="true"></i></summary>'
            f'<p>{e(a)}</p></details>' for q, a in self.t["faq"])

    def footer_cols(self):
        return "\n".join(
            f'<div class="footer__col"><h3>{e(title)}</h3><ul>'
            + "".join(f'<li><a class="link" href="{e(fill(href))}">{e(fill(name))}</a></li>' for name, href in links)
            + "</ul></div>" for title, links in self.t["footer_cols"])

    def render(self):
        t = self.t
        names, sheets, peek = self.reports()
        where_rows, where_frame = self.where()
        values = {k: e(fill(v)) for k, v in t.items() if isinstance(v, str)}
        values.update({
            "root": self.root, "url": URL, "repo": REPO, "version": __version__,
            "canonical": URL + ("" if self.lang == "pt" else "en/"),
            "languages": self.languages(), "why_facts": self.why(),
            "hero_h1": "".join(f'<span class="display__line">{e(line)}</span>' for line in t["hero_h1"]),
            "tabs": self.tabs(), "front_tab": e(t["tabs"][4]),
            "hero_copy": copy_button(t, "pipx install stingward"),
            "report_p": e(fill(t["report_p"])),
            "report_names": names, "report_sheets": sheets, "hero_peek": peek,
            "where_rows": where_rows, "where_frame": where_frame,
            "proof_tiles": self.proof(), "faq_items": self.faq(),
            "price_lines": "\n".join(f"<li>{e(fill(x))}</li>" for x in t["price_lines"]),
            "cta_copy": copy_button(t, t["cta_cmd"], "cta__button"),
            "footer_cols": self.footer_cols(), "shield": SHIELD,
            "wordmark": "".join(f'<span class="mark__block mark__block--{i % 3}" style="--h:{h}%">{c}</span>'
                                for i, (c, h) in enumerate(zip("Stingward", (100, 72, 86, 64, 94, 78, 60, 88, 70)))),
        })
        values.update(self.stages())
        values.update({"find_" + k: v for k, v in self.finds().items()})
        with open(os.path.join(SITE, "page.html"), encoding="utf-8") as fh:
            return string.Template(fh.read()).substitute(values)


def build(out, online=False):
    with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
        text = json.load(fh)
    tests = count_tests()
    with tempfile.TemporaryDirectory() as demo:
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "demo", "fixtures.py"), demo], check=True, capture_output=True)
        pages = {lang: Page(lang, text[lang], demo, online, tests).render() for lang in ("pt", "en")}
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(os.path.join(out, "en"))
    for lang, page in pages.items():
        with open(os.path.join(out, "index.html" if lang == "pt" else "en/index.html"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(page)
    for name in ("style.css", "app.js"):
        shutil.copy(os.path.join(SITE, name), out)
    shutil.copytree(os.path.join(SITE, "fonts"), os.path.join(out, "fonts"))
    os.makedirs(os.path.join(out, "assets"))
    for name in ASSETS:
        shutil.copy(os.path.join(ROOT, "docs", "assets", name), os.path.join(out, "assets"))
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    print(build(args[0] if args else os.path.join(ROOT, "_site"), online="--online" in sys.argv))
