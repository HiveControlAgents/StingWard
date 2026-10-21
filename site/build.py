"""Builds the Stingward website into a folder, in English (the root) and Portuguese (pt/).

Every report and number on the page comes from this checkout: the script runs Stingward on the README
demos and on its own skill, reads the rules and counts the tests, so the site cannot drift from the code.
The sample report (example/ and pt/exemplo/) is the real HTML report of the demo app, with a note on top.
The addresses the site had before English moved to the root (en/, en/example/ and exemplo/) are small pages
that send the visitor on to the new ones.

    python site/build.py _site            # offline reports, as the tests build it
    python site/build.py _site --online   # with dependency results from OSV.dev, as the Pages workflow builds it

The buy and waitlist buttons take their addresses from "links" in site/text.json. While one is empty its
button reads "Em breve" / "Coming soon" and is not a link; a filled one must be an https:// address.
"""
import base64
import functools
import hashlib
import html
import json
import os
import posixpath
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
PAGE_DIR = {"en": ".", "pt": "pt"}  # English is the main site; Portuguese has its own folder
SAMPLE = {"en": "example", "pt": "pt/exemplo"}  # where each language's sample report is published
HREFLANG = {"en": "en", "pt": "pt-BR"}
# The addresses the site had before English moved to the root, already shared, as old folder: (language, new folder).
# Pages cannot redirect, so each old folder gets a page that sends the visitor on (see moved()).
MOVED = {"en": ("en", "."), "en/example": ("en", "example"), "exemplo": ("pt", "pt/exemplo")}
LINKS = ("audit_checkout", "team_waitlist")
HTTPS = re.compile(r"https://[^\s\"'<>\\]+")

sys.path.insert(0, ROOT)
from stingward import __version__  # noqa: E402
from stingward import _redact as redact  # noqa: E402
from stingward.checks import deps  # noqa: E402
from stingward.model import Context  # noqa: E402
from stingward.report import ICON  # noqa: E402
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


# A row of the PR comment's table: "| 🔴 CRITICAL | title<br><sub>.env:1, app/x.ts:3</sub>... | fix |".
MD_ROW = re.compile(r"^\| (\S+) (\S+) \| (.*?)<br><sub>(.*?)</sub>", re.M)


def unmd(text):
    """Plain text again from the PR comment, which escapes what it quotes (report._esc), to escape it as HTML."""
    return html.unescape(re.sub(r"\\(.)", r"\1", text)).replace("\u200b", "")


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


def video(root, name, label, height):
    """A demo recording as a muted loop; its poster is the final frame, which is all a still page needs."""
    return (f'<video class="demo" src="{root}assets/{name}.mp4" poster="{root}assets/{name}.png" width="974" height="{height}" '
            f'muted loop playsinline preload="none" aria-label="{e(label)}"></video>')


def copy_button(t, command, cls="button"):
    return (f'<button class="{cls}" type="button" data-copy="{e(command)}" data-done="{e(t["copied"])}" '
            f'data-failed="{e(t["copy_failed"])}"><span>{e(t["copy"])}</span></button>')


def links(text):
    """The checkout and waitlist addresses from text.json. Empty means not open yet; anything else must be https."""
    given = text.get("links", {})
    for key in LINKS:
        url = given.get(key, "")
        if not isinstance(url, str) or url and not HTTPS.fullmatch(url):
            raise SystemExit(f"site/text.json: links.{key} must be empty or an https:// address, not {url!r}")
    return {key: given.get(key, "") for key in LINKS}


def offer(url, label, soon, cls="button"):
    """A buy or sign-up button. Until its address exists it is a plain label, so nothing on the page takes payment."""
    if url:
        return f'<a class="{cls}" href="{e(url)}">{e(label)}</a>'
    return f'<span class="{cls} button--soon" role="link" aria-disabled="true">{e(soon)}</span>'


def link_to(target, here):
    """Relative link from the folder `here` to the folder `target`, both given from the site root ("." is the root)."""
    path = posixpath.relpath(target, here)
    return "./" if path == "." else path + "/"


def address(folder):
    """The published address of a folder given from the site root."""
    return URL if folder == "." else URL + folder + "/"


def alternates(folders):
    """The head links of a page published in both languages: its address in each one, and English for everyone else."""
    links = [(HREFLANG[lang], address(folders[lang])) for lang in ("en", "pt")] + [("x-default", address(folders["en"]))]
    return "\n".join(f'<link rel="alternate" hreflang="{code}" href="{href}">' for code, href in links)


def pairs(key, page, text):
    """zip for a text.json list and what the page builds for it. A different length means the texts drifted from the
    page, and zip would silently drop the extra entries."""
    if len(page) != len(text):
        raise SystemExit(f"site/text.json: {key} has {len(text)} entries, the page has {len(page)}")
    return zip(page, text)


def from_demo(demo, path, snippet):
    """A piece of a demo file shown on the page, checked against the file so the picture cannot drift from the demo."""
    with open(os.path.join(demo, path), encoding="utf-8") as fh:
        if snippet not in fh.read():
            raise SystemExit(f"site: {snippet!r} is no longer in the demo file {path}")
    return snippet


# The note on top of the sample report. The report's policy (CSP) allows only inline CSS and blocks script, images,
# fonts and outside files, so the note uses nothing else; in print it disappears and the PDF is the plain report.
# Its text lines up with the report's own text column (880px sheet, 64px inside), so the two read as one page.
SAMPLE_CSS = (".sample{background:var(--ink);color:#fff}"
              ".sample-in{display:grid;gap:10px;max-width:880px;margin:0 auto;padding:20px 64px;font-size:14px;line-height:1.55}"
              ".sample p{max-width:66ch}.sample strong{color:var(--honey)}"
              ".sample-links{display:flex;flex-wrap:wrap;gap:6px 24px}"
              ".sample a{color:#fff;font-weight:600;text-decoration-color:var(--honey);text-decoration-thickness:2px;text-underline-offset:4px}"
              ".sample a:focus-visible{outline:3px solid var(--honey);outline-offset:3px}"
              "@media (max-width:700px){.sample-in{padding:16px}}"
              "@media print{.sample{display:none}}")

# The page's own policy. Everything comes from the site itself: the stylesheet, the script, the font, the logo and the
# demo recordings. The one inline script (it marks the page as having JavaScript) is allowed by its hash.
CSP = ("default-src 'none'; script-src 'self' 'sha256-{hash}'; style-src 'self' 'unsafe-inline'; img-src 'self'; "
       "media-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'")
INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)
CSP_SLOT = "@@csp@@"  # where the policy goes once the page is filled in and its inline script can be hashed


def with_policy(page):
    """The page with its policy filled in, allowing its one inline script by hash."""
    scripts = INLINE_SCRIPT.findall(page)
    if len(scripts) != 1:
        raise SystemExit("site: the page must have exactly one inline script, the one its policy allows by hash")
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode("ascii")
    return page.replace(CSP_SLOT, CSP.replace("{hash}", digest), 1)


# A page left at an old address. The refresh sends the visitor on and works without script; the script, allowed by
# the same policy as the home pages, goes first and keeps the #section and query of the old link, which a refresh
# drops. The plain link is for a browser that follows neither, and canonical tells search engines the new address.
# The icon is the site's own, so the browser does not ask the server's root for one.
MOVED_PAGE = """<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="0; url={href}">
<link rel="canonical" href="{url}">
<link rel="icon" href="{root}assets/logo.svg" type="image/svg+xml">
<title>{title}</title>
<style>body{{margin:0;padding:32px 16px;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#1b1f27;overflow-wrap:anywhere}}a{{color:inherit;font-weight:600;text-underline-offset:4px}}</style>
</head>
<body>
<p>{text}:</p>
<p><a id="to" href="{href}">{url}</a></p>
<script>location.replace(document.getElementById("to").href + location.search + location.hash)</script>
</body>
</html>
"""


def moved(t, lang, old, new):
    """The page at the old folder `old`, which now lives at the folder `new`."""
    return with_policy(MOVED_PAGE.format(lang=HREFLANG[lang], csp=CSP_SLOT, href=link_to(new, old), url=address(new),
                                         root=link_to(".", old), title=e(t["moved"]) + " · Stingward", text=e(t["moved"])))


GRADES = "ABCDF"


class Page:
    def __init__(self, lang, t, demo, online, tests, urls=None):
        self.lang, self.t, self.demo, self.online, self.tests = lang, t, demo, online, tests
        self.urls = urls or dict.fromkeys(LINKS, "")
        self.root = "" if PAGE_DIR[lang] == "." else link_to(".", PAGE_DIR[lang])
        self.sample_href = link_to(SAMPLE[lang], PAGE_DIR[lang])

    def app_grade(self):
        return json.loads(cli(["./my-saas"], self.demo, self.lang, "json", self.online))["grade"]

    # ---------------------------------------------------------------- the grade scale, the page's one motif

    def scale(self, grade, project, cls, stage=False):
        """The A to F scale as stepped bars, with the marker on the row of the real grade. Each bar says what its grade
        means; the marker names the project it was given to, and may break after a slash on a narrow screen. The
        report stage's copy follows the chosen tab, which already says its grade, so screen readers skip that one."""
        t = self.t
        bars = "".join(f'<li class="bar bar--{g}" style="--n:{i}"><b class="bar__g">{g}</b>'
                       f'<span class="bar__means">{e(means)}</span></li>'
                       for i, (g, means) in enumerate(t["grades"]))
        hide, mark = (' aria-hidden="true"', " data-marker") if stage else ("", "")
        return (f'<div class="scale {cls}"{hide}><ol class="scale__bars" aria-label="{e(t["grades_label"])}">{bars}</ol>'
                f'<p class="scale__marker" style="--row:{GRADES.index(grade)}"{mark}>'
                f'<span class="sr-only">{e(t["grade_word"])} </span><b class="scale__g">{grade}</b> '
                f'<span class="scale__what">{e(project).replace("/", "/<wbr>")}</span></p></div>')

    # ---------------------------------------------------------------- top of the page

    def nav(self):
        targets = ["#why", "#report", "#finds", "#price"]
        return "".join(f'<a class="nav__link link" href="{href}">{e(name)}</a>' for href, name in zip(targets, self.t["tabs"]))

    def languages(self):
        links = []
        for key, name, short in (("en", "English", "EN"), ("pt", "Português", "PT")):
            code = HREFLANG[key]
            label = f'<span class="lang__long">{name}</span><span class="lang__short">{short}</span>'
            if key == self.lang:  # the page you are on is marked, not linked
                links.append(f'<span lang="{code}" aria-current="page">{label}</span>')
            else:
                links.append(f'<a href="{link_to(PAGE_DIR[key], PAGE_DIR[self.lang])}" hreflang="{code}" lang="{code}">{label}</a>')
        return "".join(links)

    # ---------------------------------------------------------------- why

    def why(self):
        rows = []
        for num, text, source, link, bars in self.t["why_facts"]:
            # The share each number stands for, drawn to scale: the widest part first, the worst part on top of it.
            parts = sorted(bars, key=lambda b: -b[0] / b[1])
            bar = ('<div class="fact__bar" aria-hidden="true">' + "".join(
                f'<i class="fact__part{" fact__part--worst" if i else ""}" style="--w:{100 * part / whole:.1f}%"></i>'
                for i, (part, whole) in enumerate(parts)) + "</div>") if bars else ""
            rows.append(f'<li class="fact{"" if bars else " fact--plain"}" data-reveal><p class="fact__num">{e(num)}</p>{bar}'
                        f'<p class="fact__text">{e(text)} <a class="fact__src link-plain" href="{e(link)}">{e(source)}</a></p></li>')
        return "\n".join(rows)

    # ---------------------------------------------------------------- report

    def reports(self):
        t, lang = self.t, self.lang
        runs = [(["skill", "./pdf-helper"], self.demo, "stingward skill ./pdf-helper", "./pdf-helper"),
                (["./my-saas"], self.demo, "stingward ./my-saas", "./my-saas"),
                (["skill", "skills/stingward"], ROOT, "stingward skill skills/stingward", "skills/stingward")]
        names, sheets, grades = [], [], []
        for i, ((args, cwd, shown, project), item) in enumerate(pairs("reports", runs, t["reports"])):
            text = cli(args, cwd, lang, online=self.online)
            grade = re.search(r"(?:Nota|Grade): ([A-F])", text).group(1)
            grades.append((grade, project))
            on = i == 0
            names.append(
                f'<button class="report__name" type="button" role="tab" id="report-tab-{i}" aria-controls="report-sheet-{i}" '
                f'aria-selected="{str(on).lower()}" tabindex="{0 if on else -1}" data-grade="{grade}" data-project="{e(project)}">'
                f'<span class="report__title">{e(item["name"])}</span>'
                f'<span class="report__note">{e(item["note"])}. {e(t["grade_word"])} {grade}.</span></button>')
            sheets.append(
                f'<div class="sheet" data-ui role="tabpanel" id="report-sheet-{i}" aria-labelledby="report-tab-{i}" tabindex="0"{"" if on else " hidden"}>'
                f'<p class="sheet__cmd"><code><span aria-hidden="true">$ </span>{e(shown)}</code></p><pre class="sheet__out">{terminal(text)}</pre></div>')
        return "\n".join(names), "\n".join(sheets), self.scale(*grades[0], "scale--stage", stage=True)

    # ---------------------------------------------------------------- how it works

    def stages(self):
        t = self.t
        app = os.path.join(self.demo, "my-saas")
        files = sorted(os.path.relpath(os.path.join(d, f), app).replace(os.sep, "/")
                       for d, _, fs in os.walk(app) for f in fs)
        frag_files = (f'<p class="frag__title">{e(fill(t["files_read"], {"n": str(len(files))}))}</p><ul class="frag__files">'
                      + "".join(f"<li><code>{e(f)}</code></li>" for f in files) + "</ul>")
        # What the dependency check sends: each pinned version, and the lowest version of each range without a lockfile.
        pinned, _, ranges = deps.collect(Context(root=app, files=files))
        pkgs = sorted({(eco, name, ver) for eco, name, ver, _, _ in pinned} | {(r.eco, r.name, r.floor) for r in ranges})
        body = json.dumps({"queries": [{"package": {"ecosystem": eco, "name": n}, "version": v} for eco, n, v in pkgs]}, indent=1)
        frag_osv = f'<p class="frag__title">{e(t["sent_to"])}</p><pre class="frag__code">{e(body)}</pre>'
        groups = {}
        for rule in RULES:
            groups.setdefault(rule[:3], []).append(rule)
        frag_checks = '<ul class="frag__groups">' + "".join(
            f'<li><span class="frag__group">{e(t["groups"][g])} <b>{len(ids)}</b></span>'
            f'<code class="frag__ids">{" ".join(e(i) for i in ids)}</code></li>'
            for g, ids in sorted(groups.items(), key=lambda kv: -len(kv[1]))) + "</ul>"
        grade = self.app_grade()
        frag_grade = (f'<p class="frag__title">./my-saas</p><ol class="frag__grades">'
                      + "".join(f'<li class="frag__grade frag__grade--{g}{" is-on" if g == grade else ""}"><b>{g}</b> {e(m)}</li>'
                                for g, m in t["grades"]) + "</ol>")
        frags = [frag_files, frag_osv, frag_checks, frag_grade]
        panes, names = [], []
        for i, (frag, stage) in enumerate(pairs("stages", frags, t["stages"])):
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

    # Secrets first, then the mistakes AI makes in an app, the code checks, skills and agents, and the dependencies.
    FINDS = ("mask", "public", "rls", "limit", "shell", "sqli", "ssrf", "xss", "path", "hidden", "curl", "ssh", "bypass", "kev",
             "floor")

    def finds(self):
        f = self.t["finds"]
        with open(os.path.join(self.demo, "pdf-helper", "SKILL.md"), encoding="utf-8") as fh:
            tags = [c for c in fh.read() if 0xE0000 <= ord(c) <= 0xE007F]
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags)
        points = " ".join(f"U+{ord(c):X}" for c in tags[:4])
        cut = decoded.rfind(" ", 0, len(decoded) // 2 + 4)  # two lines, broken at the space nearest the middle
        masked = redact.sanitize_text("OPENAI_API_KEY=sk-proj-" + "x7Qm2Lp9Vt4Rw8Zk3Hn6Jd1Fs5Gb0Yc")
        # The code check and the AI mistakes, as they are written in the demo app.
        shown = functools.partial(from_demo, os.path.join(self.demo, "my-saas"))
        shell = shown("app/api/agent/route.ts", 'exec(reply.choices[0].message.content ?? "")').partition(".message")
        sql = shown("app/api/invoices/route.ts", "where user_id = '${user}'").split(" = ")
        floor = shown("worker/requirements.txt", "requests>=2.19.0").split(">=")
        html_in = shown("components/Chat.tsx", "__html: m.content").split(" ")
        fetch = shown("app/api/preview/route.ts", "fetch(url)")
        shown("app/api/invoices/pdf/route.ts", 'searchParams.get("file")')
        routes = [f"POST /api/{r}" for r in ("agent", "chat") if shown(f"app/api/{r}/route.ts", "export async function POST")]
        dollar = lambda text: e(text).replace("$", "&#36;")  # "${" would read as a placeholder left unfilled
        ui = {
            "mask": f'<code>{e(masked)}</code>',
            "kev": '<span class="el__flag">KEV</span>',
            "hidden": (f'<code class="el__dim">{e(points)} …</code>'
                       f'<code class="el__hit">{e(decoded[:cut])}</code><code class="el__hit">{e(decoded[cut + 1:])}</code>'),
            "public": '<code><mark>NEXT_PUBLIC_</mark>OPENAI_API_KEY</code>',
            "rls": '<code>using (<mark>true</mark>)</code>',
            "curl": '<code>curl -fsSL https://… <mark>| sh</mark></code>',
            "bypass": '<code>"defaultMode": <mark>"bypassPermissions"</mark></code>',
            "ssh": '<code><mark>~/.ssh/id_ed25519</mark></code>',
            "sqli": f'<code><span class="el__dim">{e(sql[0])} =</span> <mark>{dollar(sql[1])}</mark></code>',
            "ssrf": f'<code><mark>{e(fetch)}</mark></code>',
            "shell": f'<code><mark>{e(shell[0])}</mark>{e(shell[1] + shell[2])}</code>',
            "xss": f'<code>{e(html_in[0])} <mark>{e(html_in[1])}</mark></code>',
            "path": '<code><span class="el__dim">?file=</span><mark>../../.env</mark></code>',
            "limit": "".join(f"<code>{e(r)}</code>" for r in routes),
            "floor": f'<code>{e(floor[0])}&gt;=<mark>{e(floor[1])}</mark></code>',
        }
        if set(ui) != set(self.FINDS) or set(f) != set(self.FINDS):
            raise SystemExit("site: the finds on the page and in text.json differ")

        def row(key):
            name, line = f[key]
            return (f'<li class="find find--{key}"><h3 class="find__name">{e(name)}</h3>'
                    f'<div class="find__ui" data-ui>{ui[key]}</div><p class="find__line">{e(line)}</p></li>')
        return "\n".join(row(k) for k in self.FINDS)

    # ---------------------------------------------------------------- where it runs

    def where(self):
        t, lang, root = self.t, self.lang, self.root
        rows = t["where"]
        app_text = json.loads(cli(["./my-saas"], self.demo, lang, "json", self.online))
        # The first rows of the real PR comment: one row per problem, with every place it was found, in its order.
        comment = cli(["./my-saas"], self.demo, lang, "markdown", self.online)
        sev_cls = {ICON["critical"]: "crit", ICON["high"]: "high", ICON["medium"]: "med", ICON["low"]: "low"}
        comment_rows = "".join(
            f'<li><b class="sev sev--{sev_cls[icon]}">{e(label)}</b> {e(unmd(title))}<code>{e(unmd(where))}</code></li>'
            for icon, label, title, where in MD_ROW.findall(comment)[:5])
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
        for i, (prev, row) in enumerate(pairs("where", previews, rows)):
            out.append(f'<li class="index__item"><button class="index__row" type="button" data-pane="{i}">'
                       f'<span class="index__name">{e(row["name"])}</span><code class="index__cmd">{e(row["cmd"])}</code></button>'
                       f'<div class="index__thumb">{prev}</div></li>')
        frame = "".join(f'<div class="index__pane" data-pane="{i}">{p}</div>' for i, p in enumerate(previews))
        return "\n".join(out), frame

    # ---------------------------------------------------------------- the rest

    def proof(self):
        return "\n".join(
            f'<li><a class="proof__item" href="{e(fill(link))}"><strong>{e(fill(name, {"tests": str(self.tests)}))}</strong>'
            f'<span>{e(line)}</span></a></li>' for name, line, link in self.t["proof"])

    def faq(self):
        return "\n".join(
            f'<details class="faq__item" name="faq"><summary><span>{e(q)}</span><i aria-hidden="true"></i></summary>'
            f'<p>{e(a)}</p></details>' for q, a in self.t["faq"])

    def footer_cols(self):
        return "\n".join(
            f'<div class="footer__col"><h3>{e(title)}</h3><ul>'
            + "".join(f'<li><a class="link" href="{e(fill(href, {"sample": self.sample_href}))}">{e(fill(name))}</a></li>'
                      for name, href in links)
            + "</ul></div>" for title, links in self.t["footer_cols"])

    # ---------------------------------------------------------------- the paid audit and the Team waitlist

    def offers(self):
        t, urls = self.t, self.urls
        return {"audit_button": offer(urls["audit_checkout"], t["audit_buy"], t["soon"]),
                "soon_button": offer(urls["team_waitlist"], t["soon_button"], t["soon"]),
                "audit_gets": "\n".join(f"<li>{e(x)}</li>" for x in t["audit_gets"]),
                "audit_not": "\n".join(f"<li>{e(x)}</li>" for x in t["audit_not"])}

    def sample(self):
        """The real HTML report of the demo app, as Stingward writes it, with a note on top that says what it is."""
        t, lang, here = self.t, self.lang, SAMPLE[self.lang]
        other = "en" if lang == "pt" else "pt"
        report = cli(["./my-saas"], self.demo, lang, "html", self.online)
        note = (f'<aside class="sample" aria-label="{e(t["sample_label"])}"><div class="sample-in">'
                f'<p><strong>{e(t["sample_title"])}</strong> {e(fill(t["sample_text"]))}</p><p class="sample-links">'
                f'<a href="{link_to(PAGE_DIR[lang], here)}">{e(t["sample_home"])}</a>'
                f'<a href="{link_to(PAGE_DIR[lang], here)}#audit">{e(t["sample_audit"])}</a>'
                f'<a href="{link_to(SAMPLE[other], here)}" hreflang="{HREFLANG[other]}" '
                f'lang="{HREFLANG[other]}">{e(t["sample_other"])}</a></p></div></aside>')
        head, sep, body = report.partition("</head>")
        if not sep or head.count("</style>") != 1 or not head.endswith("</style>\n") or not body.startswith("\n<body>\n"):
            raise SystemExit("site: the HTML report changed shape; update Page.sample")
        # its address and its other language; these links load nothing, so the report's policy stays as it is
        links = f'<link rel="canonical" href="{address(here)}">\n{alternates(SAMPLE)}\n'
        return (head.replace("</style>", SAMPLE_CSS + "</style>") + links + sep
                + body.replace("<body>\n", "<body>\n" + note + "\n", 1))

    def render(self):
        t = self.t
        names, sheets, stage_scale = self.reports()
        where_rows, where_frame = self.where()
        own = re.search(r"(?:Nota|Grade): ([A-F])", cli(["skill", "skills/stingward"], ROOT, self.lang, online=self.online)).group(1)
        values = {k: e(fill(v)) for k, v in t.items() if isinstance(v, str)}
        values.update({
            "root": self.root, "url": URL, "repo": REPO, "version": __version__,
            "canonical": address(PAGE_DIR[self.lang]), "alternates": alternates(PAGE_DIR),
            "languages": self.languages(), "nav_links": self.nav(), "front_tab": e(t["tabs"][4]),
            "why_facts": self.why(),
            "hero_h1": "".join(f'<span class="line"><span data-line style="--i:{i}">{e(line)}</span></span>'
                               for i, line in enumerate(t["hero_h1"])),
            "hero_scale": self.scale(self.app_grade(), "./my-saas", "scale--hero"),
            "hero_copy": copy_button(t, "pipx install stingward"),
            "report_p": e(fill(t["report_p"])),
            "report_names": names, "report_sheets": sheets, "stage_scale": stage_scale,
            "where_rows": where_rows, "where_frame": where_frame,
            "proof_items": self.proof(), "faq_items": self.faq(), "find_rows": self.finds(),
            "price_lines": "\n".join(f"<li>{e(fill(x))}</li>" for x in t["price_lines"]),
            "cta_copy": copy_button(t, t["cta_cmd"], "button cta__button"),
            "cta_scale": self.scale(own, "skills/stingward", "scale--close"),
            "footer_cols": self.footer_cols(), "sample_href": self.sample_href, "csp": CSP_SLOT,
        })
        values.update(self.stages())
        values.update(self.offers())
        with open(os.path.join(SITE, "page.html"), encoding="utf-8") as fh:
            return with_policy(string.Template(fh.read()).substitute(values))


def build(out, online=False):
    with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
        text = json.load(fh)
    urls = links(text)
    tests = count_tests()
    files = {}
    with tempfile.TemporaryDirectory() as demo:
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "demo", "fixtures.py"), demo], check=True, capture_output=True)
        for lang in ("en", "pt"):
            page = Page(lang, text[lang], demo, online, tests, urls)
            files[posixpath.normpath(posixpath.join(PAGE_DIR[lang], "index.html"))] = page.render()
            files[posixpath.join(SAMPLE[lang], "index.html")] = page.sample()
    for old, (lang, new) in MOVED.items():
        rel_path = posixpath.join(old, "index.html")
        if rel_path in files:
            raise SystemExit(f"site: {old}/ is both a page and an old address")
        files[rel_path] = moved(text[lang], lang, old, new)
    if os.path.isdir(out):
        shutil.rmtree(out)
    for rel_path, content in files.items():
        path = os.path.join(out, *rel_path.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
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
