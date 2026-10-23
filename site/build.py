"""Builds the Stingward website into a folder, in English (the root) and Portuguese (pt/).

Every report and number on the page comes from this checkout: the script runs Stingward on the README
demos and on its own skill, reads the rules and counts the tests, so the site cannot drift from the code.
The sample report (example/ and pt/exemplo/) is the real HTML report of the demo app, with a note on top. The
sample of the paid report (example/full/ and pt/exemplo/completo/) is the same report with the AI review kept in
site/sample/: a comment on every finding and the summary on top, applied with --review and --notes.
The addresses the site had before English moved to the root (en/, en/example/ and exemplo/) are small pages
that send the visitor on to the new ones. The terms, privacy and refund pages of the paid report (terms/, privacy/ and
refund/, and the same under pt/) come from site/legal.json; the report service links to them at these addresses.

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
URL = "https://stingward.com/"
REPO = "https://github.com/HiveControlAgents/StingWard"
# The pages of the paid sample shown on the home page, printed by scripts/demo/record.mjs --report (docs/assets).
REPORT_PAGES = ("cover", "summary", "findings")
ASSETS = (["logo.svg", "social-preview.png", "flag-br.svg", "flag-us.svg"]
          + [f"demo-{d}-{lang}.{ext}" for d in ("app", "skill") for lang in ("pt", "en") for ext in ("mp4", "png")]
          + [f"report-{lang}-{name}.png" for lang in ("pt", "en") for name in REPORT_PAGES])
CACHE = os.path.join(tempfile.gettempdir(), "stingward-site-cache")
SEVERITY = {"🔴": "crit", "🟠": "high", "🟡": "med", "🔵": "low", "⚪": "info", "🟢": "ok"}
ROW = r"^   [^ :]+(?: [^ :]+){0,2}: "  # "   where: ...", "   how to fix: ..." under a finding
PAGE_DIR = {"en": ".", "pt": "pt"}  # English is the main site; Portuguese has its own folder
SAMPLE = {"en": "example", "pt": "pt/exemplo"}  # where each language's sample report is published
SAMPLE_AI = {"en": "example/full", "pt": "pt/exemplo/completo"}  # and the paid one, with the automatic review
HREFLANG = {"en": "en", "pt": "pt-BR"}
# The addresses the site had before English moved to the root, already shared, as old folder: (language, new folder).
# Pages cannot redirect, so each old folder gets a page that sends the visitor on (see moved()).
MOVED = {"en": ("en", "."), "en/example": ("en", "example"), "exemplo": ("pt", "pt/exemplo")}
LINKS = ("audit_checkout", "audit_waitlist", "team_waitlist")
LEGAL = ("terms", "privacy", "refund")  # folder names in each language's folder; the report service links to them
SUPPORT = "support@stingward.com"
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


def dot(sev):
    return f'<b class="dot dot--{sev}" aria-hidden="true"></b>'


def terminal(text):
    """The CLI's text report as HTML, one block per line, with the severity marks drawn as coloured dots."""
    out = []
    for line in text.rstrip("\n").split("\n"):
        mark = line[:1]
        if mark in SEVERITY and line[1:2] == " ":
            sev, rest = SEVERITY[mark], line[2:]
            label, _, title = rest.partition(" ")  # "CRITICAL" fills the padded column, so only one space may follow it
            if title and label.isupper() and len(label) > 1:
                out.append(f'<span class="t-find t-find--{sev}">{dot(sev)}<b class="t-lab">{e(label)}</b> {e(title.strip())}</span>')
            else:
                out.append(f'<span class="t-verdict t-verdict--{sev}">{dot(sev)}{e(rest)}</span>')
        elif re.match(r"^ \d+\. \S ", line) and line[4:5] in SEVERITY:  # "Fix these first" item
            num, _, rest = line.strip().partition(" ")
            title, sep, where = rest[2:].rpartition(" · ")
            if not sep:
                title, where = where, ""
            out.append(f'<span class="t-item"><i class="t-n">{e(num)}</i>{dot(SEVERITY[line[4]])}{e(title)}'
                       f'<span class="t-dim">{e(sep)}{e(where)}</span></span>')
        elif re.match(r"^(?:Corrija primeiro|Fix these first):$", line):
            out.append(f'<span class="t-head">{e(line)}</span>')
        elif re.match(ROW, line):
            key, _, val = line.strip().partition(": ")
            tag = re.search(r"\s+(\[[^\]]+\])$", val)
            if tag:
                val, tag = val[:tag.start()], f' <span class="t-dim">{e(tag.group(1))}</span>'
            out.append(f'<span class="t-row"><i>{e(key)}:</i> {e(val)}{tag or ""}</span>')
        elif line.startswith("   http"):
            out.append(f'<span class="t-row t-dim">{e(line.strip())}</span>')
        elif re.match(r"^(?:Resumo|Summary):", line):
            out.append(f'<span class="t-sum">{e(line)}</span>')
        elif re.match(r"^stingward \S+ · |^(?:Sources|Bases consultadas|README badge|Selo para o README):", line):
            out.append(f'<span class="t-dim">{e(line)}</span>')
        else:
            out.append(f'<span class="t-line">{e(line)}</span>' if line else '<span class="t-gap"></span>')
    return "".join(out)


def split_fact(num, text):
    """"23.8 million" and "keys and passwords..." become "23.8" and "million keys and passwords...": the same words in
    the same order, with the figure alone in the column of figures."""
    head, _, unit = num.partition(" ")
    return (head, f"{unit} {text}") if unit else (num, text)


def fill(s, extra=None):
    values = {"version": __version__, "rules": str(len(RULES)), "repo": REPO, **(extra or {})}
    for k, v in values.items():
        s = s.replace("{" + k + "}", v)
    return s


def count_tests():
    return unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), top_level_dir=ROOT).countTestCases()


def size(path):
    """Width and height of a PNG, from its header."""
    with open(path, "rb") as fh:
        head = fh.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"site: {path} is not a PNG")
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def video(root, name, label):
    """A demo recording as a muted loop; its poster is the final frame, which is all a still page needs."""
    width, height = size(os.path.join(ROOT, "docs", "assets", name + ".png"))
    return (f'<video class="demo" src="{root}assets/{name}.mp4" poster="{root}assets/{name}.png" width="{width}" '
            f'height="{height}" muted loop playsinline preload="none" aria-label="{e(label)}"></video>')


def copy_button(t, command, cls="button"):
    return (f'<button class="{cls}" type="button" data-copy="{e(command)}" data-done="{e(t["copied"])}" '
            f'data-failed="{e(t["copy_failed"])}"><span>{e(t["copy"])}</span></button>')


def links(text):
    """The checkout and waitlist addresses from text.json. Empty means not open yet; anything else must be https.
    An address can also be given per language, as {"en": ..., "pt": ...}, for a form written in each language."""
    given = text.get("links", {})
    for key in LINKS:
        url = given.get(key, "")
        urls = url.items() if isinstance(url, dict) else [(None, url)]
        for lang, one in urls:
            if lang is not None and lang not in PAGE_DIR or not isinstance(one, str) or one and not HTTPS.fullmatch(one):
                raise SystemExit(f"site/text.json: links.{key} must be empty, an https:// address or one per language,"
                                 f" not {url!r}")
    return {key: given.get(key, "") for key in LINKS}


def link_for(url, lang):
    """The address of one language's page, from a value of links()."""
    return url.get(lang, "") if isinstance(url, dict) else url


def offer(url, label, soon, cls="button", buy=False):
    """A buy or sign-up button. Until its address exists it is a plain label, so nothing on the page takes payment.
    buy: the button to the buy page or its waitlist, which app.js gives the label of the ad the visitor came from."""
    if url:
        return f'<a class="{cls}" href="{e(url)}"{" data-buy" if buy else ""}>{e(label)}</a>'
    return f'<span class="{cls} button--soon" role="link" aria-disabled="true">{e(soon)}</span>'


def link_to(target, here):
    """Relative link from the folder `here` to the folder `target`, both given from the site root ("." is the root)."""
    path = posixpath.relpath(target, here)
    return "./" if path == "." else path + "/"


def address(folder):
    """The published address of a folder given from the site root."""
    return URL if folder == "." else URL + folder + "/"


def legal_folders(key):
    """Where a legal page is published in each language, given from the site root ("terms", "pt/terms")."""
    return {lang: posixpath.normpath(posixpath.join(folder, key)) for lang, folder in PAGE_DIR.items()}


def languages(lang, folders):
    """The language switch of a page published in both languages; the page you are on is marked, not linked.
    Portuguese comes first: the site is English by default, so the switch leads with the other language."""
    links, root = [], "" if folders[lang] == "." else link_to(".", folders[lang])
    for key, name, short, flag in (("pt", "Português", "PT", "br"), ("en", "English", "EN", "us")):
        code = HREFLANG[key]
        label = (f'<img class="lang__flag" src="{root}assets/flag-{flag}.svg" alt="" width="16" height="12">'
                 f'<span class="lang__long">{name}</span><span class="lang__short" aria-hidden="true">{short}</span>')
        if key == lang:
            links.append(f'<span lang="{code}" aria-current="page">{label}</span>')
        else:
            links.append(f'<a href="{link_to(folders[key], folders[lang])}" hreflang="{code}" lang="{code}">{label}</a>')
    return "".join(links)


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
SAMPLE_CSS = (".sample{background:#0e1013;color:#f1f2f4}"
              ".sample-in{display:grid;gap:10px;max-width:880px;margin:0 auto;padding:20px 64px;font-size:14px;line-height:1.55}"
              ".sample p{max-width:66ch}.sample strong{color:#f5b83d;font-weight:600}"
              ".sample-links{display:flex;flex-wrap:wrap;gap:6px 24px}"
              ".sample a{color:#f1f2f4;font-weight:600;text-decoration-color:#f5b83d;text-decoration-thickness:2px;text-underline-offset:4px}"
              ".sample a:hover{color:#f5b83d}"
              ".sample a:focus-visible{outline:3px solid #f5b83d;outline-offset:3px}"
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
<style>body{{margin:0;padding:32px 16px;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:#0e1013;color:#f1f2f4;overflow-wrap:anywhere}}a{{color:inherit;font-weight:600;text-decoration-color:#f5b83d;text-underline-offset:4px}}</style>
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


GRADE = re.compile(r"(?:Nota|Grade): ([A-F])")


class Page:
    # The report open when the page loads: the demo app, the one most visitors will recognise as their own.
    FIRST_REPORT = 1

    def __init__(self, lang, t, demo, online, tests, urls=None):
        self.lang, self.t, self.demo, self.online, self.tests = lang, t, demo, online, tests
        self.urls = {key: link_for(url, lang) for key, url in (urls or dict.fromkeys(LINKS, "")).items()}
        self.root = "" if PAGE_DIR[lang] == "." else link_to(".", PAGE_DIR[lang])
        self.sample_href = link_to(SAMPLE[lang], PAGE_DIR[lang])
        self.sample_ai_href = link_to(SAMPLE_AI[lang], PAGE_DIR[lang])

    def app_grade(self):
        return json.loads(cli(["./my-saas"], self.demo, self.lang, "json", self.online))["grade"]

    # ---------------------------------------------------------------- top of the page

    def nav(self):
        targets = ["#audit", "#why", "#finds", "#price"]
        return "".join(f'<a class="nav__link" href="{href}">{e(name)}</a>' for href, name in zip(targets, self.t["tabs"]))

    def languages(self):
        return languages(self.lang, PAGE_DIR)

    # ---------------------------------------------------------------- the three real reports, in the terminal

    def reports(self):
        """A tab for each report, with the grade it really got, and the report itself as the terminal prints it."""
        t, lang = self.t, self.lang
        runs = [(["skill", "./pdf-helper"], self.demo, "stingward skill ./pdf-helper"),
                (["./my-saas"], self.demo, "stingward ./my-saas"),
                (["skill", "skills/stingward"], ROOT, "stingward skill skills/stingward")]
        tabs, panels = [], []
        for i, ((args, cwd, shown), item) in enumerate(pairs("reports", runs, t["reports"])):
            text = cli(args, cwd, lang, online=self.online)
            grade = GRADE.search(text).group(1)
            on = i == self.FIRST_REPORT
            tabs.append(
                f'<button class="term__tab" type="button" role="tab" id="report-tab-{i}" aria-controls="report-out-{i}" '
                f'aria-selected="{str(on).lower()}" tabindex="{0 if on else -1}" data-grade="{grade}">'
                f'<span class="term__name">{e(item["name"])}</span><span class="term__grade">{e(t["grade_word"])} {grade}</span></button>')
            panels.append(
                f'<pre class="term__out" role="tabpanel" id="report-out-{i}" aria-labelledby="report-tab-{i}" tabindex="0"'
                f'{"" if on else " data-off"}><span class="t-note"><b aria-hidden="true"># </b>{e(item["note"])}</span>'
                f'<span class="t-cmd"><b aria-hidden="true">$ </b>{e(shown)}</span>{terminal(text)}</pre>')
        return "\n".join(tabs), "\n".join(panels)

    # ---------------------------------------------------------------- the paid report, as it prints

    def pages(self):
        """Three pages of the paid sample report as it prints: the cover with the grade, the summary and the first
        page of findings. They are the report a visitor who doesn't read terminals gets, and each opens the whole sample."""
        items = []
        for name, (caption, alt) in pairs("pages", REPORT_PAGES, self.t["pages"]):
            file = f"report-{self.lang}-{name}.png"
            width, height = size(os.path.join(ROOT, "docs", "assets", file))
            items.append(f'<li class="sheet sheet--{name}"><figure><a href="{self.sample_ai_href}"><img src="{self.root}assets/{file}" '
                         f'width="{width}" height="{height}" alt="{e(alt)}" decoding="async"></a>'
                         f'<figcaption>{e(caption)}</figcaption></figure></li>')
        return "\n".join(items)

    # ---------------------------------------------------------------- why

    def why(self):
        rows = []
        for num, text, source, link in self.t["why_facts"]:
            figure, caption = split_fact(num, text)
            rows.append(f'<li class="led"><p class="led__num" data-reveal>{e(figure)}</p>'
                        f'<p class="led__cap" data-reveal>{e(caption)} <a class="src" href="{e(link)}">{e(source)}</a></p></li>')
        return "\n".join(rows)

    # ---------------------------------------------------------------- how it works

    def stages(self):
        """The four stages of an audit of the demo app, each with the piece of it that stage really produces."""
        t = self.t
        app = os.path.join(self.demo, "my-saas")
        files = sorted(os.path.relpath(os.path.join(d, f), app).replace(os.sep, "/")
                       for d, _, fs in os.walk(app) for f in fs)
        frag_files = (f'<p class="frag__title">{e(fill(t["files_read"], {"n": str(len(files))}))}</p><ul class="frag__files">'
                      + "".join(f"<li><code>{e(f)}</code></li>" for f in files) + "</ul>")
        # What the dependency check sends: each pinned version, and the lowest version of each range without a lockfile.
        pinned, _, ranges = deps.collect(Context(root=app, files=files))
        pkgs = sorted({(eco, name, ver) for eco, name, ver, _, _ in pinned} | {(r.eco, r.name, r.floor) for r in ranges})
        queries = ",\n".join(" " + json.dumps({"package": {"ecosystem": eco, "name": n}, "version": v}) for eco, n, v in pkgs)
        body = '{"queries": [\n' + queries + "\n]}"
        frag_osv = f'<p class="frag__title">{e(t["sent_to"])}</p><pre class="frag__code">{e(body)}</pre>'
        groups = {}
        for rule in RULES:
            groups.setdefault(rule[:3], []).append(rule)
        frag_checks = '<ul class="frag__groups">' + "".join(
            f'<li><span class="frag__group">{e(t["groups"][g])}</span><b class="frag__count">{len(ids)}</b>'
            f'<code class="frag__ids">{" ".join(e(i) for i in ids)}</code></li>'
            for g, ids in sorted(groups.items(), key=lambda kv: -len(kv[1]))) + "</ul>"
        grade = self.app_grade()  # the only grade marked here is the one the demo app really got
        frag_grade = (f'<p class="frag__title">./my-saas</p><ol class="frag__grades" aria-label="{e(t["grades_label"])}">'
                      + "".join(f'<li class="frag__grade{" is-on" if g == grade else ""}"><b>{g}</b> <span>{e(m)}</span></li>'
                                for g, m in t["grades"]) + "</ol>")
        frags = [("files", frag_files), ("osv", frag_osv), ("checks", frag_checks), ("grade", frag_grade)]
        steps = []
        for i, ((kind, frag), stage) in enumerate(pairs("stages", frags, t["stages"]), 1):
            steps.append(f'<li class="step step--{kind}"><h3 class="step__clause" data-reveal>{e(fill(stage["clause"]))}</h3>'
                         f'<p class="step__detail" data-reveal>{e(fill(stage["detail"]))}</p>'
                         f'<div class="frag frag--{kind}" data-ui data-reveal role="group" aria-label="{e(stage["name"])}">{frag}</div></li>')
        return {"how_steps": "\n".join(steps)}

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
        """Four places Stingward runs, as tabs beside one view: the two terminal recordings, the Claude Code and Codex commands and
        the first rows of the real pull request comment."""
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
            ("video", video(root, f"demo-app-{lang}", rows[0]["alt"])),
            ("video", video(root, f"demo-skill-{lang}", rows[1]["alt"])),
            ("cc", '<div class="cc" data-ui><p class="cc__tool">Claude Code</p>'
                   '<p><code>/plugin marketplace add HiveControlAgents/StingWard</code></p>'
                   '<p><code>/plugin install stingward@stingward</code></p>'
                   '<p class="cc__tool">Codex</p>'
                   '<p class="cc__sh"><code>codex plugin marketplace add HiveControlAgents/StingWard</code></p>'
                   '<p class="cc__sh"><code>codex plugin add stingward@stingward</code></p>'
                   f'<p class="cc__ask"><code>&gt; {e(rows[2]["ask1"])}</code></p><p class="cc__ask"><code>&gt; {e(rows[2]["ask2"])}</code></p></div>'),
            ("pr", f'<div class="pr" data-ui><p class="pr__head"><span class="pr__grade">stingward {e(app_text["grade"])}</span> '
                   f'{e(rows[3]["comment_title"])}</p><ul class="pr__rows">{comment_rows}</ul></div>'),
        ]
        tabs, panes = [], []
        for i, ((kind, prev), row) in enumerate(pairs("where", previews, rows)):
            on = i == 0
            tabs.append(f'<button class="dock__tab" type="button" role="tab" id="where-tab-{i}" aria-controls="where-pane-{i}" '
                        f'aria-selected="{str(on).lower()}" tabindex="{0 if on else -1}"><span class="dock__name">{e(row["name"])}</span>'
                        f'<code class="dock__cmd">{e(row["cmd"])}</code></button>')
            panes.append(f'<div class="dock__pane dock__pane--{kind}" role="tabpanel" id="where-pane-{i}" aria-labelledby="where-tab-{i}" '
                         f'tabindex="0"{"" if on else " data-off"}>{prev}</div>')
        return "\n".join(tabs), "\n".join(panes)

    # ---------------------------------------------------------------- the rest

    def proof(self):
        return "\n".join(
            f'<li><a class="tile" href="{e(fill(link))}"><strong class="tile__name">{e(fill(name, {"tests": str(self.tests)}))}</strong>'
            f'<span class="tile__line">{e(line)}</span></a></li>' for name, line, link in self.t["proof"])

    def faq(self):
        return "\n".join(
            f'<details class="faq__item" name="faq"><summary><span class="faq__q">{e(q)}</span><i class="faq__sign" aria-hidden="true"></i></summary>'
            f'<p class="faq__a">{e(a)}</p></details>' for q, a in self.t["faq"])

    def footer_cols(self):
        return "\n".join(
            f'<div class="footer__col"><h3>{e(title)}</h3><ul>'
            + "".join(f'<li><a href="{e(fill(href, {"sample": self.sample_href}))}">{e(fill(name))}</a></li>'
                      for name, href in links)
            + "</ul></div>" for title, links in self.t["footer_cols"])

    # ---------------------------------------------------------------- the paid audit and the Team waitlist

    def offers(self):
        t, urls = self.t, self.urls
        if urls["audit_checkout"] or not urls["audit_waitlist"]:
            audit = offer(urls["audit_checkout"], t["audit_buy"], t["soon"], buy=True)
        else:  # not on sale yet: the button takes the visitor to the waitlist instead
            audit = offer(urls["audit_waitlist"], t["audit_waitlist"], t["soon"], buy=True)
        return {"audit_button": audit,
                "soon_button": offer(urls["team_waitlist"], t["soon_button"], t["soon"]),
                "audit_gets": "\n".join(f"<li>{e(x)}</li>" for x in t["audit_gets"]),
                "audit_not": "\n".join(f"<li>{e(x)}</li>" for x in t["audit_not"])}

    def sample(self, ai=False):
        """The real HTML report of the demo app, as Stingward writes it, with a note on top that says what it is.
        ai: with the AI review of site/sample/, run with --no-ignore as the report service runs it."""
        t, lang = self.t, self.lang
        folders, twin = (SAMPLE_AI, SAMPLE) if ai else (SAMPLE, SAMPLE_AI)
        here, other = folders[lang], "en" if lang == "pt" else "pt"
        args = ["./my-saas"]
        if ai:
            review, shown = os.path.join(SITE, "sample", f"review-{lang}.json"), f"site/sample/review-{lang}.json"
            args += ["--no-ignore", "--review", review, "--notes", os.path.join(SITE, "sample", f"notes-{lang}.md")]
            got = json.loads(cli(args, self.demo, lang, "json", self.online))["review"]
            if got["counts"].get("unreviewed"):  # a finding the review file does not have would read "not reviewed yet"
                raise SystemExit(f"site: {shown} has no comment for "
                                 f"{got['counts']['unreviewed']} finding(s) of the demo app")
            if got["masked"]:
                raise SystemExit(f"site: something in {shown} or its notes looks like a secret")
        report = cli(args, self.demo, lang, "html", self.online)
        title, text, see = ((t["sample_ai_title"], t["sample_ai_text"], t["sample_plain"]) if ai else
                            (t["sample_title"], t["sample_text"], t["sample_with_ai"]))
        note = (f'<aside class="sample" aria-label="{e(t["sample_label"])}"><div class="sample-in">'
                f'<p><strong>{e(title)}</strong> {e(fill(text))}</p><p class="sample-links">'
                f'<a href="{link_to(PAGE_DIR[lang], here)}">{e(t["sample_home"])}</a>'
                f'<a href="{link_to(PAGE_DIR[lang], here)}#audit">{e(t["sample_audit"])}</a>'
                f'<a href="{link_to(twin[lang], here)}">{e(see)}</a>'
                f'<a href="{link_to(folders[other], here)}" hreflang="{HREFLANG[other]}" '
                f'lang="{HREFLANG[other]}">{e(t["sample_other"])}</a></p></div></aside>')
        head, sep, body = report.partition("</head>")
        if not sep or head.count("</style>") != 1 or not head.endswith("</style>\n") or not body.startswith("\n<body>\n"):
            raise SystemExit("site: the HTML report changed shape; update Page.sample")
        # its address and its other language; these links load nothing, so the report's policy stays as it is
        links = f'<link rel="canonical" href="{address(here)}">\n{alternates(folders)}\n'
        return (head.replace("</style>", SAMPLE_CSS + "</style>") + links + sep
                + body.replace("<body>\n", "<body>\n" + note + "\n", 1))

    def render(self):
        t = self.t
        report_tabs, report_panels = self.reports()
        where_tabs, where_panes = self.where()
        values = {k: e(fill(v)) for k, v in t.items() if isinstance(v, str)}
        values.update({
            "root": self.root, "url": URL, "repo": REPO, "version": __version__,
            "canonical": address(PAGE_DIR[self.lang]), "alternates": alternates(PAGE_DIR),
            "languages": self.languages(), "nav_links": self.nav(), "front_tab": e(t["tabs"][4]),
            "why_facts": self.why(), "report_pages": self.pages(),
            "hero_h1": "".join(f'<span class="line"><span>{e(line)}</span></span>' for line in t["hero_h1"]),
            "hero_hooks": e(json.dumps(t["hero_hooks"], ensure_ascii=False)),
            "hero_copy": copy_button(t, "pipx install stingward", "button install__copy"),
            "report_p": e(fill(t["report_p"])),
            "report_tabs": report_tabs, "report_panels": report_panels,
            "where_tabs": where_tabs, "where_panes": where_panes,
            "proof_items": self.proof(), "faq_items": self.faq(), "find_rows": self.finds(),
            "price_lines": "\n".join(f"<li>{e(fill(x))}</li>" for x in t["price_lines"]),
            "cta_copy": copy_button(t, t["cta_cmd"], "button cta__copy"),
            "footer_cols": self.footer_cols(), "sample_href": self.sample_href, "sample_ai_href": self.sample_ai_href,
            "csp": CSP_SLOT,
            "legal_label": e(legal_texts()[self.lang]["label"]),
            # the price in another currency, where the language's own one is not what everyone pays (empty: no line)
            "audit_note": f'<p class="audit__note" data-reveal>{e(t["audit_note"])}</p>' if t["audit_note"] else "",
            "legal_links": legal_nav(legal_texts()[self.lang], self.lang, PAGE_DIR[self.lang]),
        })
        values.update(self.stages())
        values.update(self.offers())
        with open(os.path.join(SITE, "page.html"), encoding="utf-8") as fh:
            return with_policy(string.Template(fh.read()).substitute(values))


# ---------------------------------------------------------------- terms, privacy and refunds

# The legal pages load the site's stylesheet, font and logo, and no script at all.
LEGAL_CSP = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'"
LEGAL_PAGE = """<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<title>{title} · Stingward</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{url}">
{alternates}
<meta name="theme-color" content="#0e1013">
<meta name="color-scheme" content="dark">
<link rel="icon" href="{root}assets/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<a class="skip" href="#main">{skip}</a>
<header class="top">
  <a class="brand" href="{home}" aria-label="Stingward"><img src="{root}assets/logo.svg" alt="" width="26" height="26"><span>Stingward</span></a>
  <nav class="lang" aria-label="{lang_label}">{languages}</nav>
</header>
<main class="legal" id="main">
<h1 class="head">{title}</h1>
<p class="legal__lead">{intro}</p>
{sections}
<p class="legal__date">{updated}</p>
</main>
<footer class="footer footer--legal">
  <div class="footer__last">
    <p>{copy}</p>
    <nav class="footer__legal" aria-label="{legal_label}">{legal_links}</nav>
    <a href="{home}">{home_label}</a>
  </div>
</footer>
</body>
</html>
"""
INLINE_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


@functools.lru_cache(maxsize=None)
def legal_texts():
    with open(os.path.join(SITE, "legal.json"), encoding="utf-8") as fh:
        words = json.load(fh)
    for lang in PAGE_DIR:
        if sorted(words[lang]["pages"]) != sorted(LEGAL):
            raise SystemExit(f"site/legal.json: {lang} must have exactly the pages {', '.join(LEGAL)}")
    return words


def legal_nav(words, lang, here, current=None):
    """Links to the three legal pages, from the folder `here`; the one you are on is marked, not linked."""
    out = []
    for key in LEGAL:
        name = e(words["pages"][key]["name"])
        if key == current:
            out.append(f'<span aria-current="page">{name}</span>')
        else:
            out.append(f'<a href="{link_to(legal_folders(key)[lang], here)}">{name}</a>')
    return "".join(out)


def _plain(text):
    if "](" in text:
        raise SystemExit(f"site/legal.json: a link is not written as [words](target): {text!r}")
    return e(text).replace(SUPPORT, f'<a href="mailto:{SUPPORT}">{SUPPORT}</a>')


def inline(text, lang, here):
    """A sentence of legal.json as HTML: escaped, the support address as a mail link, and [words](target) as a link
    to another legal page (terms, privacy, refund) or to an https:// address. Any other target stops the build."""
    out, last = [], 0
    for m in INLINE_LINK.finditer(text):
        words, target = m.groups()
        if target in LEGAL:
            href = link_to(legal_folders(target)[lang], here)
        elif HTTPS.fullmatch(target):
            href = target
        else:
            raise SystemExit(f"site/legal.json: {target!r} is not terms, privacy, refund or an https:// address")
        out += [_plain(text[last:m.start()]), f'<a href="{e(href)}">{_plain(words)}</a>']
        last = m.end()
    return "".join(out) + _plain(text[last:])


def blocks(items, lang, here):
    """A section's body: a string is a paragraph, a list of strings is a list."""
    return "\n".join("<ul>" + "".join(f"<li>{inline(x, lang, here)}</li>" for x in item) + "</ul>" if isinstance(item, list)
                     else f"<p>{inline(item, lang, here)}</p>" for item in items)


def legal(t, words, lang, key):
    """The terms, privacy or refund page in one language. t is the language's text.json, words its legal.json."""
    folders = legal_folders(key)
    here, doc = folders[lang], words["pages"][key]
    sections = "\n".join(f"<section>\n<h2>{e(head)}</h2>\n{blocks(items, lang, here)}\n</section>"
                         for head, items in doc["sections"])
    return LEGAL_PAGE.format(
        lang=HREFLANG[lang], csp=LEGAL_CSP, title=e(doc["title"]), description=e(doc["description"]), url=address(here),
        alternates=alternates(folders), root=link_to(".", here), skip=e(t["skip"]), home=link_to(PAGE_DIR[lang], here),
        lang_label=e(t["lang_label"]), languages=languages(lang, folders), intro=inline(doc["intro"], lang, here),
        sections=sections, updated=e(words["updated"]), copy=e(words["copy"]), legal_label=e(words["label"]),
        legal_links=legal_nav(words, lang, here, key), home_label=e(words["home"]))


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
            files[posixpath.join(SAMPLE_AI[lang], "index.html")] = page.sample(ai=True)
    for old, (lang, new) in MOVED.items():
        rel_path = posixpath.join(old, "index.html")
        if rel_path in files:
            raise SystemExit(f"site: {old}/ is both a page and an old address")
        files[rel_path] = moved(text[lang], lang, old, new)
    words = legal_texts()
    for lang in PAGE_DIR:
        for key in LEGAL:
            rel_path = posixpath.join(legal_folders(key)[lang], "index.html")
            if rel_path in files:
                raise SystemExit(f"site: {key}/ is published twice")
            files[rel_path] = legal(text[lang], words[lang], lang, key)
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
