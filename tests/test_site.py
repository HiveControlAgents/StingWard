"""O site é montado a partir deste checkout; estes testes montam o site e conferem o que ele promete."""
import base64
import hashlib
import html
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from stingward import __version__, report, report_html, scan
from stingward.rules import RULES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
FAKE_KEY_PART = "Demo7Fake9Key0Not4Real"
PAGES = {"pt": "index.html", "en": os.path.join("en", "index.html")}
SAMPLES = {"pt": os.path.join("exemplo", "index.html"), "en": os.path.join("en", "example", "index.html")}


def _text():
    with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _builder():
    spec = importlib.util.spec_from_file_location("stingward_site_build", os.path.join(SITE, "build.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _shape(value):
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(v) for v in value]
    return type(value).__name__


class Site(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.build = _builder()
        cls.out = cls.build.build(os.path.join(cls.tmp.name, "site"))
        cls.pages, cls.samples = {}, {}
        for pages, paths in ((cls.pages, PAGES), (cls.samples, SAMPLES)):
            for lang, rel in paths.items():
                with open(os.path.join(cls.out, rel), encoding="utf-8") as fh:
                    pages[lang] = fh.read()

    def every_page(self):
        for lang in PAGES:
            yield lang, PAGES[lang], self.pages[lang]
            yield lang, SAMPLES[lang], self.samples[lang]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_both_languages_have_the_same_texts(self):
        with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
            text = json.load(fh)
        self.assertEqual(_shape(text["pt"]), _shape(text["en"]))

    def test_a_list_that_no_longer_matches_the_page_fails_the_build(self):
        # The page pairs some text.json lists with what it builds (reports, stages, where). One entry more or less in
        # both languages keeps the shapes equal, so the build has to say so instead of dropping the extra one.
        pt = _text()["pt"]
        demo = os.path.join(self.tmp.name, "demo")
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "demo", "fixtures.py"), demo], check=True, capture_output=True)
        for key in ("reports", "stages", "where"):
            t = dict(pt, **{key: pt[key] + pt[key][-1:]})
            with self.assertRaises(SystemExit) as caught:
                getattr(self.build.Page("pt", t, demo, False, 0), key)()
            self.assertIn(f"site/text.json: {key} has {len(pt[key]) + 1} entries", str(caught.exception))
        for page, text in (([1, 2, 3, 4], [1, 2, 3, 4, 5]), ([1, 2, 3, 4], [1, 2, 3])):
            with self.assertRaises(SystemExit):
                list(self.build.pairs("where", page, text))
        self.assertEqual(list(self.build.pairs("where", [1, 2], ["a", "b"])), [(1, "a"), (2, "b")])

    def test_the_pull_request_preview_shows_the_rows_of_the_real_comment(self):
        # The PR comment merges one problem found in several places into one row, in the order of report.merge. The
        # preview shows its first rows the same way: the public key in .env and in the chat route is one row, not two.
        demo = os.path.join(self.tmp.name, "demo-pr")
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "demo", "fixtures.py"), demo], check=True, capture_output=True)
        _, findings = scan.run(os.path.join(demo, "my-saas"), offline=True)
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                rows = page.split('class="pr__rows">', 1)[1].split("</ul>", 1)[0]
                got = re.findall(r'<li><b class="sev sev--\w+">([^<]+)</b> (.*?)<code>(.*?)</code></li>', rows)
                shown, _ = report.split(report.merge(findings, lang))
                want = [(report.LABEL[lang][x.severity], html.escape(x.title), html.escape(report.places(x, lang, limit=5)))
                        for x in shown[:5]]
                self.assertEqual(got, want)
                self.assertEqual(rows.count("NEXT_PUBLIC_OPENAI_API_KEY"), 1)
                self.assertIn("<code>.env:1, app/api/chat/route.ts:3</code>", rows)

    def test_nothing_is_left_unfilled(self):
        for lang, rel, page in self.every_page():
            with self.subTest(page=rel):
                if rel in PAGES.values():  # the sample report quotes the demo's own code, ${user} included
                    self.assertNotIn("${", page)
                self.assertIsNone(re.search(r"\{(?:version|rules|repo|tests|n|sample)\}", page))

    def test_the_reports_are_real_output(self):
        pt, en = self.pages["pt"], self.pages["en"]
        self.assertIn("Não instale ainda: há problemas graves.", pt)
        self.assertIn("Do not install yet: serious problems found.", en)
        self.assertIn("Nota F.", pt)
        self.assertIn("Nota A.", pt)
        self.assertIn(f"stingward {__version__}", pt)
        self.assertIn(f"{len(RULES)} regras", pt)
        self.assertIn(f"{len(RULES)} rules", en)

    def test_the_fake_key_never_shows(self):
        for lang, rel, page in self.every_page():
            with self.subTest(page=rel):
                self.assertNotIn(FAKE_KEY_PART, page)
                self.assertNotIn("sk-proj-", page)

    def test_local_links_and_files_exist(self):
        for lang, rel, page in self.every_page():
            base = os.path.dirname(os.path.join(self.out, rel))
            for target in re.findall(r'(?:href|src|poster)="([^"]+)"', page):
                if re.match(r"^[a-z]+:|^#", target):
                    continue
                with self.subTest(page=rel, link=target):
                    path = os.path.normpath(os.path.join(base, target.split("#", 1)[0]))
                    self.assertTrue(os.path.exists(path), path)

    def test_in_page_links_point_at_sections_that_exist(self):
        for lang, rel, page in self.every_page():
            base = os.path.dirname(os.path.join(self.out, rel))
            for target in re.findall(r'href="([^"#]*)#([^"]+)"', page):
                with self.subTest(page=rel, target=target):
                    if target[0] and re.match(r"^[a-z]+:", target[0]):
                        continue
                    linked = page if not target[0] else self.read(os.path.join(base, target[0]))
                    self.assertIn(f' id="{target[1]}"', linked)

    def read(self, path):
        path = os.path.join(path, "index.html") if os.path.isdir(path) else path
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_language_switch_marks_the_current_page(self):
        self.assertIn('<span lang="pt-BR" aria-current="page">', self.pages["pt"])
        self.assertIn('<a href="en/" hreflang="en" lang="en">', self.pages["pt"])
        self.assertIn('<span lang="en" aria-current="page">', self.pages["en"])
        self.assertIn('<a href="../" hreflang="pt-BR" lang="pt-BR">', self.pages["en"])

    def test_every_number_on_why_it_exists_links_its_source(self):
        with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
            text = json.load(fh)
        for lang, page in self.pages.items():
            for number, _, source, link, _ in text[lang]["why_facts"]:
                with self.subTest(lang=lang, number=number):
                    self.assertTrue(link.startswith("https://"))
                    self.assertIn(f'href="{link}">{source}</a>', page)

    def test_the_bars_on_why_it_exists_draw_the_numbers_they_stand_for(self):
        """Each bar is a share drawn to scale. It must be the share the sentence states, not a shape that looks right:
        45% fills 45 of 100, 170 of 1,645 apps fills 170 of 1,645, and the 13% inside the 36% is in the same sentence."""
        sep = {"pt": ".", "en": ","}
        for lang, page in self.pages.items():
            for number, text, _, _, bars in _text()[lang]["why_facts"]:
                with self.subTest(lang=lang, number=number):
                    said = number + " " + text
                    for part, whole in bars:
                        self.assertLess(0, part)
                        self.assertLessEqual(part, whole)
                        if whole == 100:
                            self.assertIn(f"{part}%", said)
                        else:
                            self.assertIn(str(part), number)
                            self.assertIn(f"{whole:,}".replace(",", sep[lang]), said)
                        self.assertIn(f'style="--w:{100 * part / whole:.1f}%"', page)
                    if bars:  # the widest part is the number in big type
                        part, whole = max(bars, key=lambda b: b[0] / b[1])
                        self.assertEqual(number, f"{part}%" if whole == 100 else str(part))

    def test_sales_are_announced_and_nothing_takes_payment(self):
        self.assertIn("Em breve", self.pages["pt"])
        self.assertIn("Coming soon", self.pages["en"])
        for lang, rel, page in self.every_page():
            with self.subTest(page=rel):
                self.assertNotIn("<form", page)
                self.assertNotIn("<input type=\"email\"", page)

    # ---------------------------------------------------------------- the paid audit and the Team waitlist

    def test_buy_and_waitlist_buttons_wait_for_their_addresses(self):
        """While text.json has no address, the buttons say "Em breve" and are not links; nothing can be bought yet."""
        text = _text()
        self.assertEqual(text["links"], {"audit_checkout": "", "team_waitlist": ""})
        for lang, page in self.pages.items():
            t = text[lang]
            with self.subTest(lang=lang):
                audit = page.split('id="audit"', 1)[1].split("</section>", 1)[0]
                soon = re.findall(r'<span class="button[^"]*button--soon" role="link" aria-disabled="true">([^<]+)</span>', audit)
                self.assertEqual(soon, [t["soon"], t["soon"]])
                for label in (t["audit_buy"], t["soon_button"]):
                    self.assertNotRegex(page, r"<a [^>]*>" + re.escape(label) + "</a>")
                self.assertNotIn('href=""', page)

    def test_buttons_link_once_an_address_is_set(self):
        text = _text()
        urls = {"audit_checkout": "https://pay.example.com/audit", "team_waitlist": "https://forms.example.com/team"}
        for lang in PAGES:
            with self.subTest(lang=lang):
                offers = self.build.Page(lang, text[lang], None, False, 0, urls).offers()
                self.assertEqual(offers["audit_button"], f'<a class="button" href="{urls["audit_checkout"]}">'
                                                         f'{text[lang]["audit_buy"]}</a>')
                self.assertEqual(offers["soon_button"], f'<a class="button" href="{urls["team_waitlist"]}">'
                                                        f'{text[lang]["soon_button"]}</a>')

    def test_only_https_addresses_are_accepted(self):
        self.assertEqual(self.build.links({}), {"audit_checkout": "", "team_waitlist": ""})
        self.assertEqual(self.build.links({"links": {"audit_checkout": "https://pay.example.com/a?b=1"}})["audit_checkout"],
                         "https://pay.example.com/a?b=1")
        for bad in ("http://pay.example.com", "javascript:alert(1)", "//pay.example.com", "https://a.example/\" onclick=\"x", 149):
            with self.subTest(url=bad), self.assertRaises(SystemExit):
                self.build.links({"links": {"team_waitlist": bad}})

    def test_the_audit_offer_says_what_it_costs_and_covers(self):
        text = _text()
        for lang, page in self.pages.items():
            t = text[lang]
            audit = page.split('id="audit"', 1)[1].split("</section>", 1)[0]
            with self.subTest(lang=lang):
                self.assertIn(t["audit_h2"], audit)
                self.assertIn(f'<span class="figure__cur">US$</span><span class="figure__num">149</span>', audit)
                self.assertIn("48 h", t["audit_per"])
                for line in t["audit_gets"] + t["audit_not"]:
                    self.assertIn(f"<li>{line}</li>", audit)
                self.assertIn(t["soon_h3"], audit)
                # the sample report's note repeats the price: it must be the same one
                self.assertIn(f'{t["audit_currency"]} {t["audit_price"]}', t["sample_audit"])

    # ---------------------------------------------------------------- the sample report

    def test_sample_report_is_linked_from_the_home_page(self):
        for lang, href in (("pt", "exemplo/"), ("en", "example/")):
            with self.subTest(lang=lang):
                self.assertIn(f'<a class="button" href="{href}">{_text()[lang]["report_sample"]}</a>', self.pages[lang])

    def test_sample_report_is_the_real_html_report_of_the_demo_app(self):
        heads = {"pt": "Resumo executivo", "en": "Executive summary"}
        for lang, page in self.samples.items():
            with self.subTest(lang=lang):
                self.assertTrue(page.startswith("<!doctype html>"))
                self.assertIn(f'<html lang="{"pt-BR" if lang == "pt" else "en"}">', page)
                self.assertIn(heads[lang], page)
                self.assertIn("my-saas", page)
                for rule in ("APP001", "APP009", "APP011", "COD001", "COD007", "COD008"):
                    self.assertIn(f" {rule}</span>", page)
                self.assertIn(_text()[lang]["sample_title"], page)

    def test_sample_report_keeps_its_policy_and_loads_nothing_from_outside(self):
        """The report's CSP allows inline CSS only. The note on top must not need anything else, or Pages would show it
        broken: no script, no stylesheet, font or image file, and the policy comes before the first style."""
        for lang, page in self.samples.items():
            with self.subTest(lang=lang):
                meta = f'<meta http-equiv="Content-Security-Policy" content="{report_html.CSP}">'
                self.assertEqual(page.count(meta), 1)
                self.assertLess(page.index(meta), page.index("<style>"))
                self.assertEqual(page.count("<style>"), 1)
                for tag in ("<script", "<link", "<img", "<iframe", "<object", "<embed", "<form"):
                    self.assertNotIn(tag, page)
                style = page.split("<style>", 1)[1].split("</style>", 1)[0]
                self.assertNotIn("url(", style)
                self.assertNotIn("@import", style)
                self.assertIsNone(re.search(r"\s(?:src|srcset|poster|action)=", page))
                for href in re.findall(r'href="([^"]+)"', page):
                    self.assertTrue(href.startswith(("https://", "../", "#")), href)

    def test_sample_note_disappears_in_print(self):
        for page in self.samples.values():
            self.assertIn("@media print{.sample{display:none}}", page)

    # ---------------------------------------------------------------- what the new checks look like on the page

    def test_the_code_and_ai_checks_have_their_rows(self):
        for lang, page in self.pages.items():
            for key in ("shell", "sqli", "ssrf", "xss", "path", "limit", "floor"):
                with self.subTest(lang=lang, row=key):
                    self.assertIn(f'<li class="find find--{key}"><h3 class="find__name">', page)
            self.assertIn("&#x27;&#36;{user}&#x27;", page)

    def test_every_catch_is_shown_once_with_its_name_and_how_it_reads_in_the_code(self):
        for lang, page in self.pages.items():
            finds = _text()[lang]["finds"]
            rows = re.findall(r'<li class="find find--([a-z]+)"><h3 class="find__name">([^<]+)</h3><div class="find__ui" data-ui>', page)
            with self.subTest(lang=lang):
                self.assertEqual([key for key, _ in rows], list(self.build.Page.FINDS))
                self.assertEqual(set(finds), set(self.build.Page.FINDS))
                for key, name in rows:
                    self.assertEqual(name, html.escape(finds[key][0]))

    # ---------------------------------------------------------------- the grade label

    def scales(self, page):
        return re.findall(r'<div class="scale (scale--\w+)"[^>]*><ol class="scale__bars" aria-label="[^"]+">(.*?)</ol>'
                          r'<p class="scale__marker" style="--row:(\d)"[^>]*><span class="sr-only">[^<]+</span>'
                          r'<b class="scale__g">([A-F])</b> <span class="scale__what">(.*?)</span></p></div>', page)

    def test_the_label_marks_the_grades_the_reports_really_gave(self):
        """The marker on each A to F label sits on a grade Stingward printed in this build: the demo app's grade on the
        first screen, the first report's grade beside the reports, and its own skill's grade at the end."""
        for lang, page in self.pages.items():
            t = _text()[lang]
            tabs = re.findall(r'<button class="report__name"[^>]* data-grade="([A-F])" data-project="([^"]+)">'
                              r'<span class="report__title">[^<]+</span><span class="report__note">[^<]+ ([A-F])\.</span>', page)
            sheets = re.findall(r'<div class="sheet" data-ui role="tabpanel".*?</pre></div>', page, re.S)
            with self.subTest(lang=lang):
                self.assertEqual(len(tabs), 3)
                self.assertEqual(len(sheets), 3)
                for (grade, project, said), sheet in zip(tabs, sheets):
                    self.assertEqual(grade, said)
                    self.assertEqual(re.search(r"(?:Nota|Grade): ([A-F])", sheet).group(1), grade)
                    self.assertIn(html.escape(project), sheet.split("</code>", 1)[0])
                found = {cls: (int(row), grade, what) for cls, _, row, grade, what in self.scales(page)}
                self.assertEqual(set(found), {"scale--hero", "scale--stage", "scale--close"})
                app = [g for g, p, _ in tabs if p == "./my-saas"][0]
                own = [g for g, p, _ in tabs if p == "skills/stingward"][0]
                self.assertEqual(found["scale--hero"], ("ABCDF".index(app), app, "./<wbr>my-saas"))
                self.assertEqual(found["scale--stage"][:2], ("ABCDF".index(tabs[0][0]), tabs[0][0]))
                self.assertEqual(found["scale--close"], ("ABCDF".index(own), own, "skills/<wbr>stingward"))
                self.assertIn(f'<b class="scale__g">{app}</b>', page.split('class="hero__body"', 1)[1].split("</header>", 1)[0])
                for _, bars, _, _, _ in self.scales(page):
                    got = re.findall(r'<li class="bar bar--([A-F])" style="--n:(\d)"><b class="bar__g">\1</b>'
                                     r'<span class="bar__means">([^<]+)</span></li>', bars)
                    self.assertEqual([(g, int(n), m) for g, n, m in got],
                                     [(g, i, html.escape(m)) for i, (g, m) in enumerate(t["grades"])])

    # ---------------------------------------------------------------- what the page loads

    def test_the_page_policy_allows_its_own_files_and_its_one_inline_script(self):
        """The home pages carry a Content Security Policy too. It allows files from the site itself and the one inline
        script by its hash, so a script injected into the page, or one edited without rebuilding, does not run."""
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                policies = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
                self.assertEqual(len(policies), 1)
                policy = policies[0]
                inline = re.findall(r"<script>(.*?)</script>", page, re.S)
                self.assertEqual(len(inline), 1)
                digest = base64.b64encode(hashlib.sha256(inline[0].encode("utf-8")).digest()).decode("ascii")
                self.assertIn(f"script-src 'self' 'sha256-{digest}';", policy)
                self.assertTrue(policy.startswith("default-src 'none';"))
                for word in ("http", "*", "data:", "unsafe-eval", "blob:"):
                    self.assertNotIn(word, policy)
                self.assertIn("base-uri 'none'", policy)
                self.assertIn("form-action 'none'", policy)
                self.assertLess(page.index(policies[0]), page.index("<link rel=\"stylesheet\""))
                self.assertLess(page.index(policies[0]), page.index("<script"))
                for tag in re.findall(r"<script\b[^>]*>", page):
                    self.assertTrue(tag == "<script>" or re.fullmatch(r'<script src="(?:\.\./)?app\.js" defer>', tag), tag)

    def test_the_pages_load_nothing_from_outside(self):
        """No CDN, no web font service, no remote image: everything the page needs is published with it."""
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                for tag in re.findall(r"<(?:link|script|img|video|source|audio|iframe)\b[^>]*>", page):
                    if tag.startswith(("<link rel=\"canonical\"", "<link rel=\"alternate\"")):
                        continue
                    for url in re.findall(r'(?:src|href|poster|srcset)="([^"]+)"', tag):
                        self.assertFalse(re.match(r"^(?:[a-z]+:|//)", url), tag)
                self.assertNotIn("<iframe", page)
                self.assertIsNone(re.search(r'style="[^"]*url\(', page))
        with open(os.path.join(SITE, "style.css"), encoding="utf-8") as fh:
            css = fh.read()
        with open(os.path.join(SITE, "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertNotIn("@import", css)
        for url in re.findall(r"url\(([^)]*)\)", css):
            target = url.strip("\"'")
            self.assertFalse(re.match(r"^(?:[a-z]+:|//)", target), url)
            self.assertTrue(os.path.isfile(os.path.join(SITE, target)), target)
        for call in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import(", "http"):
            self.assertNotIn(call, js)

    def test_the_font_is_published_with_its_license(self):
        """The one font file is under the SIL Open Font License, and the license goes out with it."""
        fonts = os.path.join(SITE, "fonts")
        files = sorted(os.listdir(fonts))
        with open(os.path.join(SITE, "style.css"), encoding="utf-8") as fh:
            css = fh.read()
        with open(os.path.join(fonts, "OFL.txt"), encoding="utf-8") as fh:
            license_text = fh.read()
        self.assertIn("SIL Open Font License, Version 1.1", license_text)
        self.assertIn("The Archivo Project Authors", license_text)
        for name in files:
            if name != "OFL.txt":
                with self.subTest(font=name):
                    self.assertIn(f'url("fonts/{name}")', css)
                    with open(os.path.join(fonts, name), "rb") as fh:
                        self.assertEqual(fh.read(4), b"wOF2")
        self.assertEqual(sorted(os.listdir(os.path.join(self.out, "fonts"))), files)

    def test_the_lowest_version_of_a_range_is_shown_as_sent(self):
        for page in self.pages.values():
            osv = page.split('class="frag__code">', 1)[1].split("</pre>", 1)[0]
            self.assertIn("&quot;name&quot;: &quot;requests&quot;", osv)
            self.assertIn("&quot;version&quot;: &quot;2.19.0&quot;", osv)


if __name__ == "__main__":
    unittest.main()
