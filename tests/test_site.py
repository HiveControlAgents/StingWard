"""O site é montado a partir deste checkout; estes testes montam o site e conferem o que ele promete."""
import base64
import hashlib
import html
import importlib.util
import json
import os
import posixpath
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
URL = "https://stingward.com/"
# English is the main site, at the root; Portuguese lives under pt/. Paths are given from the site's root.
PAGES = {"en": "index.html", "pt": "pt/index.html"}
SAMPLES = {"en": "example/index.html", "pt": "pt/exemplo/index.html"}
# The same report with the AI review of site/sample/, as the paid report comes. The report service links here.
SAMPLES_AI = {"en": "example/full/index.html", "pt": "pt/exemplo/completo/index.html"}
# The addresses the site had before English moved to the root. They were shared, so each one must still lead somewhere:
# the old folder, the language of the page left there and the folder the page moved to.
MOVED = {"en/": ("en", ""), "en/example/": ("en", "example/"), "exemplo/": ("pt", "pt/exemplo/")}
HREFLANG = {"en": "en", "pt": "pt-BR"}
# The terms, privacy and refund pages. The report service's buy page links to these addresses, so they must not move.
LEGAL = {key: {"en": f"{key}/index.html", "pt": f"pt/{key}/index.html"} for key in ("terms", "privacy", "refund")}


def _text():
    with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _legal():
    with open(os.path.join(SITE, "legal.json"), encoding="utf-8") as fh:
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
        cls.pages, cls.samples, cls.ai_samples = {}, {}, {}
        for pages, paths in ((cls.pages, PAGES), (cls.samples, SAMPLES), (cls.ai_samples, SAMPLES_AI)):
            for lang, rel in paths.items():
                pages[lang] = cls.file(rel)
        cls.moved = {old: cls.file(old + "index.html") for old in MOVED}

    @classmethod
    def file(cls, rel):
        with open(os.path.join(cls.out, *rel.split("/")), encoding="utf-8") as fh:
            return fh.read()

    def built(self):
        """Every HTML file the build wrote, as a path from the site's root."""
        for folder, _, names in os.walk(self.out):
            for name in names:
                if name.endswith(".html"):
                    yield os.path.relpath(os.path.join(folder, name), self.out).replace(os.sep, "/")

    def every_page(self):
        for lang in PAGES:
            yield lang, PAGES[lang], self.pages[lang]
            yield lang, SAMPLES[lang], self.samples[lang]
            yield lang, SAMPLES_AI[lang], self.ai_samples[lang]

    def every_sample(self):
        for samples in (self.samples, self.ai_samples):
            yield from samples.items()

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
        self.assertIn("Nota: F", pt)
        self.assertIn("Nota: A", pt)
        self.assertIn("Grade: F", en)
        self.assertIn("Grade: A", en)
        self.assertIn(f"stingward {__version__}", pt)
        self.assertIn(f"{len(RULES)} regras", pt)
        self.assertIn(f"{len(RULES)} rules", en)

    def test_the_fake_key_never_shows(self):
        for lang, rel, page in self.every_page():
            with self.subTest(page=rel):
                self.assertNotIn(FAKE_KEY_PART, page)
                self.assertNotIn("sk-proj-", page)

    def test_every_link_on_every_built_page_reaches_a_built_file(self):
        """Relative links, the redirect of a moved page and the site's own absolute addresses (canonical, hreflang,
        og:url, og:image) must all land on a file the build wrote; a folder counts only with its index.html. A link
        that starts with "/" would leave the /StingWard/ folder Pages serves the site from, so there are none."""
        pages = sorted(self.built())
        self.assertEqual(len(pages), len(PAGES) + len(SAMPLES) + len(SAMPLES_AI) + len(MOVED) + 2 * len(LEGAL))
        for rel in pages:
            page = self.file(rel)
            here = posixpath.dirname(rel)
            targets = re.findall(r'\s(?:href|src|poster)="([^"]+)"', page)
            targets += re.findall(r'<meta http-equiv="refresh" content="0; url=([^"]+)">', page)
            targets += re.findall(r'<meta property="og:(?:url|image)" content="([^"]+)">', page)
            for target in targets:
                with self.subTest(page=rel, link=target):
                    self.assertFalse(target.startswith("/"), target)
                    if target.startswith(URL):
                        path = target[len(URL):]
                    elif re.match(r"^[a-z]+:|^#", target):
                        continue
                    else:
                        path = posixpath.join(here, target)
                    path = posixpath.normpath(path.split("#", 1)[0].split("?", 1)[0] or ".")
                    self.assertFalse(path.startswith(".."), target)
                    if os.path.isdir(os.path.join(self.out, *path.split("/"))):
                        path = posixpath.join(path, "index.html")
                    self.assertTrue(os.path.isfile(os.path.join(self.out, *path.split("/"))), path)

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
        self.assertIn('<span lang="en" aria-current="page">', self.pages["en"])
        self.assertIn('<a href="pt/" hreflang="pt-BR" lang="pt-BR">', self.pages["en"])
        self.assertIn('<span lang="pt-BR" aria-current="page">', self.pages["pt"])
        self.assertIn('<a href="../" hreflang="en" lang="en">', self.pages["pt"])
        flags = {"en": "", "pt": "../"}
        for lang, page in self.pages.items():  # the site is English by default, so Portuguese, the other one, comes first
            with self.subTest(lang=lang):
                switch = page.split('<nav class="lang"', 1)[1].split("</nav>", 1)[0]
                self.assertLess(switch.index("Português"), switch.index("English"))
                # each language beside its flag, a picture the name already says, so readers skip it
                self.assertEqual(re.findall(r'<img class="lang__flag" src="([^"]+)" alt="" width="16" height="12">', switch),
                                 [f"{flags[lang]}assets/flag-br.svg", f"{flags[lang]}assets/flag-us.svg"])

    # ---------------------------------------------------------------- addresses

    def test_english_is_the_root_and_portuguese_is_under_pt(self):
        for lang, rel, page in self.every_page():
            with self.subTest(page=rel):
                self.assertIn(f'<html lang="{HREFLANG[lang]}">', page)
                self.assertEqual(rel.startswith("pt/"), lang == "pt")
        self.assertEqual(self.build.PAGE_DIR, {"en": ".", "pt": "pt"})
        self.assertEqual(self.build.SAMPLE, {"en": "example", "pt": "pt/exemplo"})
        self.assertEqual(self.build.SAMPLE_AI, {"en": "example/full", "pt": "pt/exemplo/completo"})

    def test_each_page_names_its_address_and_the_other_language(self):
        """canonical is the page's own address, hreflang lists both languages and points x-default at English, and
        the social card says the same address and both locales."""
        locale = {"en": "en_US", "pt": "pt_BR"}
        for paths in (PAGES, SAMPLES, SAMPLES_AI):
            address = {lang: URL + posixpath.dirname(rel) + ("/" if posixpath.dirname(rel) else "")
                       for lang, rel in paths.items()}
            want = {"en": address["en"], "pt-BR": address["pt"], "x-default": address["en"]}
            for lang, rel in paths.items():
                page = self.file(rel)
                with self.subTest(page=rel):
                    self.assertEqual(re.findall(r'<link rel="canonical" href="([^"]+)">', page), [address[lang]])
                    alternates = re.findall(r'<link rel="alternate" hreflang="([^"]+)" href="([^"]+)">', page)
                    self.assertEqual(dict(alternates), want)
                    self.assertEqual(len(alternates), 3)
                    if paths is PAGES:
                        self.assertEqual(re.findall(r'<meta property="og:url" content="([^"]+)">', page), [address[lang]])
                        self.assertIn(f'<meta property="og:locale" content="{locale[lang]}">', page)
                        other = locale["pt" if lang == "en" else "en"]
                        self.assertIn(f'<meta property="og:locale:alternate" content="{other}">', page)
                        self.assertIn(f'<meta property="og:image" content="{URL}assets/social-preview.png">', page)

    def test_the_old_addresses_lead_to_the_new_ones(self):
        """/en/, /en/example/ and /exemplo/ were shared before English moved to the root. Pages cannot redirect, so
        each is a page that sends the visitor on at once, names the new address as canonical and links it for anyone
        whose browser does not follow the refresh. Nothing picks the language from the browser."""
        for old, (lang, new) in MOVED.items():
            page = self.moved[old]
            with self.subTest(old=old):
                refresh = re.findall(r'<meta http-equiv="refresh" content="0; url=([^"]+)">', page)
                self.assertEqual(len(refresh), 1)
                target = posixpath.normpath(posixpath.join(old, refresh[0]))
                self.assertEqual(target, posixpath.normpath(new or "."))
                self.assertEqual(re.findall(r'<link rel="canonical" href="([^"]+)">', page), [URL + new])
                self.assertIn(f'<a id="to" href="{refresh[0]}">{URL + new}</a>', page)
                self.assertIn(f'<html lang="{HREFLANG[lang]}">', page)
                self.assertIn(html.escape(_text()[lang]["moved"]), page)
                arrived = self.file(new + "index.html")  # the new address is the real page, not one more hop
                self.assertNotIn('http-equiv="refresh"', arrived)
                self.assertIn(f'<html lang="{HREFLANG[lang]}">', arrived)
                self.assertNotIn("navigator.language", page)
                self.assertNotIn("hreflang", page)

    def test_the_moved_pages_keep_the_site_policy_and_load_nothing_from_outside(self):
        """The moved pages carry the same policy as the home pages. Their one inline script, allowed by its hash,
        keeps the #section and the query of the old link; the refresh and the plain link work without it."""
        for old, page in self.moved.items():
            with self.subTest(old=old):
                policies = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
                self.assertEqual(len(policies), 1)
                inline = re.findall(r"<script>(.*?)</script>", page, re.S)
                self.assertEqual(len(inline), 1)
                self.assertIn("location.hash", inline[0])
                digest = base64.b64encode(hashlib.sha256(inline[0].encode("utf-8")).digest()).decode("ascii")
                self.assertEqual(policies[0], self.build.CSP.replace("{hash}", digest))
                head = page.split("</head>", 1)[0]
                self.assertLess(head.index("Content-Security-Policy"), head.index('http-equiv="refresh"'))
                self.assertLess(head.index("Content-Security-Policy"), head.index("<style>"))
                self.assertEqual(re.findall(r"<script\b[^>]*>", page), ["<script>"])
                icon = posixpath.relpath("assets/logo.svg", old)  # the site's own icon, as the home pages have
                self.assertEqual(re.findall(r"<link\b[^>]*>", page), [f'<link rel="canonical" href="{URL + MOVED[old][1]}">',
                                                                      f'<link rel="icon" href="{icon}" type="image/svg+xml">'])
                for tag in ("<img", "<video", "<iframe", "<object", "<embed", "<form", "@import", "url("):
                    self.assertNotIn(tag, page)
                self.assertIsNone(re.search(r"\s(?:src|srcset|poster|action)=", page))
                for href in re.findall(r'<a [^>]*href="([^"]+)"', page):
                    self.assertFalse(re.match(r"^(?:[a-z]+:|//|/)", href), href)

    def test_every_number_on_why_it_exists_links_its_source(self):
        with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
            text = json.load(fh)
        for lang, page in self.pages.items():
            for number, said, source, link in text[lang]["why_facts"]:
                with self.subTest(lang=lang, number=number):
                    self.assertTrue(link.startswith("https://"))
                    self.assertIn(f'href="{link}">{source}</a>', page)
                    # the figure stands alone in its column; a unit after it ("23.8 million") opens the sentence
                    figure, _, unit = number.partition(" ")
                    caption = html.escape(f"{unit} {said}" if unit else said)
                    self.assertIn(f'<p class="led__num" data-reveal>{html.escape(figure)}</p>'
                                  f'<p class="led__cap" data-reveal>{caption} <a class="src"', page)

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
                self.assertEqual(offers["audit_button"], f'<a class="button" href="{urls["audit_checkout"]}" data-buy>'
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
                self.assertIn(html.escape(t["audit_h2"]), audit)
                # reais in Portuguese, the Hotmart offer for Brazil, with the dollar price beside it; dollars in
                # English, where nobody is told about reais
                self.assertEqual((t["audit_currency"], t["audit_price"]), {"pt": ("R$", "99"), "en": ("$", "29")}[lang])
                self.assertIn(f'<span class="figure__cur">{t["audit_currency"]}</span>'
                              f'<span class="figure__num">{t["audit_price"]}</span>', audit)
                if lang == "pt":
                    self.assertIn(f'<p class="audit__note" data-reveal>{html.escape(t["audit_note"])}</p>', audit)
                    self.assertIn("US$ 29", t["audit_note"])
                else:
                    self.assertEqual(t["audit_note"], "")
                    self.assertNotIn("audit__note", audit)
                # the promises the report service keeps: one free new check, and a refund when the report is late
                gets = " ".join(t["audit_gets"])
                self.assertIn({"pt": "30 dias", "en": "30 days"}[lang], gets)
                self.assertIn({"pt": "24 horas", "en": "24 hours"}[lang], gets)
                for line in t["audit_gets"] + t["audit_not"]:
                    self.assertIn(f"<li>{html.escape(line)}</li>", audit)
                self.assertIn(html.escape(t["soon_h3"]), audit)
                # the code is deleted when the report is ready: the privacy summary in the terms says the same
                deleted = {"pt": "Seu código apagado assim que o relatório fica pronto",
                           "en": "Your code deleted as soon as the report is ready"}[lang]
                self.assertIn(deleted, t["audit_gets"])
                self.assertIn({"pt": "seu código é apagado assim que o relatório fica pronto",
                               "en": "your code is deleted as soon as the report is ready"}[lang], json.dumps(_legal()[lang], ensure_ascii=False))
                # the sample report's note repeats the price: it must be the same one
                self.assertIn({"pt": "R$ 99", "en": "$29"}[lang], t["sample_audit"])
                # the terms, the same for everyone, give both prices in both languages
                terms = self.file(LEGAL["terms"][lang])
                self.assertIn("US$ 29", terms)
                self.assertIn("R$ 99", terms)

    def test_the_offer_shows_real_pages_of_the_paid_sample(self):
        text = _text()
        for lang, page in self.pages.items():
            audit = page.split('id="audit"', 1)[1].split("</section>", 1)[0]
            paid = {"en": "example/full/", "pt": "exemplo/completo/"}[lang]
            with self.subTest(lang=lang):
                sheets = re.findall(r'<li class="sheet sheet--(\w+)"><figure><a href="([^"]+)"><img src="([^"]+)" '
                                    r'width="(\d+)" height="(\d+)" alt="([^"]+)" decoding="async"></a>'
                                    r'<figcaption>([^<]+)</figcaption>', audit)
                self.assertEqual([name for name, *_ in sheets], ["cover", "summary", "findings"])
                for (name, href, src, width, height, alt, caption), (want_caption, want_alt) in zip(sheets, text[lang]["pages"]):
                    # each page opens the whole paid sample, and is the PNG the build copied, at its own size
                    self.assertEqual(href, paid)
                    self.assertEqual((html.unescape(caption), html.unescape(alt)), (want_caption, want_alt))
                    path = os.path.join(self.out, posixpath.normpath(posixpath.join(posixpath.dirname(PAGES[lang]), src)))
                    self.assertEqual(self.build.size(path), (int(width), int(height)))
                    # a printed A4 page, not a drawing of one
                    self.assertEqual(int(width), 900)
                    self.assertAlmostEqual(int(height) / int(width), 297 / 210, delta=0.01)
                # the pages sit between the price and what it includes
                self.assertLess(audit.index("audit__figure"), audit.index("audit__pages"))
                self.assertLess(audit.index("audit__pages"), audit.index("audit__list--gets"))

    def test_the_offer_comes_right_after_the_first_screen(self):
        text = _text()
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                order = [page.index(f'id="{id_}"') for id_ in ("report", "audit", "why", "how", "finds", "where", "price", "run")]
                self.assertEqual(order, sorted(order))
                # and the first screen points at the paid sample for those who don't use a terminal
                alt = page.split('<p class="hero__alt">', 1)[1].split("</p>", 1)[0]
                self.assertIn(html.escape(text[lang]["hero_alt"]), alt)
                self.assertIn(f'<a href="{ {"en": "example/full/", "pt": "exemplo/completo/"}[lang] }">', alt)

    def test_small_screens_get_a_menu_with_every_section(self):
        with open(os.path.join(SITE, "app.js"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertIn("aria-expanded", script)
        self.assertIn("Escape", script)
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                self.assertIn(f'<button class="menu" type="button" aria-expanded="false" aria-controls="menu">'
                              f'{html.escape(_text()[lang]["menu"])}</button>', page)
                nav = page.split('<nav class="nav" id="menu"', 1)[1].split("</nav>", 1)[0]
                for target in ("#audit", "#why", "#finds", "#price", "#where"):
                    self.assertIn(f'href="{target}"', nav)

    def test_the_first_screen_shows_a_different_hook_on_each_visit(self):
        """The page is built with the first hook, the one shown without the script; app.js picks one of data-hooks on
        each visit, or hook N from ?hook=N. Every hook was measured in the browser on two lines from 360 to 1440px,
        with 16 characters the longest line; a longer one has to be measured first."""
        with open(os.path.join(SITE, "app.js"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertIn("dataset.hooks", script)
        self.assertIn('get("hook")', script)
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                text = _text()[lang]
                hooks = text["hero_hooks"]
                self.assertEqual(hooks[0], text["hero_h1"])
                self.assertEqual(len({tuple(hook) for hook in hooks}), len(hooks))
                found = re.search(r'<h1 class="hero__title" data-hooks="([^"]+)">', page)
                self.assertEqual(json.loads(html.unescape(found.group(1))), hooks)
                for hook in hooks:
                    self.assertEqual(len(hook), 2, hook)
                    for line in hook:
                        self.assertLessEqual(len(line), 16, line)
                        self.assertNotRegex(line.lower(), r"hack|guarant|garant|100\s*%", line)
                        self.assertTrue(all(ord(char) < 0x2000 for char in line), line)

    # ---------------------------------------------------------------- terms, privacy and refunds

    def test_legal_texts_have_the_same_shape_in_both_languages(self):
        legal = _legal()
        self.assertEqual(_shape(legal["pt"]), _shape(legal["en"]))
        self.assertEqual(sorted(legal["en"]["pages"]), sorted(LEGAL))

    def test_legal_pages_are_linked_from_every_page_of_the_site(self):
        """The terms, privacy and refund policy are reachable from the site's navigation, as Hotmart's review expects:
        the footer of both home pages and of every legal page links all three, in its language."""
        legal = _legal()
        for lang, page in self.pages.items():
            names = [legal[lang]["pages"][k]["name"] for k in LEGAL]
            with self.subTest(page=lang):
                nav = page.split('<nav class="footer__legal"', 1)[1].split("</nav>", 1)[0]
                want = "".join(f'<a href="{k}/">{n}</a>' for k, n in zip(LEGAL, names))
                self.assertIn(want, nav)
            for key, paths in LEGAL.items():
                with self.subTest(page=paths[lang]):
                    nav = self.file(paths[lang]).split('<nav class="footer__legal"', 1)[1].split("</nav>", 1)[0]
                    marks = re.findall(r'<(a href="\.\./([a-z]+)/"|span aria-current="page")>([^<]+)<', nav)
                    self.assertEqual([m[2] for m in marks], names)
                    self.assertEqual([m[1] or key for m in marks], list(LEGAL))
                    self.assertIn(f'<span aria-current="page">{legal[lang]["pages"][key]["name"]}</span>', nav)

    def test_legal_pages_name_their_address_and_the_other_language(self):
        for key, paths in LEGAL.items():
            address = {lang: URL + posixpath.dirname(rel) + "/" for lang, rel in paths.items()}
            want = {"en": address["en"], "pt-BR": address["pt"], "x-default": address["en"]}
            for lang, rel in paths.items():
                page = self.file(rel)
                with self.subTest(page=rel):
                    self.assertIn(f'<html lang="{HREFLANG[lang]}">', page)
                    self.assertEqual(re.findall(r'<link rel="canonical" href="([^"]+)">', page), [address[lang]])
                    self.assertEqual(dict(re.findall(r'<link rel="alternate" hreflang="([^"]+)" href="([^"]+)">', page)), want)
                    other = "pt" if lang == "en" else "en"
                    self.assertIn(f'<a href="{posixpath.relpath(posixpath.dirname(paths[other]), posixpath.dirname(rel))}/" '
                                  f'hreflang="{HREFLANG[other]}" lang="{HREFLANG[other]}">', page)
                    self.assertIn('<a class="brand" href="../"', page)  # the home page of the same language

    def test_legal_pages_run_no_script_and_load_nothing_from_outside(self):
        for key, paths in LEGAL.items():
            for lang, rel in paths.items():
                page = self.file(rel)
                with self.subTest(page=rel):
                    policies = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
                    self.assertEqual(policies, [self.build.LEGAL_CSP])
                    self.assertNotIn("script-src", policies[0])
                    self.assertNotIn("<script", page)
                    for tag in re.findall(r"<(?:link|img|video|source|iframe)\b[^>]*>", page):
                        if tag.startswith(("<link rel=\"canonical\"", "<link rel=\"alternate\"")):
                            continue
                        for url in re.findall(r'(?:src|href)="([^"]+)"', tag):
                            self.assertFalse(re.match(r"^(?:[a-z]+:|//)", url), tag)

    def test_the_terms_say_who_sells_and_who_answers(self):
        """The terms say that we sell the report and Hotmart takes the payment, with Hotmart's purchase terms in the
        reader's language; every page gives the support address as a mail link; the numbers match what the report
        service does."""
        legal = _legal()
        seller = {"en": ("You buy the report from us. The payment goes through Hotmart",
                         "https://hotmart.com/en/legal/purchase-terms"),
                  "pt": ("Você compra o relatório de nós. O pagamento passa pela Hotmart",
                         "https://hotmart.com/pt-br/legal/termos-de-compra")}
        for lang in PAGES:
            with self.subTest(lang=lang):
                terms = self.file(LEGAL["terms"][lang])
                self.assertIn(html.escape(seller[lang][0]), terms)
                self.assertIn(f'href="{seller[lang][1]}"', terms)
                self.assertNotIn("Paddle", terms)
                self.assertIn("Isaque Moutta", terms)
                for key, paths in LEGAL.items():
                    self.assertIn('<a href="mailto:support@stingward.com">support@stingward.com</a>', self.file(paths[lang]))
                    self.assertIn(html.escape(legal[lang]["updated"]), self.file(paths[lang]))
                refund = html.unescape(self.file(LEGAL["refund"][lang]))
                for number in ({"en": "7 days", "pt": "7 dias"}, {"en": "24 hours", "pt": "24 horas"},
                               {"en": "15 days", "pt": "15 dias"}):
                    self.assertIn(number[lang], refund)
                privacy = html.unescape(self.file(LEGAL["privacy"][lang]))
                for number in ({"en": "48 hours", "pt": "48 horas"}, {"en": "30 days", "pt": "30 dias"},
                               {"en": "30 minutes", "pt": "30 minutos"}):
                    self.assertIn(number[lang], privacy)

    def test_legal_links_go_only_to_the_other_pages_or_https(self):
        self.assertEqual(self.build.inline("See the [refund policy](refund).", "pt", "pt/terms"),
                         'See the <a href="../refund/">refund policy</a>.')
        self.assertEqual(self.build.inline("[Hotmart](https://refund.hotmart.com) & <b>", "en", "terms"),
                         '<a href="https://refund.hotmart.com">Hotmart</a> &amp; &lt;b&gt;')
        for bad in ("[x](javascript:alert(1))", "[x](http://example.com)", "[x](/terms)", "[x](terms\")",
                    "[x] (terms)](y"):
            with self.subTest(text=bad), self.assertRaises(SystemExit):
                self.build.inline(bad, "en", "terms")

    # ---------------------------------------------------------------- the sample report

    def test_sample_report_is_linked_from_the_home_page(self):
        for lang, href in (("en", "example/"), ("pt", "exemplo/")):
            with self.subTest(lang=lang):
                self.assertIn(f'<a class="button" href="{href}">{_text()[lang]["report_sample"]}</a>', self.pages[lang])

    def test_sample_report_is_the_real_html_report_of_the_demo_app(self):
        heads = {"pt": "Resumo executivo", "en": "Executive summary"}
        for lang, page in self.every_sample():
            with self.subTest(lang=lang):
                self.assertTrue(page.startswith("<!doctype html>"))
                self.assertIn(f'<html lang="{"pt-BR" if lang == "pt" else "en"}">', page)
                self.assertIn(heads[lang], page)
                self.assertIn("my-saas", page)
                for rule in ("APP001", "APP009", "APP011", "COD001", "COD007", "COD008"):
                    self.assertIn(f" {rule}</span>", page)
        for lang in SAMPLES:
            self.assertIn(_text()[lang]["sample_title"], self.samples[lang])
            self.assertIn(_text()[lang]["sample_ai_title"], self.ai_samples[lang])

    def test_sample_report_keeps_its_policy_and_loads_nothing_from_outside(self):
        """The report's CSP allows inline CSS only. The note on top must not need anything else, or Pages would show it
        broken: no script, no stylesheet, font or image file, and the policy comes before the first style. Its only
        links in the head are its address and its other language, which load nothing."""
        for lang, page in self.every_sample():
            with self.subTest(lang=lang):
                meta = f'<meta http-equiv="Content-Security-Policy" content="{report_html.CSP}">'
                self.assertEqual(page.count(meta), 1)
                self.assertLess(page.index(meta), page.index("<style>"))
                self.assertEqual(page.count("<style>"), 1)
                for tag in re.findall(r"<link\b[^>]*>", page):
                    self.assertRegex(tag, r'^<link rel="(?:canonical|alternate)" (?:hreflang="[^"]+" )?href="' + re.escape(URL))
                for tag in ("<script", "<img", "<iframe", "<object", "<embed", "<form"):
                    self.assertNotIn(tag, page)
                style = page.split("<style>", 1)[1].split("</style>", 1)[0]
                self.assertNotIn("url(", style)
                self.assertNotIn("@import", style)
                self.assertIsNone(re.search(r"\s(?:src|srcset|poster|action)=", page))
                for href in re.findall(r'href="([^"]+)"', page):  # a page of this site, or https
                    self.assertTrue(href.startswith(("https://", "#")) or not re.match(r"[A-Za-z][\w+.-]*:|/", href), href)

    def test_sample_note_disappears_in_print(self):
        for _, page in self.every_sample():
            self.assertIn("@media print{.sample{display:none}}", page)

    def test_the_paid_sample_has_the_ai_review_on_every_finding(self):
        words = {"en": ("Automatic review", "Summary"), "pt": ("Revisão automática", "Resumo")}
        for lang, page in self.ai_samples.items():
            with self.subTest(lang=lang):
                self.assertIn(words[lang][0], page)
                self.assertIn(f">{words[lang][1]}<", page)
                with open(os.path.join(SITE, "sample", f"notes-{lang}.md"), encoding="utf-8") as fh:
                    first = fh.read().split(". ", 1)[0]
                self.assertIn(html.escape(first, quote=False), page)
                badges = re.findall(r'class="rv rv-([\w-]+)"', page)
                self.assertGreaterEqual(len(badges), 15)
                self.assertEqual(set(badges), {"confirmed"})  # nothing "not reviewed yet"
                self.assertNotIn('class="rv rv-confirmed"', self.samples[lang])  # the free one has no review

    def test_the_review_files_match_each_other(self):
        docs = {}
        for lang in SAMPLES_AI:
            with open(os.path.join(SITE, "sample", f"review-{lang}.json"), encoding="utf-8") as fh:
                docs[lang] = json.load(fh)
        for lang, doc in docs.items():
            with self.subTest(lang=lang):
                self.assertEqual(doc["review_kind"], "ai")
                self.assertTrue(all(row["comment"] and row["status"] == "confirmed" for row in doc["findings"]))
        self.assertEqual([r["fingerprint"] for r in docs["en"]["findings"]], [r["fingerprint"] for r in docs["pt"]["findings"]])

    def test_a_finding_the_review_file_does_not_have_fails_the_build(self):
        demo = os.path.join(self.tmp.name, "demo-review")
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "demo", "fixtures.py"), demo], check=True, capture_output=True)
        site = os.path.join(self.tmp.name, "site-review")
        os.makedirs(os.path.join(site, "sample"))
        for name in ("review-en.json", "notes-en.md"):
            with open(os.path.join(SITE, "sample", name), encoding="utf-8") as fh:
                text = fh.read()
            if name.endswith(".json"):
                doc = json.loads(text)
                doc["findings"] = [r for r in doc["findings"] if r["finding"]["rule"] != "COD007"]
                text = json.dumps(doc)
            with open(os.path.join(site, "sample", name), "w", encoding="utf-8") as fh:
                fh.write(text)
        real = self.build.SITE
        self.build.SITE = site
        try:
            with self.assertRaises(SystemExit) as caught:
                self.build.Page("en", _text()["en"], demo, False, 0).sample(ai=True)
        finally:
            self.build.SITE = real
        self.assertIn("has no comment for 1 finding(s) of the demo app", str(caught.exception))

    def test_the_samples_link_to_each_other_and_the_offer_to_the_paid_one(self):
        t = _text()
        for lang, here in (("en", "example/"), ("pt", "pt/exemplo/")):
            with self.subTest(lang=lang):
                ai = {"en": "full/", "pt": "completo/"}[lang]
                self.assertIn(f'<a href="{ai}">{html.escape(t[lang]["sample_with_ai"])}</a>', self.samples[lang])
                self.assertIn(f'<a href="../">{html.escape(t[lang]["sample_plain"])}</a>', self.ai_samples[lang])
                act = self.pages[lang].split('<div class="audit__act">', 1)[1].split("</div>", 1)[0]
                self.assertIn(f'<a href="{"example/" if lang == "en" else "exemplo/"}{ai}">', act)

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

    # ---------------------------------------------------------------- the grades

    def test_grades_show_only_where_a_real_report_gave_them(self):
        """Each report's tab shows the grade that report printed in this build, the stage that grades marks only the
        demo app's grade, and the pull request preview carries that same grade. No other grade is drawn on the page."""
        projects = ["./pdf-helper", "./my-saas", "skills/stingward"]
        for lang, page in self.pages.items():
            t = _text()[lang]
            tabs = re.findall(r'<button class="term__tab" type="button" role="tab" id="report-tab-(\d)" '
                              r'aria-controls="report-out-\1" aria-selected="(true|false)" tabindex="(-1|0)" data-grade="([A-F])">'
                              r'<span class="term__name">[^<]+</span><span class="term__grade">([^<]+) ([A-F])</span></button>', page)
            panels = re.findall(r'<pre class="term__out" role="tabpanel" id="report-out-(\d)" aria-labelledby="report-tab-\1" '
                                r'tabindex="0"( data-off)?>(.*?)</pre>', page, re.S)
            with self.subTest(lang=lang):
                self.assertEqual([int(i) for i, *_ in tabs], [0, 1, 2])
                self.assertEqual([int(i) for i, *_ in panels], [0, 1, 2])
                grades = {}
                for (i, selected, index, grade, word, shown), (_, off, out), project in zip(tabs, panels, projects):
                    self.assertEqual((word, shown), (t["grade_word"], grade))
                    self.assertEqual(re.search(r"(?:Nota|Grade): ([A-F])", out).group(1), grade)
                    self.assertIn(f"stingward {'' if project == './my-saas' else 'skill '}{project}</span>", out)
                    # the demo app is the report on show; the others wait behind their tabs
                    on = project == "./my-saas"
                    self.assertEqual((selected, index, off), ("true", "0", "") if on else ("false", "-1", " data-off"))
                    grades[project] = grade
                app = grades["./my-saas"]
                stage = re.findall(r'<li class="frag__grade( is-on)?"><b>([A-F])</b> <span>([^<]+)</span></li>', page)
                self.assertEqual(stage, [(" is-on" if g == app else "", g, html.escape(m)) for g, m in t["grades"]])
                self.assertEqual(re.findall(r'<span class="pr__grade">stingward ([A-F])</span>', page), [app])
                self.assertEqual(page.count("data-grade="), 3)
                self.assertEqual(page.count("is-on"), 1)
                self.assertEqual(page.count("pr__grade"), 1)

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

    def test_the_fonts_are_published_with_their_licenses(self):
        """Hanken Grotesk and JetBrains Mono are under the SIL Open Font License; each license goes out beside its font,
        and the stylesheet loads each font file from the site itself."""
        fonts = os.path.join(SITE, "fonts")
        files = sorted(os.listdir(fonts))
        with open(os.path.join(SITE, "style.css"), encoding="utf-8") as fh:
            css = fh.read()
        authors = {"hanken-grotesk": "The Hanken Grotesk Project Authors", "jetbrains-mono": "The JetBrains Mono Project Authors"}
        woff = [name for name in files if name.endswith(".woff2")]
        self.assertEqual(sorted(name.split("-latin")[0] for name in woff), sorted(authors))
        self.assertEqual(sorted(set(files) - set(woff)), sorted(f"{family}-OFL.txt" for family in authors))
        for family, author in authors.items():
            with self.subTest(license=family):
                with open(os.path.join(fonts, f"{family}-OFL.txt"), encoding="utf-8") as fh:
                    license_text = fh.read()
                self.assertIn("SIL Open Font License, Version 1.1", license_text)
                self.assertIn(author, license_text)
        for name in woff:
            with self.subTest(font=name):
                self.assertIn(f'url("fonts/{name}")', css)
                with open(os.path.join(fonts, name), "rb") as fh:
                    self.assertEqual(fh.read(4), b"wOF2")
        self.assertNotIn("Archivo", css)
        self.assertEqual(sorted(os.listdir(os.path.join(self.out, "fonts"))), files)
    def test_the_lowest_version_of_a_range_is_shown_as_sent(self):
        for page in self.pages.values():
            osv = page.split('class="frag__code">', 1)[1].split("</pre>", 1)[0]
            self.assertIn("&quot;name&quot;: &quot;requests&quot;", osv)
            self.assertIn("&quot;version&quot;: &quot;2.19.0&quot;", osv)


if __name__ == "__main__":
    unittest.main()
