"""O site é montado a partir deste checkout; estes testes montam o site e conferem o que ele promete."""
import importlib.util
import json
import os
import re
import tempfile
import unittest

from stingward import __version__, report_html
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
            for number, _, source, link in text[lang]["why_facts"]:
                with self.subTest(lang=lang, number=number):
                    self.assertTrue(link.startswith("https://"))
                    self.assertIn(f'href="{link}">{source}</a>', page)

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
                self.assertEqual(offers["audit_button"], f'<a class="button button--ink" href="{urls["audit_checkout"]}">'
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

    def test_the_code_and_ai_checks_have_their_tiles(self):
        for lang, page in self.pages.items():
            for key in ("shell", "sqli", "ssrf", "xss", "path", "limit", "floor"):
                with self.subTest(lang=lang, tile=key):
                    self.assertIn(f'<div class="tile tile--{key}" data-reveal>', page)
            self.assertIn("&#x27;&#36;{user}&#x27;", page)

    def test_the_lowest_version_of_a_range_is_shown_as_sent(self):
        for page in self.pages.values():
            osv = page.split('class="frag__code">', 1)[1].split("</pre>", 1)[0]
            self.assertIn("&quot;name&quot;: &quot;requests&quot;", osv)
            self.assertIn("&quot;version&quot;: &quot;2.19.0&quot;", osv)


if __name__ == "__main__":
    unittest.main()
