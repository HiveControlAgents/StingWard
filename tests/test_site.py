"""O site é montado a partir deste checkout; estes testes montam o site e conferem o que ele promete."""
import importlib.util
import json
import os
import re
import tempfile
import unittest

from stingward import __version__
from stingward.rules import RULES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
FAKE_KEY_PART = "Demo7Fake9Key0Not4Real"
PAGES = {"pt": "index.html", "en": os.path.join("en", "index.html")}


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
        cls.out = _builder().build(os.path.join(cls.tmp.name, "site"))
        cls.pages = {}
        for lang, rel in PAGES.items():
            with open(os.path.join(cls.out, rel), encoding="utf-8") as fh:
                cls.pages[lang] = fh.read()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_both_languages_have_the_same_texts(self):
        with open(os.path.join(SITE, "text.json"), encoding="utf-8") as fh:
            text = json.load(fh)
        self.assertEqual(_shape(text["pt"]), _shape(text["en"]))

    def test_nothing_is_left_unfilled(self):
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                self.assertNotIn("${", page)
                self.assertIsNone(re.search(r"\{(?:version|rules|repo|tests|n)\}", page))

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
        for lang, page in self.pages.items():
            with self.subTest(lang=lang):
                self.assertNotIn(FAKE_KEY_PART, page)
                self.assertNotIn("sk-proj-", page)

    def test_local_links_and_files_exist(self):
        for lang, page in self.pages.items():
            base = os.path.dirname(os.path.join(self.out, PAGES[lang]))
            for target in re.findall(r'(?:href|src|poster)="([^"]+)"', page):
                if re.match(r"^[a-z]+:|^#", target):
                    continue
                with self.subTest(lang=lang, link=target):
                    path = os.path.normpath(os.path.join(base, target.split("#", 1)[0]))
                    self.assertTrue(os.path.exists(path), path)

    def test_in_page_links_point_at_sections_that_exist(self):
        for lang, page in self.pages.items():
            ids = set(re.findall(r' id="([^"]+)"', page))
            for target in re.findall(r'href="#([^"]+)"', page):
                with self.subTest(lang=lang, target=target):
                    self.assertIn(target, ids)

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
        for page in self.pages.values():
            self.assertNotIn("<form", page)


if __name__ == "__main__":
    unittest.main()
