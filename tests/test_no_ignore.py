"""--no-ignore: auditar o projeto de outra pessoa sem aceitar o .stingwardignore nem os comentários stingward:ignore dele.

Nada aqui usa a rede. Segredos de teste são falsos e montados por concatenação."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from stingward import cli, review, scan

GH = "ghp_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"
CORS = "app.use(cors())\n"

_DIRS = []


def tearDownModule():
    for d in _DIRS:
        d.cleanup()


def tree(files):
    d = tempfile.TemporaryDirectory()
    _DIRS.append(d)
    for rel, content in files.items():
        p = os.path.join(d.name, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    return d.name


def rules(root, **kw):
    _, findings = scan.run(root, offline=True, **kw)
    return sorted(f.rule for f in findings)


def main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Scan(unittest.TestCase):
    def test_ignore_file_hides_by_default_and_not_with_no_ignore(self):
        root = tree({"server.js": CORS, ".stingwardignore": "APP003 server.js\n"})
        self.assertEqual(rules(root), [])
        self.assertEqual(rules(root, honor_ignores=False), ["APP003"])

    def test_every_ignore_line_form_is_skipped(self):
        for line in ("APP003", "server.js", "APP003 server.js", "*"):
            with self.subTest(line=line):
                root = tree({"server.js": CORS, ".stingwardignore": line + "\n"})
                self.assertEqual(rules(root, honor_ignores=False), ["APP003"])

    def test_inline_comment_hides_by_default_and_not_with_no_ignore(self):
        root = tree({"src/keys.py": f'TOKEN = "{GH}"  # stingward:ignore\n'})
        self.assertNotIn("SEC001", rules(root))
        self.assertIn("SEC001", rules(root, honor_ignores=False))

    def test_inline_comment_in_app_and_code_checks(self):
        root = tree({"server.js": "app.use(cors()) // stingward:ignore\n",
                     "app.py": "import os\nfrom flask import request\n\n@app.route('/r')\ndef r():\n"
                               "    os.system('ls ' + request.args['d'])  # stingward:ignore\n"})
        self.assertEqual(rules(root), [])
        self.assertEqual(rules(root, honor_ignores=False), ["APP003", "COD002"])

    def test_context_records_the_choice(self):
        root = tree({"main.py": "print('hello')\n"})
        self.assertTrue(scan.run(root, offline=True)[0].honor_ignores)
        self.assertFalse(scan.run(root, offline=True, honor_ignores=False)[0].honor_ignores)


class Cli(unittest.TestCase):
    def test_flag_shows_ignored_findings(self):
        root = tree({"server.js": CORS, ".stingwardignore": "*\n"})
        code, out, _ = main([root, "--offline", "--format", "json", "--fail-on", "never"])
        self.assertEqual(json.loads(out)["findings"], [])
        code, out, _ = main([root, "--offline", "--format", "json", "--fail-on", "never", "--no-ignore"])
        self.assertEqual([f["rule"] for f in json.loads(out)["findings"]], ["APP003"])

    def test_flag_counts_for_fail_on(self):
        root = tree({"src/keys.py": f'TOKEN = "{GH}"  # stingward:ignore\n'})
        self.assertEqual(main([root, "--offline", "--format", "json"])[0], 0)
        self.assertEqual(main([root, "--offline", "--format", "json", "--no-ignore"])[0], 1)

    def test_help_lists_flag_in_both_languages(self):
        for lang, word in (("en", "stingward:ignore"), ("pt", "stingward:ignore")):
            with self.subTest(lang=lang):
                _, out, _ = main(["--help", "--lang", lang])
                self.assertIn("--no-ignore", out)
                self.assertIn(word, out)

    def test_review_template_keeps_ignored_findings(self):
        root = tree({"server.js": CORS, ".stingwardignore": "APP003\n"})
        path = os.path.join(tree({}), "review.json")
        main([root, "--offline", "--format", "json", "--no-ignore", "--review-template", path])
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual([i["finding"]["rule"] for i in data["findings"]], ["APP003"])


class Report(unittest.TestCase):
    NOTE_EN = "this check did not apply those requests"
    NOTE_PT = "esta verificação não aceitou esses pedidos"

    def html(self, root, *extra, lang="en"):
        out = os.path.join(tree({}), "r.html")
        main([root, "--offline", "--lang", lang, "--fail-on", "never", "--format", "json", "--html", out, *extra])
        with open(out, encoding="utf-8") as fh:
            return fh.read()

    def test_note_when_the_project_asked_to_hide_findings(self):
        root = tree({"server.js": CORS, ".stingwardignore": "APP003\n"})
        self.assertIn(self.NOTE_EN, self.html(root, "--no-ignore"))
        self.assertIn(self.NOTE_PT, self.html(root, "--no-ignore", lang="pt"))

    def test_note_for_an_inline_comment_only(self):
        root = tree({"server.js": "app.use(cors()) // stingward:ignore\n"})
        self.assertIn(self.NOTE_EN, self.html(root, "--no-ignore"))

    def test_no_note_without_the_flag_or_without_requests(self):
        asked = tree({"server.js": CORS, ".stingwardignore": "APP003\n"})
        page = self.html(asked)
        self.assertNotIn(self.NOTE_EN, page)
        self.assertIn(".stingwardignore", page)  # o aviso de sempre: as regras escondem achados de propósito
        self.assertNotIn(self.NOTE_EN, self.html(tree({"server.js": CORS}), "--no-ignore"))

    def test_with_the_flag_the_usual_hiding_warning_is_gone(self):
        page = self.html(tree({"server.js": CORS, ".stingwardignore": "APP003\n"}), "--no-ignore")
        self.assertNotIn("hides some findings on purpose", page)


class AiReviewFixed(unittest.TestCase):
    """Sem os "ignorar", uma linha do .stingwardignore ou um comentário não escondem nada: um "fixed" de achado que
    sumiu vale de novo na revisão por IA."""

    def review_file(self, where, rule="APP003"):
        path = os.path.join(tree({}), "review.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"stingward_review": 1, "review_kind": "ai", "findings": [
                {"fingerprint": "0123456789abcdef", "status": "fixed", "comment": "Gone.",
                 "finding": {"rule": rule, "severity": "high", "where": where, "title": "CORS"}}]}, fh)
        return path

    def test_fixed_behind_an_ignore_line_is_refused_only_when_ignores_apply(self):
        root = tree({"server.js": "app.listen(3000)\n", ".stingwardignore": "APP003 server.js\n"})
        path = self.review_file("server.js:1")
        code, _, err = main([root, "--offline", "--format", "json", "--review", path])
        self.assertEqual(code, 2)
        self.assertIn(".stingwardignore", err)
        code, out, err = main([root, "--offline", "--format", "json", "--fail-on", "never", "--review", path,
                               "--no-ignore"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["findings"], [])

    def test_fixed_behind_an_inline_comment_is_accepted_with_no_ignore(self):
        root = tree({"server.js": "app.listen(3000) // stingward:ignore\n"})
        path = self.review_file("server.js:1")
        self.assertEqual(main([root, "--offline", "--format", "json", "--review", path])[0], 2)
        code, _, err = main([root, "--offline", "--format", "json", "--fail-on", "never", "--review", path,
                             "--no-ignore"])
        self.assertEqual(code, 0, err)

    def test_hidden_reason_respects_the_context(self):
        root = tree({"server.js": "app.listen(3000)\n", ".stingwardignore": "*\n"})
        on, _ = scan.run(root, offline=True)
        off, _ = scan.run(root, offline=True, honor_ignores=False)
        self.assertIsNotNone(review._hidden(on, "APP003", "server.js:1"))
        self.assertIsNone(review._hidden(off, "APP003", "server.js:1"))


if __name__ == "__main__":
    unittest.main()
