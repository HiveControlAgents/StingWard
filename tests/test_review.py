"""Revisão humana: impressão digital estável, arquivo de revisão, cliente e parecer, e o que muda na nota e nos relatórios.

Nada aqui usa a rede. Segredos de teste são falsos e montados por concatenação, como no resto da suíte: nenhum
comentário ou parecer pode deixar passar um deles, nem em pedaço de 12 caracteres.
"""
import contextlib
import html.parser
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from stingward import cli, report, report_html, review, vulndb
from stingward.model import Context, Finding

# Com cara de chave de verdade, como em test_cli: valores com "Fake" ou "Demo" a ferramenta já trata como exemplo.
GH = "ghp_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"
OAI = "sk-" + "proj-" + "N4bV7cX1zL9kJ3hG6fD2sA8qW5eR0tY"
DB_PASSWORD = "S3cr3t" + "Passw0rd"
OPAQUE = "Zq8vN3kL" + "0pR7tY2wX5mB9cD4"
PEM_BODY = "MIIEowIBAAKCAQEA7bq9m3kKx1" + "Zq8W3e5R7t9Y1u3I5o7P9a1S3"
SECRETS = [GH, OAI, DB_PASSWORD, OPAQUE, PEM_BODY]
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + PEM_BODY + "\n" + PEM_BODY[::-1] + "\n-----END RSA " + "PRIVATE KEY-----"

APP = {
    "src/db.js": f'const db = connect({{\n  password: "{DB_PASSWORD}",\n}});\n',
    "src/config.py": f'import os\nGITHUB_TOKEN = "{GH}"\n',
    ".env": f"NEXT_PUBLIC_OPENAI_API_KEY={OAI}\n",
    ".gitignore": ".env\n",
    "api.js": 'res.setHeader("Access-Control-Allow-Origin", "*");\n',
}


def tree(files):
    root = tempfile.mkdtemp(prefix="stingward-review-")
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return root


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def run(argv):
    """cli.main em processo, sem rede: (código, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(vulndb, "fetch_json", side_effect=AssertionError("network access in a test")))
        stack.enter_context(mock.patch.dict(os.environ, {"STINGWARD_LANG": "en"}))
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


def scan_json(root):
    code, out, _ = run([root, "--offline", "--format", "json"])
    return json.loads(out)["findings"]


class Tags(html.parser.HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags, self.data = [], []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.data.append(data)


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tree(APP)
        self.dir = tempfile.mkdtemp(prefix="stingward-review-out-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def template(self, lang="en"):
        code, _, err = run([self.root, "--offline", "--review-template", self.path("r.json"), "--lang", lang])
        self.assertIn(code, (0, 1), err)
        with open(self.path("r.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def save_review(self, doc):
        write(self.path("r.json"), json.dumps(doc, ensure_ascii=False, indent=2))
        return self.path("r.json")

    def decide(self, decisions, reviewer="Ana Revisora"):
        """decisions: {regra: (status, comentário)}; o resto fica confirmado."""
        doc = self.template()
        doc["reviewer"] = reviewer
        for item in doc["findings"]:
            item["status"], item["comment"] = decisions.get(item["finding"]["rule"], ("confirmed", ""))
        return self.save_review(doc)

    def assertNoSecret(self, text, where):
        for s in SECRETS:
            leaked = [s[i:i + 12] for i in range(len(s) - 11) if s[i:i + 12] in text]
            self.assertEqual(leaked, [], (where, s))


# =========================================================================== impressão digital

class Fingerprint(Case):
    def fps(self):
        return {(f["rule"], f["file"]): f["fingerprint"] for f in scan_json(self.root)}

    def test_every_finding_has_a_unique_hex_fingerprint(self):
        found = scan_json(self.root)
        self.assertTrue(found)
        fps = [f["fingerprint"] for f in found]
        for fp in fps:
            self.assertRegex(fp, r"^[0-9a-f]{16}$")
        self.assertEqual(len(fps), len(set(fps)))

    def test_survives_edits_elsewhere_in_the_file(self):
        before = self.fps()
        write(os.path.join(self.root, "src/db.js"), "// a comment\n\n\n" + APP["src/db.js"].replace("  password", "      password") + "\nexport default db;\n")
        write(os.path.join(self.root, "src/config.py"), "import os\nimport sys\n\n# token for the CI\n" + APP["src/config.py"].split("\n", 1)[1])
        after = self.fps()
        self.assertEqual(before, after)

    def test_changes_when_the_flagged_line_changes(self):
        before = self.fps()
        write(os.path.join(self.root, "api.js"), 'res.setHeader("Access-Control-Allow-Origin", "*"); // public\n')
        after = self.fps()
        self.assertNotEqual(before[("APP003", "api.js")], after[("APP003", "api.js")])
        self.assertEqual(before[("SEC001", "src/config.py")], after[("SEC001", "src/config.py")])

    def test_rotating_the_secret_keeps_the_fingerprint(self):
        before = self.fps()
        write(os.path.join(self.root, "src/config.py"), APP["src/config.py"].replace(GH, GH[:-6] + "Zz99Yy"))
        self.assertEqual(before[("SEC001", "src/config.py")], self.fps()[("SEC001", "src/config.py")])

    def test_identical_lines_get_an_order_number(self):
        line = f'GITHUB_TOKEN = "{GH}"\n'
        rel = os.path.join(self.root, "src/config.py")
        write(rel, line + "x = 1\n" + line)
        first = [f["fingerprint"] for f in scan_json(self.root) if f["file"] == "src/config.py"]
        self.assertEqual(len(set(first)), 2)
        write(rel, "# top\n" + line + "x = 1\n" + line + "y = 2\n" + line)
        second = [f["fingerprint"] for f in scan_json(self.root) if f["file"] == "src/config.py"]
        self.assertEqual(len(set(second)), 3)
        self.assertEqual(second[:2], first)

    def test_package_findings_use_package_and_version(self):
        ctx = Context(root=self.root, files=[])
        a = Finding("DEP001", "high", "package-lock.json", 10, {"pkg": "next", "version": "14.1.0", "fixed": "14.2.25", "epss": 0.9})
        b = Finding("DEP001", "critical", "package-lock.json", 10, {"pkg": "next", "version": "14.1.0", "fixed": "15.5.24", "epss": 0.1})
        c = Finding("DEP001", "high", "package-lock.json", 10, {"pkg": "next", "version": "14.2.0", "fixed": "15.5.24"})
        review.assign(ctx, [a])
        review.assign(ctx, [b])
        review.assign(ctx, [c])
        self.assertEqual(a.fingerprint, b.fingerprint)  # base de falhas mudou, o achado é o mesmo
        self.assertNotEqual(a.fingerprint, c.fingerprint)

    def test_no_secret_in_the_fingerprint_input(self):
        ctx = Context(root=self.root, files=[])
        seen = []
        real = review._digest
        with mock.patch.object(review, "_digest", side_effect=lambda *p: seen.append(p) or real(*p)):
            review.assign(ctx, [Finding("SEC001", "high", "src/config.py", 2, {}), Finding("SEC001", "high", ".env", 1, {})])
        self.assertTrue(seen)
        self.assertNoSecret(repr(seen), "digest input")

    def test_json_and_sarif_carry_it(self):
        code, out, _ = run([self.root, "--offline", "--format", "sarif"])
        results = json.loads(out)["runs"][0]["results"]
        fps = {f["fingerprint"] for f in scan_json(self.root)}
        self.assertEqual({r["properties"]["fingerprint"] for r in results}, fps)
        doc = json.loads(run([self.root, "--offline", "--format", "json"])[1])
        self.assertEqual(set(doc), {"tool", "version", "grade", "sources", "findings"})
        self.assertNotIn("review", doc["findings"][0])

    def test_hand_built_findings_get_one_too(self):
        ctx = Context(root=self.root, files=[])
        doc = json.loads(report.as_json(ctx, [Finding("APP003", "medium", "api.js", 1, {})], "en"))
        self.assertRegex(doc["findings"][0]["fingerprint"], r"^[0-9a-f]{16}$")


# =========================================================================== arquivo de revisão

class ReviewFile(Case):
    def test_template_has_one_entry_per_finding(self):
        doc = self.template()
        found = scan_json(self.root)
        self.assertEqual(doc["stingward_review"], 1)
        self.assertEqual([i["fingerprint"] for i in doc["findings"]], [f["fingerprint"] for f in found])
        for item in doc["findings"]:
            self.assertEqual((item["status"], item["comment"]), ("", ""))
            self.assertEqual(set(item["finding"]), {"rule", "severity", "where", "title"})
        self.assertIn("false_positive", doc["help"])
        self.assertNoSecret(json.dumps(doc), "template")

    def test_template_keeps_what_was_reviewed(self):
        doc = self.template()
        doc["reviewer"] = "Ana"
        doc["findings"][0].update(status="confirmed", comment="Checked by hand.")
        doc["findings"].append({"fingerprint": "0123456789abcdef", "status": "fixed", "comment": "Gone."})
        self.save_review(doc)
        write(os.path.join(self.root, "src/db.js"), "\n\n" + APP["src/db.js"])  # mexe no arquivo, não no achado
        code, _, err = run([self.root, "--offline", "--review-template", self.path("r.json")])
        self.assertIn("1 already reviewed, 1 no longer matching", err)
        with open(self.path("r.json"), encoding="utf-8") as fh:
            again = json.load(fh)
        self.assertEqual(again["reviewer"], "Ana")
        self.assertEqual((again["findings"][0]["status"], again["findings"][0]["comment"]), ("confirmed", "Checked by hand."))
        self.assertEqual(again["findings"][-1], {"fingerprint": "0123456789abcdef", "status": "fixed", "comment": "Gone."})

    def test_a_broken_file_is_not_overwritten(self):
        write(self.path("r.json"), "{not json")
        code, _, err = run([self.root, "--offline", "--review-template", self.path("r.json")])
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", err)
        with open(self.path("r.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "{not json")

    def test_errors_say_where(self):
        cases = {
            "{not json": "invalid JSON",
            '{"x": 1}': 'missing the "findings" list',
            '{"findings": [{"fingerprint": "zz", "status": "confirmed"}]}': "findings[1]: fingerprint 'zz'",
            '{"findings": [{"fingerprint": "0123456789abcdef", "status": "maybe"}]}': "status 'maybe'",
            '{"findings": [{"fingerprint": "0123456789abcdef"}, {"fingerprint": "0123456789ABCDEF"}]}': "findings[2]: fingerprint 0123456789abcdef",
            '{"findings": [{"fingerprint": "0123456789abcdef", "comment": 3}]}': '"comment"',
            '{"stingward_review": 2, "findings": []}': "stingward_review 2",
            '{"reviewer": ["x"], "findings": []}': '"reviewer"',
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                write(self.path("bad.json"), text)
                code, out, err = run([self.root, "--offline", "--review", self.path("bad.json")])
                self.assertEqual(code, 2)
                self.assertIn(want, err)
                self.assertEqual(out, "")
        code, _, err = run([self.root, "--offline", "--review", self.path("missing.json")])
        self.assertEqual(code, 2)

    def test_status_spelling_is_forgiving(self):
        write(self.path("r.json"), json.dumps({"findings": [
            {"fingerprint": "0123456789abcdef", "status": "False Positive"},
            {"fingerprint": "0123456789abcdee", "status": "accepted-risk"},
            {"fingerprint": "0123456789abcded", "status": "todo"}]}))
        rv = review.load(self.path("r.json"))
        self.assertEqual([s for s, _ in rv.entries.values()], ["false_positive", "accepted_risk", ""])

    def test_bom_and_bare_list(self):
        with open(self.path("r.json"), "w", encoding="utf-8-sig") as fh:
            fh.write('[{"fingerprint": "0123456789abcdef", "status": "fixed"}]')
        self.assertEqual(review.load(self.path("r.json")).entries, {"0123456789abcdef": ("fixed", "")})

    def test_warnings_for_stale_and_unreviewed_entries(self):
        doc = self.template()
        doc["findings"][0]["status"] = "confirmed"
        doc["findings"].append({"fingerprint": "0123456789abcdef", "status": "fixed"})
        self.save_review(doc)
        _, _, err = run([self.root, "--offline", "--review", self.path("r.json")])
        self.assertIn("1 item(s) in", err)
        self.assertIn(f"{len(doc['findings']) - 2} finding(s) still have no status", err)


# =========================================================================== nota e código de saída

class Grade(Case):
    def test_false_positives_and_fixed_leave_the_grade_and_the_exit_code(self):
        code, out, _ = run([self.root, "--offline", "--format", "json"])
        self.assertEqual((code, json.loads(out)["grade"]), (1, "F"))
        path = self.decide({"SEC001": ("false_positive", "Test value."), "APP001": ("fixed", "Renamed during the audit.")})
        code, out, _ = run([self.root, "--offline", "--format", "json", "--review", path])
        doc = json.loads(out)
        self.assertEqual(code, 0)  # o que sobrou é médio: abaixo do --fail-on high
        self.assertEqual(doc["grade"], "B")
        self.assertEqual(doc["review"]["reviewer"], "Ana Revisora")
        self.assertEqual(doc["review"]["counts"]["false_positive"], sum(1 for f in doc["findings"] if f["rule"] == "SEC001"))
        statuses = {f["rule"]: f["review"]["status"] for f in doc["findings"]}
        self.assertEqual((statuses["SEC001"], statuses["APP001"], statuses["APP003"]), ("false_positive", "fixed", "confirmed"))
        self.assertEqual(len(doc["findings"]), len(scan_json(self.root)))  # JSON continua com um registro por achado

    def test_accepted_risk_still_counts(self):
        path = self.decide({"SEC001": ("accepted_risk", "Client decision."), "APP001": ("accepted_risk", "")})
        code, out, _ = run([self.root, "--offline", "--format", "json", "--review", path])
        self.assertEqual((code, json.loads(out)["grade"]), (1, "F"))

    def test_unreviewed_findings_count(self):
        doc = self.template()
        self.save_review(doc)
        code, out, _ = run([self.root, "--offline", "--format", "json", "--review", self.path("r.json")])
        self.assertEqual((code, json.loads(out)["grade"]), (1, "F"))


# =========================================================================== relatório em HTML

class Html(Case):
    def render(self, decisions, *extra, lang="en"):
        path = self.decide(decisions)
        code, out, err = run([self.root, "--offline", "--format", "html", "--lang", lang, "--review", path] + list(extra))
        return out, err

    def section(self, out, sid):
        m = re.search(rf'<section[^>]* id="{sid}">.*?</section>', out, re.S)
        return m.group(0) if m else ""

    def test_false_positives_go_to_the_appendix(self):
        out, _ = self.render({"SEC001": ("false_positive", "A **test** value, not a real key.")})
        app = self.section(out, "appendix")
        self.assertIn("Appendix: false positives", app)
        self.assertIn("Secret in code", app)
        self.assertIn("A <strong>test</strong> value, not a real key.", app)
        self.assertIn('<span class="rv rv-false_positive">False positive</span>', app)
        for sid in ("summary", "plan", "findings"):
            self.assertNotIn("Secret in code", self.section(out, sid), sid)
        self.assertIn('href="#appendix"', out)
        self.assertEqual([a["id"] for t, a in Tags(out).tags if t == "section"],
                         ["cover", "summary", "plan", "findings", "scope", "appendix"])

    def test_accepted_risk_leaves_fix_first_but_stays_visible(self):
        out, _ = self.render({"APP001": ("accepted_risk", "Client decision, see the notes.")})
        summary = self.section(out, "summary")
        self.assertNotIn("Secret exposed to the browser", summary)
        self.assertIn('<span class="grade-v">F</span>', summary)  # SEC001 crítico continua
        plan = self.section(out, "plan")
        self.assertIn("No action planned: accepted risk or already fixed", plan)
        self.assertLess(plan.index("Critical: fix now"), plan.index("No action planned"))
        self.assertIn("Secret exposed to the browser", plan.split("No action planned", 1)[1])
        self.assertIn('<span class="rv rv-accepted_risk">Accepted risk</span>', self.section(out, "findings"))

    def test_fixed_is_marked_and_not_counted(self):
        out, _ = self.render({"SEC001": ("fixed", ""), "APP001": ("fixed", "")})
        self.assertIn('<span class="grade-v">B</span>', out)
        self.assertIn('<span class="rv rv-fixed">Fixed</span>', self.section(out, "findings"))
        self.assertNotIn('id="appendix"', out)

    def test_cover_scope_and_grade_rules(self):
        notes = self.path("notes.md")
        write(notes, "Short summary.\n")
        out, _ = self.render({"SEC001": ("false_positive", "")}, "--client", "Example Client LLC", "--notes", notes)
        cover = self.section(out, "cover")
        self.assertIn("<dt>Prepared for</dt><dd><strong>Example Client LLC</strong></dd>", cover)
        self.assertIn("<dt>Human review</dt><dd>Ana Revisora · ", cover)
        self.assertIn("false positive", cover)
        scope = self.section(out, "scope")
        self.assertIn("Ana Revisora checked the findings by hand", scope)
        self.assertIn("How the review changes the grade", scope)
        self.assertIn("False positives do not count", scope)
        self.assertIn("Accepted risks still count toward the grade", scope)
        self.assertIn("checked by a person", scope)
        summary = self.section(out, "summary")
        self.assertIn("After the human review, false positives and what was fixed during the audit do not count.", summary)
        self.assertIn("Analyst summary", summary)
        self.assertIn("Ana Revisora · ", summary)

    def test_portuguese(self):
        notes = self.path("notes.md")
        write(notes, "Resumo **curto**.\n")
        out, _ = self.render({"SEC001": ("false_positive", "Valor de teste.")}, "--client", "Cliente Exemplo", "--notes", notes, lang="pt")
        for want in ("Preparado para", "Parecer do analista", "Apêndice: alarmes falsos", "Alarme falso", "Revisão humana",
                     "Como a revisão muda a nota", "Resumo <strong>curto</strong>."):
            self.assertIn(want, out)

    def test_without_review_nothing_changes(self):
        code, out, _ = run([self.root, "--offline", "--format", "html"])
        self.assertNotIn('class="rv ', out)
        self.assertNotIn("Human review", out)
        self.assertNotIn('id="appendix"', out)
        self.assertNotIn("Prepared for", out)

    def test_client_and_notes_without_a_review(self):
        notes = self.path("notes.md")
        write(notes, "- one\n- two\n")
        code, out, _ = run([self.root, "--offline", "--format", "html", "--client", "X", "--notes", notes])
        self.assertIn("<dt>Prepared for</dt>", out)
        self.assertIn("<ul><li>one</li><li>two</li></ul>", out)
        self.assertNotIn("Human review", out)
        self.assertNotIn('class="rv ', out)


# =========================================================================== escape e segredos

EVIL = '<script>alert(1)</script><img src=x onerror=alert(1)><b>bold</b>[x](javascript:alert(1)) @everyone \u202e'


class Escaping(Case):
    def test_comments_notes_client_and_reviewer_are_inert(self):
        notes = self.path("notes.md")
        write(notes, f"{EVIL}\n\n- **{EVIL}** and `{EVIL}`\n")
        path = self.decide({"SEC001": ("false_positive", EVIL), "APP001": ("confirmed", f"`{EVIL}`")}, reviewer=EVIL)
        for fmt in ("html", "markdown", "text"):
            code, out, _ = run([self.root, "--offline", "--format", fmt, "--review", path, "--notes", notes, "--client", EVIL])
            with self.subTest(fmt=fmt):
                self.assertNotIn("\u202e", out)
                if fmt != "text":
                    self.assertNotIn("<script", out.lower())
                    self.assertNotIn("<img", out.lower())
                if fmt == "html":
                    doc = Tags(out)
                    self.assertFalse({t for t, _ in doc.tags} & {"script", "img", "b", "iframe"})
                    for tag, attrs in doc.tags:
                        self.assertFalse(any(k.startswith("on") for k in attrs), (tag, attrs))
                        self.assertFalse(attrs.get("href", "#").lower().startswith("javascript"))
                    self.assertIn(EVIL.replace("\u202e", "\\u202e"), "".join(doc.data))
                if fmt == "markdown":
                    self.assertNotRegex(out, r"(?<!\\)\]\(javascript")
                    self.assertNotIn("@everyone", out)
                if fmt == "text":
                    self.assertIn("<script>alert(1)</script>", out)  # texto puro no terminal

    def test_notes_subset(self):
        m = review.Masker()
        blocks = review.parse("First line\nsame paragraph with **bold** and `code`.\n\n- item one\n  continued\n* item two\n\nAfter \\*not bold\\* and \\`tick\\`.\n**open", m)
        self.assertEqual(blocks, [
            ("p", [("", "First line same paragraph with "), ("b", "bold"), ("", " and "), ("c", "code"), ("", ".")]),
            ("ul", [[("", "item one continued")], [("", "item two")]]),
            ("p", [("", "After *not bold* and `tick`. **open")]),
        ])
        self.assertEqual(review.inline("**`x`** y"), [("bc", "x"), ("", " y")])
        self.assertEqual(review.inline("a ** b"), [("", "a ** b")])
        self.assertEqual(review.inline("``"), [("", "``")])
        self.assertEqual(report_html._md_html(review.parse("# Title\n1. one", m)), "<p># Title 1. one</p>")


class Secrets(Case):
    def notes(self):
        text = (f"Rotate {GH} today.\n\n"
                f"The fallback password was {DB_PASSWORD} in src/db.js.\n\n"   # prosa: só a lista do projeto pega
                f"- Piece: {DB_PASSWORD[2:16]} and {OAI[5:20]}\n"
                f"- Split: {GH[:10]}**{GH[10:]}**\n"
                f"- `api_key = \"{OPAQUE}\"`\n\n"
                f"{PEM}\n")
        path = self.path("notes.md")
        write(path, text)
        return path

    def test_no_secret_leaks_through_comments_or_notes(self):
        comment = f'Seen as password: "{DB_PASSWORD}" and token {GH}. Backup: {OPAQUE}. Key: {PEM}'
        path = self.decide({"SEC001": ("false_positive", comment), "APP001": ("confirmed", f"**{OAI}**")})
        notes = self.notes()
        for lang in ("en", "pt"):
            for fmt in ("html", "markdown", "text", "json"):
                code, out, err = run([self.root, "--offline", "--format", fmt, "--lang", lang, "--review", path, "--notes", notes])
                self.assertNoSecret(out, (lang, fmt))
                self.assertIn("REDACTED", out, (lang, fmt))
                self.assertIn({"en": "masked something that looks like a secret", "pt": "mascarei algo que parece segredo"}[lang], err)

    def test_secret_files_written_alongside(self):
        path = self.decide({"SEC001": ("confirmed", f"token {GH}")})
        outs = [self.path(n) for n in ("r.html", "r.md", "r.json")]
        run([self.root, "--offline", "--review", path, "--notes", self.notes(), "--html", outs[0], "--markdown", outs[1], "--json", outs[2]])
        for p in outs:
            with open(p, encoding="utf-8") as fh:
                self.assertNoSecret(fh.read(), p)

    def test_client_and_reviewer_names_are_masked_too(self):
        path = self.decide({}, reviewer=f"Ana {DB_PASSWORD}")
        for fmt in ("html", "markdown", "text", "json"):
            code, out, err = run([self.root, "--offline", "--format", fmt, "--review", path, "--client", f"Client {OAI[:20]}"])
            self.assertNoSecret(out, fmt)
            self.assertIn("masked something that looks like a secret", err)

    def test_a_pgp_private_key_is_masked_whole(self):
        # A última linha do corpo de uma chave PGP é curta: linha a linha ela passaria como texto comum.
        pgp = ("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\n\n" + PEM_BODY + "\n" + OPAQUE[:11] + "\n=Ab3x\n"
               "-----END PGP " + "PRIVATE KEY BLOCK-----")
        m = review.Masker()
        self.assertEqual(m.lines(f"Found this in the repo:\n{pgp}\nRotate it."),
                         "Found this in the repo:\n[REDACTED:private_key]\nRotate it.")
        self.assertTrue(m.changed)

    def test_long_notes_stay_fast(self):
        ctx = Context(root=self.root, files=[])
        found = [Finding("SEC001", "high", "src/db.js", 2, {}), Finding("SEC001", "high", ".env", 1, {})]
        m = review.Masker(ctx, found)
        text = ("Nothing to see in this paragraph, only words. " * 4000) + DB_PASSWORD
        out = m(text)
        self.assertNotIn(DB_PASSWORD, out)
        self.assertTrue(out.endswith("[REDACTED:secret_field]"))

    def test_project_secrets_are_known_even_in_prose(self):
        ctx = Context(root=self.root, files=[])
        found = [Finding("SEC001", "high", "src/db.js", 2, {}), Finding("SEC001", "high", ".env", 1, {})]
        m = review.Masker(ctx, found)
        self.assertIn(DB_PASSWORD, m.known)
        self.assertEqual(m(f"it was {DB_PASSWORD}, really"), "it was [REDACTED:secret_field], really")
        self.assertTrue(m.changed)

    def test_whole_file_findings_teach_every_line(self):
        write(os.path.join(self.root, ".env.local"), f"APP_NAME=shop\nDB_PASSWORD={DB_PASSWORD}\n")
        ctx = Context(root=self.root, files=[])
        m = review.Masker(ctx, [Finding("SEC003", "medium", ".env.local", None, {})])
        self.assertEqual(m.known, [DB_PASSWORD])
        self.assertEqual(m(f"old value {DB_PASSWORD[:13]}"), "old value [REDACTED:secret_field]")

    def test_prose_after_a_sensitive_word_stays(self):
        m = review.Masker()
        for text in ("**Login and session:** none of the API routes checks who is calling.",
                     "Senha: troque já, e revogue a antiga.", "Token: rotate it in the dashboard."):
            self.assertEqual(m(text), text)
        self.assertFalse(m.changed)
        self.assertEqual(m("password: hunter2"), "password: [REDACTED:secret_field]")
        self.assertTrue(m.changed)


# =========================================================================== texto e Markdown

class TextAndMarkdown(Case):
    def test_text_honors_the_review(self):
        notes = self.path("notes.md")
        write(notes, "First.\n\n- one\n")
        path = self.decide({"SEC001": ("false_positive", "Test value."), "APP001": ("accepted_risk", "Client decision.")})
        code, out, _ = run([self.root, "--offline", "--review", path, "--client", "Example Client", "--notes", notes, "--no-color"])
        self.assertIn("Prepared for: Example Client", out)
        self.assertIn("Reviewed by Ana Revisora: ", out)
        self.assertIn("Analyst summary:\n  First.\n\n  - one\n", out)
        self.assertIn("[Accepted risk]", out)
        self.assertIn("   review: Accepted risk · Client decision.", out)
        main, discarded = out.split("Discarded as false positives", 1)
        self.assertNotIn("Secret in code", main)
        self.assertIn("Secret in code", discarded)
        self.assertIn("Test value.", discarded)
        self.assertNotIn("Fix these first", out)  # o crítico que sobrou é risco aceito
        self.assertIn("The grade leaves out false positives", out)
        self.assertIn("Grade: F", out)  # risco aceito continua contando

    def test_markdown_honors_the_review(self):
        path = self.decide({"SEC001": ("false_positive", "Test | value <b>x</b>"), "APP003": ("fixed", "")})
        code, out, _ = run([self.root, "--offline", "--format", "markdown", "--review", path])
        self.assertIn("**Reviewed by Ana Revisora:**", out)
        self.assertIn("<b>Fixed</b>", out)
        self.assertIn("**Discarded as false positives (", out)
        self.assertIn("Test \\| value &lt;b&gt;x&lt;/b&gt;", out)
        table = out.split("**Discarded", 1)[0]
        self.assertNotIn("Secret in code", table)


if __name__ == "__main__":
    unittest.main()
