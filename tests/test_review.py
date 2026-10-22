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

from stingward import cli, report, report_html, review, scan, vulndb
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
        self.assertEqual(set(doc), {"tool", "version", "grade", "sources", "not_read", "findings"})
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
        self.assertEqual(again["findings"][-1], {"fingerprint": "0123456789abcdef", "status": "fixed", "comment": "Gone.", "stale": True})

    def test_an_item_that_no_longer_matches_is_marked_and_unmarked(self):
        # O item que não bate mais fica no arquivo (o comentário de quem revisou está nele), marcado "stale": true;
        # quando o achado volta, a marca sai.
        doc = self.template()
        item = next(i for i in doc["findings"] if i["finding"]["where"].startswith("src/db.js"))
        item.update(status="confirmed", comment="Checked by hand.")
        self.save_review(doc)
        write(os.path.join(self.root, "src/db.js"), "const db = connect();\n")
        code, _, err = run([self.root, "--offline", "--lang", "en", "--review-template", self.path("r.json")])
        self.assertIn('1 no longer matching any finding (marked "stale": true and kept at the end)', err)
        with open(self.path("r.json"), encoding="utf-8") as fh:
            again = json.load(fh)
        gone = [i for i in again["findings"] if i.get("stale")]
        self.assertEqual([(i["fingerprint"], i["status"], i["comment"], i["stale"]) for i in gone],
                         [(item["fingerprint"], "confirmed", "Checked by hand.", True)])
        self.assertEqual(again["findings"][-1], gone[0])  # no fim do arquivo
        write(os.path.join(self.root, "src/db.js"), APP["src/db.js"])
        run([self.root, "--offline", "--lang", "en", "--review-template", self.path("r.json")])
        with open(self.path("r.json"), encoding="utf-8") as fh:
            back = json.load(fh)
        match = next(i for i in back["findings"] if i["fingerprint"] == item["fingerprint"])
        self.assertNotIn("stale", match)
        self.assertEqual((match["status"], match["comment"]), ("confirmed", "Checked by hand."))
        self.assertFalse(any("stale" in i for i in back["findings"]))

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

    def test_utf16_review_and_notes_files(self):
        # Windows PowerShell 5 writes UTF-16 LE with a byte order mark on `>` (and Notepad on "Unicode").
        doc = '[{"fingerprint": "0123456789abcdef", "status": "fixed", "comment": "Conferido à mão."}]\r\n'
        notes = "Resumo **curto**: tudo conferido.\r\n\r\n- Ação feita\r\n"
        for name, bom, codec in (("le", b"\xff\xfe", "utf-16-le"), ("be", b"\xfe\xff", "utf-16-be")):
            with self.subTest(utf16=name):
                with open(self.path("r.json"), "wb") as fh:
                    fh.write(bom + doc.encode(codec))
                with open(self.path("notes.md"), "wb") as fh:
                    fh.write(bom + notes.encode(codec))
                self.assertEqual(review.load(self.path("r.json")).entries, {"0123456789abcdef": ("fixed", "Conferido à mão.")})
                self.assertEqual(review.load_notes(self.path("notes.md")), "Resumo **curto**: tudo conferido.\n\n- Ação feita\n")
                code, out, err = run([self.root, "--offline", "--format", "markdown", "--notes", self.path("notes.md")])
                self.assertIn(code, (0, 1), err)
                self.assertIn("tudo conferido", out)

    def test_review_file_that_is_not_utf8_is_refused(self):
        with open(self.path("r.json"), "wb") as fh:
            fh.write('[{"fingerprint": "0123456789abcdef", "comment": "Conferido à mão."}]'.encode("cp1252"))
        code, out, err = run([self.root, "--offline", "--review", self.path("r.json")])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("not UTF-8", err)

    def test_warnings_for_stale_and_unreviewed_entries(self):
        doc = self.template()
        doc["findings"][0]["status"] = "confirmed"
        doc["findings"].append({"fingerprint": "0123456789abcdef", "status": "confirmed"})
        doc["findings"].append({"fingerprint": "0123456789abcdee", "status": "fixed"})  # corrigido e sumido: esperado
        self.save_review(doc)
        _, _, err = run([self.root, "--offline", "--review", self.path("r.json")])
        self.assertIn("1 item(s) in", err)
        self.assertIn(f"{len(doc['findings']) - 3} finding(s) still have no status", err)


# =========================================================================== corrigido durante a auditoria

class FixedAndGone(Case):
    """Um achado "fixed" some na nova varredura. O relatório o lista como corrigido durante a auditoria, com o bloco
    "finding" que o arquivo de revisão guardou."""

    def fix_cors(self):
        path = self.decide({"APP003": ("fixed", "Origin list set to the shop domain.")})
        write(os.path.join(self.root, "api.js"), 'res.setHeader("Access-Control-Allow-Origin", "https://shop.example");\n')
        return path

    def test_listed_in_every_format(self):
        path = self.fix_cors()
        out = {fmt: run([self.root, "--offline", "--lang", "en", "--format", fmt, "--review", path])
               for fmt in ("text", "markdown", "html", "json")}
        for fmt, (_, _, err) in out.items():
            self.assertNotIn("match no finding", err, fmt)  # o que foi corrigido e sumiu é o esperado: sem aviso
        text = out["text"][1]
        self.assertIn("Fixed during the audit, no longer in this scan (1):\n - 🟡 CORS open to any website · api.js:1  [APP003]\n"
                      "     Origin list set to the shop domain.\n", text)
        self.assertIn("1 fixed during the audit", text)
        md = out["markdown"][1]
        self.assertIn("**Fixed during the audit, no longer in this scan (1)**\n\n- 🟡 CORS open to any website · <sub>api.js:1</sub>"
                      "<br><sub><b>Fixed</b> · Origin list set to the shop domain.</sub>", md)
        plan = out["html"][1].split('<section id="plan">', 1)[1].split("</section>", 1)[0]
        done = plan.split('class="band band-done"', 1)[1]
        self.assertIn("CORS open to any website", done)
        self.assertIn('<span class="rv rv-fixed">Fixed</span>', done)
        self.assertIn("1 fixed during the audit", out["html"][1])
        doc = json.loads(out["json"][1])
        self.assertEqual(doc["review"]["counts"]["fixed"], 1)
        self.assertNotIn("APP003", [f["rule"] for f in doc["findings"]])  # JSON segue com um registro por achado atual

    def test_only_fixed_items_are_listed(self):
        path = self.decide({"APP003": ("confirmed", "Seen.")})
        write(os.path.join(self.root, "api.js"), "res.send(1);\n")
        code, out, err = run([self.root, "--offline", "--lang", "en", "--review", path])
        self.assertNotIn("Fixed during the audit, no longer in this scan", out)
        self.assertIn("1 item(s) in", err)  # o aviso de sempre

    def test_the_stored_block_is_untrusted_text(self):
        doc = self.template()
        doc["findings"].append({"fingerprint": "0123456789abcdef", "status": "fixed", "comment": f"token {GH}",
                                "finding": {"rule": "XYZ999", "severity": "urgent", "where": "a.js:1\x1b[2J @octocat #12",
                                            "title": f"<img src=x onerror=alert(1)> {GH} [x](https://evil.example)"}})
        doc["findings"].append({"fingerprint": "0123456789abcdee", "status": "fixed", "finding": ["not", "a", "block"]})
        path = self.save_review(doc)
        outs = {fmt: run([self.root, "--offline", "--lang", "en", "--format", fmt, "--review", path])[1]
                for fmt in ("text", "markdown", "html", "json")}
        for fmt, out in outs.items():
            self.assertNoSecret(out, fmt)
            self.assertNotIn("\x1b", out, fmt)
        for fmt in ("markdown", "html"):
            self.assertNotIn("<img", outs[fmt], fmt)
        self.assertIn("Fixed during the audit, no longer in this scan (2):", outs["text"])
        self.assertIn(" - ⚪ ", outs["text"])  # severidade desconhecida vira info
        self.assertNotIn("[XYZ999]", outs["text"])  # regra que não existe não aparece
        self.assertIn(" - ⚪ 0123456789abcdee", outs["text"])  # sem bloco: a fingerprint no lugar do título
        for bad in ("](https://evil.example)", "@octocat", "#12"):
            self.assertNotIn(bad, outs["markdown"])
        self.assertIn("&lt;img src=x", outs["html"])
        self.assertEqual(json.loads(outs["json"])["review"]["counts"]["fixed"], 2)


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


# =========================================================================== revisão por IA

class AiCase(Case):
    def ai(self, decisions, kind="ai", reviewer=""):
        """Como decide(), com o tipo da revisão no arquivo."""
        path = self.decide(decisions, reviewer=reviewer)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["review_kind"] = kind
        return self.save_review(doc)


class AiReviewFile(AiCase):
    def test_kind_defaults_to_person(self):
        self.assertEqual(review.load(self.decide({})).kind, "person")

    def test_kind_spelling_is_forgiving(self):
        self.assertEqual(review.load(self.ai({}, kind="AI ")).kind, "ai")

    def test_unknown_kind_is_refused(self):
        code, _, err = run([self.root, "--offline", "--review", self.ai({}, kind="robot")])
        self.assertEqual(code, 2)
        self.assertIn('"review_kind"', err)
        self.assertIn("robot", err)

    def test_kind_must_be_text(self):
        for bad in (True, 1, []):
            if os.path.exists(self.path("r.json")):  # o arquivo da volta anterior é inválido: o template não o reaproveita
                os.remove(self.path("r.json"))
            code, _, err = run([self.root, "--offline", "--review", self.ai({}, kind=bad)])
            self.assertEqual(code, 2, bad)
            self.assertIn('"review_kind"', err, bad)
            self.assertNotIn("Traceback", err, bad)

    def test_ai_review_refuses_accepted_risk(self):
        code, _, err = run([self.root, "--offline", "--review", self.ai({"SEC001": ("accepted_risk", "")})])
        self.assertEqual(code, 2)
        self.assertIn("accepted_risk", err)
        self.assertIn("findings[", err)

    def test_ai_review_refuses_fixed_on_a_finding_still_there(self):
        path = self.ai({"SEC001": ("fixed", "")})
        with open(path, encoding="utf-8") as fh:
            fp = next(i["fingerprint"] for i in json.load(fh)["findings"] if i["status"] == "fixed")
        code, _, err = run([self.root, "--offline", "--review", path])
        self.assertEqual(code, 2)
        self.assertIn('"fixed"', err)
        self.assertIn(fp, err)

    def test_ai_review_allows_fixed_for_a_gone_finding(self):
        path = self.ai({"APP003": ("fixed", "Origin list set to the shop domain.")})
        write(os.path.join(self.root, "api.js"), 'res.setHeader("Access-Control-Allow-Origin", "https://shop.example");\n')
        code, out, err = run([self.root, "--offline", "--lang", "en", "--format", "html", "--review", path])
        self.assertIn(code, (0, 1), err)
        done = out.split('<section id="plan">', 1)[1].split("</section>", 1)[0].split('class="band band-done"', 1)[1]
        self.assertIn("CORS open to any website", done)
        self.assertIn(f'<span class="rv rv-fixed">{report.T["en"]["status"]["fixed"]}</span>', done)

    def test_ai_review_says_fixed_since_the_previous_report(self):
        """In an AI review nobody followed the fix: what was fixed is what a new scan no longer finds. Every format says
        "since the previous report"; a review by a person keeps "during the audit"."""
        with open(self.ai({"APP003": ("fixed", "Origin list set to the shop domain.")}), encoding="utf-8") as fh:
            doc = json.load(fh)
        write(os.path.join(self.root, "api.js"), 'res.setHeader("Access-Control-Allow-Origin", "https://shop.example");\n')
        for kind, phrase, other in (("ai", "since the previous report", "during the audit"),
                                    ("person", "during the audit", "since the previous report")):
            path = self.save_review(dict(doc, review_kind=kind))
            for fmt in ("text", "markdown", "html"):
                with self.subTest(kind=kind, format=fmt):
                    code, out, err = run([self.root, "--offline", "--lang", "en", "--format", fmt, "--review", path, "--no-color"])
                    self.assertIn(code, (0, 1), err)
                    self.assertIn(f"1 fixed {phrase}", out)
                    self.assertNotIn(other, out)
        code, out, _ = run([self.root, "--offline", "--lang", "pt", "--review", self.save_review(dict(doc, review_kind="ai")),
                            "--no-color"])
        self.assertIn("1 corrigido desde o relatório anterior", out)
        self.assertIn("Corrigidos desde o relatório anterior, já fora desta varredura (1):", out)
        self.assertNotIn("durante a auditoria", out)

    def hidden(self, *, ignore=None, line=None, pad=0):
        """Revisão por IA que marca como corrigido o CORS aberto do api.js, que continua no código mas some da
        varredura: por uma linha do .stingwardignore, por um comentário stingward:ignore ou por tamanho."""
        path = self.ai({"APP003": ("fixed", "Origin list set to the shop domain.")})
        with open(path, encoding="utf-8") as fh:
            fp = next(i["fingerprint"] for i in json.load(fh)["findings"] if i["status"] == "fixed")
        if ignore is not None:
            write(os.path.join(self.root, ".stingwardignore"), ignore)
        if line is not None or pad:
            code = line or APP["api.js"].rstrip("\n")
            write(os.path.join(self.root, "api.js"), code + "\n" + "// " + "x" * pad + "\n")
        return path, fp

    def assertRefusedAsHidden(self, path, fp, why):
        code, _, err = run([self.root, "--offline", "--review", path])
        self.assertEqual(code, 2, err)
        self.assertIn(fp, err)
        self.assertIn(why, err)
        self.assertNotIn("Traceback", err)

    def test_fixed_hidden_by_stingwardignore_is_refused(self):
        ignore = os.path.join(self.root, ".stingwardignore")
        for line in ("APP003 api.js\n", "APP003\n", "api.js\n", "* api.js\n"):
            for old in (self.path("r.json"), ignore):  # a volta anterior deixou os dois: o template sairia sem o achado
                if os.path.exists(old):
                    os.remove(old)
            path, fp = self.hidden(ignore=line)
            with self.subTest(line=line):
                self.assertRefusedAsHidden(path, fp, "stingwardignore")

    def test_fixed_hidden_by_an_inline_ignore_is_refused(self):
        path, fp = self.hidden(line=APP["api.js"].rstrip("\n") + "  // stingward:ignore")
        self.assertRefusedAsHidden(path, fp, "stingward:ignore")

    def test_fixed_in_a_file_too_big_to_read_is_refused(self):
        path, fp = self.hidden(pad=400)
        with mock.patch.object(scan, "MAX_BYTES", 300):
            self.assertRefusedAsHidden(path, fp, "too big")

    def test_fixed_when_the_scan_stopped_at_the_file_limit_is_refused(self):
        # O CORS foi corrigido de verdade, mas a varredura não leu todos os arquivos: não dá para saber se sumiu.
        path, fp = self.hidden(line='res.setHeader("Access-Control-Allow-Origin", "https://shop.example");')
        with mock.patch.object(scan, "MAX_FILES", 1):
            self.assertRefusedAsHidden(path, fp, "file limit")

    def test_ignore_lines_for_other_findings_do_not_block_fixed(self):
        path, fp = self.hidden(ignore="SEC001 src/config.py\nAPP003 other.js\n",
                               line='res.setHeader("Access-Control-Allow-Origin", "https://shop.example");')
        write(os.path.join(self.root, "src/config.py"), f'import os\nGITHUB_TOKEN = "{GH}"  # stingward:ignore\n')
        code, _, err = run([self.root, "--offline", "--review", path])
        self.assertIn(code, (0, 1), err)

    def test_person_review_may_mark_a_hidden_finding_fixed(self):
        path = self.decide({"APP003": ("fixed", "")})
        write(os.path.join(self.root, ".stingwardignore"), "APP003 api.js\n")
        code, _, err = run([self.root, "--offline", "--review", path])
        self.assertIn(code, (0, 1), err)

    def test_template_keeps_the_kind(self):
        self.ai({})
        run([self.root, "--offline", "--review-template", self.path("r.json")])
        with open(self.path("r.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["review_kind"], "ai")
        self.assertEqual(self.template()["review_kind"], "ai")  # o mesmo arquivo, gravado de novo
        os.remove(self.path("r.json"))
        self.assertEqual(self.template()["review_kind"], "person")

    def test_person_review_still_allows_every_status(self):
        path = self.decide({"SEC001": ("accepted_risk", "Client decision."), "APP003": ("fixed", "")})
        code, _, err = run([self.root, "--offline", "--review", path])
        self.assertIn(code, (0, 1), err)


class AiReviewHtml(AiCase):
    def render(self, path, *extra, lang="en", root=None):
        code, out, err = run([root or self.root, "--offline", "--format", "html", "--lang", lang, "--review", path] + list(extra))
        self.assertIn(code, (0, 1), err)
        return out

    def section(self, out, sid):
        m = re.search(rf'<section[^>]* id="{sid}">.*?</section>', out, re.S)
        return m.group(0) if m else ""

    def sections(self, out):
        return "".join(self.section(out, sid) for sid in ("cover", "summary", "scope"))

    def test_cover_scope_and_summary_say_ai(self):
        notes = self.path("notes.md")
        write(notes, "Short summary.\n")
        out = self.render(self.ai({"SEC001": ("false_positive", "Test value.")}), "--notes", notes)
        self.assertIn("<dt>Automatic review</dt>", self.section(out, "cover"))
        scope = self.section(out, "scope")
        self.assertIn("the automatic review read the code of each finding", scope)
        self.assertIn("We checked the code and configuration", scope)
        summary = self.section(out, "summary")
        self.assertIn("After the automatic review", summary)
        self.assertIn('<h3 class="analyst-h">Summary</h3>', summary)
        for human in ("by hand", "checked by a person", "Human review", "Analyst summary", "AI review", "an AI", "AI model"):
            self.assertNotIn(human, self.sections(out), human)

    def test_portuguese(self):
        notes = self.path("notes.md")
        write(notes, "Resumo curto.\n")
        out = self.render(self.ai({"SEC001": ("false_positive", "Valor de teste.")}), "--notes", notes, lang="pt")
        for want in ("Revisão automática", '<h3 class="analyst-h">Resumo</h3>', "a revisão automática leu o código de cada achado",
                     "Conferimos o código e a configuração"):
            self.assertIn(want, out)
        for human in ("à mão", "conferida por uma pessoa", "Revisão humana", "Parecer do analista", "por IA", "uma IA", "modelo de IA"):
            self.assertNotIn(human, self.sections(out), human)

    def test_clean_project_with_an_ai_review(self):
        root = tree({"README.md": "# Hello\n"})
        self.addCleanup(shutil.rmtree, root, True)
        path = self.save_review({"stingward_review": 1, "review_kind": "ai", "findings": []})
        code, out, err = run([root, "--offline", "--format", "html", "--lang", "en", "--review", path])
        self.assertEqual(code, 0, err)
        self.assertIn("<dt>Automatic review</dt>", self.section(out, "cover"))
        self.assertNotIn("checked by a person", self.section(out, "scope"))

    def test_privacy_says_what_went_to_the_ai(self):
        scope = self.section(self.render(self.ai({})), "scope")
        self.assertIn("For the automatic review, the code excerpt of each finding, with secrets masked, was sent to the review service.", scope)
        self.assertNotIn("The code did not.", scope)
        scope = self.section(self.render(self.ai({}), lang="pt"), "scope")
        self.assertIn("Para a revisão automática, o trecho de cada achado, com os segredos mascarados, foi enviado ao serviço de revisão.", scope)
        self.assertNotIn("O código não saiu.", scope)

    def test_person_review_keeps_its_words(self):
        out = self.render(self.decide({"SEC001": ("false_positive", "Test value.")}))
        self.assertIn("Human review", out)
        self.assertIn("checked the findings by hand", out)
        self.assertIn("The code did not.", self.section(out, "scope"))


class AiReviewOtherFormats(AiCase):
    def notes(self, text="First.\n"):
        path = self.path("notes.md")
        write(path, text)
        return path

    def test_text_says_reviewed_by_ai(self):
        code, out, _ = run([self.root, "--offline", "--no-color", "--review", self.ai({}), "--notes", self.notes()])
        self.assertIn("Reviewed automatically: ", out)
        self.assertIn("Summary:\n  First.\n", out)
        self.assertNotIn("Reviewed by a person", out)
        self.assertNotIn("Analyst summary", out)

    def test_markdown_says_ai(self):
        code, out, _ = run([self.root, "--offline", "--format", "markdown", "--review", self.ai({}), "--notes", self.notes()])
        self.assertIn("**Reviewed automatically:**", out)
        self.assertIn("**Summary**", out)
        self.assertNotIn("Analyst summary", out)

    def test_portuguese_text(self):
        code, out, _ = run([self.root, "--offline", "--no-color", "--lang", "pt", "--review", self.ai({}), "--notes", self.notes()])
        self.assertIn("Revisado automaticamente: ", out)
        self.assertIn("Resumo:\n  First.\n", out)
        self.assertNotIn("Parecer do analista", out)

    def test_json_kind_and_masked(self):
        code, out, _ = run([self.root, "--offline", "--format", "json", "--review", self.ai({"SEC001": ("confirmed", "Seen.")})])
        doc = json.loads(out)
        self.assertEqual(doc["review"]["kind"], "ai")
        self.assertIs(doc["review"]["masked"], False)

    def test_json_masked_when_a_comment_or_the_notes_carry_a_secret(self):
        for comment, notes in ((f"token {GH}", "Fine.\n"), ("Seen.", f"The key {OAI} leaked.\n")):
            path = self.ai({"SEC001": ("confirmed", comment)})
            code, out, _ = run([self.root, "--offline", "--format", "json", "--review", path, "--notes", self.notes(notes)])
            self.assertIs(json.loads(out)["review"]["masked"], True, comment)
            self.assertNoSecret(out, "json")

    def test_json_masked_whatever_format_masks_it(self):
        # Chave e valor em linhas diferentes: o JSON guarda o comentário linha a linha, o HTML junta o parágrafo e
        # mascara. O aviso vale para o arquivo de revisão inteiro, qualquer que seja o formato e a ordem em que saem.
        path = self.ai({"SEC001": ("confirmed", "password\n= " + "Hunter2" + "Hunter2Xy")})
        code, out, err = run([self.root, "--offline", "--format", "json", "--html", self.path("out.html"), "--review", path])
        self.assertIs(json.loads(out)["review"]["masked"], True)
        self.assertIn("masked something", err)

    def test_json_masked_counts_the_comment_of_a_fixed_finding(self):
        # O item corrigido não entra no JSON, mas o texto e o Markdown mostram o comentário dele, mascarado.
        path = self.ai({"APP003": ("fixed", f"Was {GH} before.")})
        write(os.path.join(self.root, "api.js"), 'res.setHeader("Access-Control-Allow-Origin", "https://shop.example");\n')
        code, out, err = run([self.root, "--offline", "--format", "json", "--review", path])
        self.assertIs(json.loads(out)["review"]["masked"], True)
        self.assertIn("masked something", err)
        self.assertNoSecret(out + err, "json")

    def test_json_person_kind(self):
        code, out, _ = run([self.root, "--offline", "--format", "json", "--review", self.decide({})])
        self.assertEqual(json.loads(out)["review"]["kind"], "person")


if __name__ == "__main__":
    unittest.main()
