"""Caminhos menos comuns: cache e novas tentativas na rede, download de skills, relatórios e o motor de segredos."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest import mock

from stingward import _redact as redact, cli, gitsafe, net, report, scan, vulndb
from stingward.checks import deps
from stingward.model import Context, Finding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resp(payload):
    r = mock.MagicMock()
    r.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return r


class NetCacheAndRetries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"STINGWARD_CACHE": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_second_call_is_served_from_the_cache(self):
        with mock.patch("urllib.request.urlopen", return_value=_resp({"n": 1})) as op:
            self.assertEqual(net.fetch_json("https://example.com/a", ttl=60), {"n": 1})
            self.assertEqual(net.fetch_json("https://example.com/a", ttl=60), {"n": 1})
        self.assertEqual(op.call_count, 1)
        self.assertEqual(len(os.listdir(self.tmp.name)), 1)

    def test_entry_dated_a_moment_ahead_is_still_served(self):
        # Windows, Python 3.12: time.time() and st_mtime come from the same 100 ns clock tick through different float
        # sums, and st_mtime can come out a fraction later. The entry just written then looked like it came from the
        # future and was fetched again: test_second_call_is_served_from_the_cache saw 2 calls once. A network drive's
        # clock can also be a little ahead. Far ahead (another machine, a wrong clock) still does not count.
        with mock.patch("urllib.request.urlopen", return_value=_resp({"n": 1})):
            net.fetch_json("https://example.com/a", ttl=3600)
        (name,) = os.listdir(self.tmp.name)
        mtime = os.stat(os.path.join(self.tmp.name, name)).st_mtime
        for ahead, calls in ((1e-6, 0), (1.0, 0), (30.0, 0), (600.0, 1)):
            with self.subTest(ahead=ahead):
                with mock.patch("time.time", return_value=mtime - ahead), \
                        mock.patch("urllib.request.urlopen", return_value=_resp({"n": 1})) as op:
                    self.assertEqual(net.fetch_json("https://example.com/a", ttl=3600), {"n": 1})
                self.assertEqual(op.call_count, calls)
                os.utime(os.path.join(self.tmp.name, name), (mtime, mtime))  # the refetch wrote the entry again

    def test_body_is_part_of_the_cache_key(self):
        with mock.patch("urllib.request.urlopen", side_effect=[_resp({"n": 1}), _resp({"n": 2})]) as op:
            net.fetch_json("https://example.com/a", body={"q": 1}, ttl=60)
            self.assertEqual(net.fetch_json("https://example.com/a", body={"q": 2}, ttl=60), {"n": 2})
        self.assertEqual(op.call_count, 2)
        req = op.call_args[0][0]
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(req.data), {"q": 2})

    def test_expired_or_corrupt_cache_is_refetched(self):
        with mock.patch("urllib.request.urlopen", return_value=_resp({"n": 1})):
            net.fetch_json("https://example.com/a", ttl=60)
        (name,) = os.listdir(self.tmp.name)
        with open(os.path.join(self.tmp.name, name), "w") as fh:
            fh.write("{broken")
        with mock.patch("urllib.request.urlopen", return_value=_resp({"n": 3})) as op:
            self.assertEqual(net.fetch_json("https://example.com/a", ttl=60), {"n": 3})
        self.assertEqual(op.call_count, 1)

    def test_client_error_is_not_retried(self):
        err = urllib.error.HTTPError("https://example.com/a", 404, "nope", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err) as op, mock.patch("time.sleep") as sl:
            with self.assertRaisesRegex(net.NetError, "HTTP 404"):
                net.fetch_json("https://example.com/a")
        self.assertEqual((op.call_count, sl.call_count), (1, 0))

    def test_rate_limit_is_retried_then_succeeds(self):
        err = urllib.error.HTTPError("https://example.com/a", 429, "slow down", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=[err, err, _resp({"ok": True})]) as op, \
                mock.patch("time.sleep") as sl:
            self.assertEqual(net.fetch_json("https://example.com/a"), {"ok": True})
        self.assertEqual((op.call_count, sl.call_count), (3, 2))

    def test_three_server_errors_give_up(self):
        err = urllib.error.HTTPError("https://example.com/a", 503, "down", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err) as op, mock.patch("time.sleep"):
            with self.assertRaises(net.NetError):
                net.fetch_json("https://example.com/a")
        self.assertEqual(op.call_count, 3)

    def test_headers_are_sent(self):
        with mock.patch("urllib.request.urlopen", return_value=_resp({})) as op:
            net.fetch_json("https://example.com/a", headers={"apiKey": "k"})
        req = op.call_args[0][0]
        self.assertEqual(req.get_header("Apikey"), "k")
        self.assertIn("stingward", req.get_header("User-agent"))


class RemoteSkills(unittest.TestCase):
    def test_what_counts_as_remote(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(cli._is_remote("https://github.com/a/b"))
            self.assertTrue(cli._is_remote("git@github.com:a/b.git"))
            self.assertTrue(cli._is_remote("owner/repo"))
            self.assertFalse(cli._is_remote(d))
            self.assertFalse(cli._is_remote("./missing-folder"))
            self.assertFalse(cli._is_remote("-x/repo"))

    def _fetch(self, target, returncode=0):
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode, "", "fatal: nope")) as run:
            try:
                tmp, path = cli._fetch(target)
            except cli.FetchError as e:
                return run.call_args[0][0], e
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        return run.call_args[0][0], path

    def test_owner_repo_becomes_a_github_url(self):
        cmd, path = self._fetch("owner/repo")
        self.assertEqual(cmd[-2:-1], ["https://github.com/owner/repo.git"])
        self.assertEqual(cmd[cmd.index("--") - 1], "--quiet")
        self.assertTrue(path.endswith(os.path.join("repo", "")))

    def test_tree_url_picks_branch_and_subfolder(self):
        cmd, path = self._fetch("https://github.com/owner/repo/tree/dev/skills/x")
        self.assertIn("--branch", cmd)
        self.assertEqual(cmd[cmd.index("--branch") + 1], "dev")
        self.assertEqual(cmd[cmd.index("--") + 1], "https://github.com/owner/repo.git")
        self.assertTrue(path.endswith(os.path.join("repo", "skills/x")))

    def test_url_is_passed_after_double_dash(self):
        cmd, _ = self._fetch("https://github.com/owner/repo.git")
        self.assertEqual(cmd[cmd.index("--") + 1], "https://github.com/owner/repo.git")

    def test_failed_clone_is_a_clear_error(self):
        _, err = self._fetch("owner/repo", returncode=128)
        self.assertIsInstance(err, cli.FetchError)
        self.assertEqual((err.key, err.detail), ("git", "fatal: nope"))


class Reports(unittest.TestCase):
    def ctx(self, **sources):
        c = Context(root="/x", files=[], offline=False)
        c.sources.update(sources)
        return c

    def test_sources_line(self):
        self.assertEqual(report._sources_line(self.ctx(packages=3, osv=True, kev="2026.10.16", epss=True, nvd=True), "en"),
                         "3 package(s) checked · OSV.dev · CISA KEV 2026.10.16 · EPSS (FIRST) · NVD")
        self.assertIn("CISA KEV", report._sources_line(self.ctx(kev=True), "en"))
        self.assertNotEqual(report._sources_line(self.ctx(osv_error="down"), "en"), report._sources_line(self.ctx(), "en"))

    def test_many_low_findings_are_folded(self):
        # títulos diferentes: cada um é um item; o mesmo título em vários arquivos vira um item só (teste abaixo)
        findings = [Finding("SKL003", "low", f"f{i}.md", 1, {"snippet": f"phrase {i}"}) for i in range(20)]
        out = report.text(self.ctx(), findings, "en", max_low=5)
        self.assertIn("f4.md", out)
        self.assertNotIn("f5.md", out)
        self.assertIn("and 15 more low-severity item(s)", out)

    def test_same_problem_in_many_places_is_one_item(self):
        findings = [Finding("SKL003", "low", f"f{i}.md", 1, {"snippet": "x"}) for i in range(20)]
        out = report.text(self.ctx(), findings, "en", max_low=5)
        self.assertEqual(out.count("Instruction that tries to override the user"), 1)
        self.assertIn("where: f0.md:1, f1.md:1", out)
        self.assertIn("f9.md:1 and 10 more", out)
        self.assertNotIn("more low-severity", out)
        self.assertIn("Summary: 20 low", out)  # a contagem e a nota continuam por achado

    def test_color_and_reference_link(self):
        f = Finding("SEC001", "critical", "a.js", 1, {"kind_en": "key", "kind_pt": "chave"}, refs=["https://osv.dev/x"])
        out = report.text(self.ctx(), [f], "en", color=True)
        self.assertIn("\033[1;31m", out)
        self.assertIn("\033[0m", out)
        self.assertIn("https://osv.dev/x", out)
        self.assertNotIn("\033", report.text(self.ctx(), [f], "en", color=False))

    def test_counts_agree_in_number(self):
        f = [Finding("SEC001", s, "a", 1) for s in ("critical", "critical", "high", "medium", "medium", "low", "info", "info")]
        self.assertEqual(report.counts_line(f, "pt"), "2 críticos, 1 alto, 2 médios, 1 baixo, 2 info")
        self.assertEqual(report.counts_line(f, "en"), "2 critical, 1 high, 2 medium, 1 low, 2 info")

    def test_every_format_has_the_grade(self):
        f = Finding("SEC001", "high", "a.js", 1, {"kind_en": "key", "kind_pt": "chave"})
        self.assertIn("Grade: C", report.text(self.ctx(), [f], "en"))
        self.assertIn("stingward-C", report.markdown(self.ctx(), [f], "en"))
        self.assertEqual(json.loads(report.as_json(self.ctx(), [f], "en"))["grade"], "C")


class DepsDegradeGracefully(unittest.TestCase):
    def check(self, docs, kev=None, kev_error=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "package-lock.json"), "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"": {}, "node_modules/left": {"version": "1.0.0"}}}, fh)
        ctx = Context(tmp.name, ["package-lock.json"])
        kev_mock = mock.patch.object(vulndb, "kev", side_effect=net.NetError("kev down")) if kev_error else \
            mock.patch.object(vulndb, "kev", return_value=(kev or {}, "2026.10.16"))
        with mock.patch.object(vulndb, "osv_query", return_value=[sorted(docs)]), \
                mock.patch.object(vulndb, "osv_vulns", side_effect=lambda want: {i: docs[i] for i in want}), \
                kev_mock, mock.patch.object(vulndb, "epss", return_value={}), \
                mock.patch.object(vulndb, "nvd_severity", return_value=None):
            return ctx, deps.check(ctx)

    @staticmethod
    def vuln(vid, fixed=None, sev="HIGH"):
        events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
        return {"id": vid, "aliases": [vid.replace("GHSA", "CVE")], "summary": "bad", "database_specific": {"severity": sev},
                "affected": [{"package": {"ecosystem": "npm", "name": "left"}, "ranges": [{"type": "SEMVER", "events": events}]}]}

    def test_kev_outage_still_reports_the_vulnerability(self):
        docs = {"GHSA-1": self.vuln("GHSA-1", "1.2.0")}
        ctx, got = self.check(docs, kev_error=True)
        self.assertEqual([f.rule for f in got], ["DEP001"])
        self.assertIn("kev down", ctx.sources["kev_error"])

    def test_partly_unfixed_package_says_so(self):
        docs = {"GHSA-1": self.vuln("GHSA-1", "1.2.0"), "GHSA-2": self.vuln("GHSA-2")}
        _, got = self.check(docs)
        self.assertEqual(got[0].params["fixed"], "1.2.0")
        self.assertIn("1 issue(s) still unfixed", got[0].params["fix_en"])

    def test_no_fix_at_all(self):
        _, got = self.check({"GHSA-2": self.vuln("GHSA-2")})
        self.assertEqual(got[0].params["fixed"], "")
        self.assertIn("No fixed version yet", got[0].params["fix_en"])

    def check_ids(self, ids, docs, files=None):
        """OSV lists ids for the package, but only the details in docs could be downloaded."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        files = files or {"package-lock.json": {"lockfileVersion": 3, "packages": {"": {}, "node_modules/left": {"version": "1.0.0"}}}}
        for rel, content in files.items():
            with open(os.path.join(tmp.name, rel), "w") as fh:
                json.dump(content, fh)
        self.ctx = ctx = Context(tmp.name, sorted(files))
        with self.osv(ids, docs):
            return deps.check(ctx)

    @staticmethod
    def osv(ids, docs):
        stack = ExitStack()
        for name, kw in (("osv_query", {"return_value": [list(ids)]}),
                         ("osv_vulns", {"side_effect": lambda want: {i: docs[i] for i in want if i in docs}}),
                         ("kev", {"return_value": ({}, "")}), ("epss", {"return_value": {}}), ("nvd_severity", {"return_value": None})):
            stack.enter_context(mock.patch.object(vulndb, name, **kw))
        return stack

    def test_missing_details_mark_the_check_incomplete(self):
        self.check_ids(["GHSA-1", "GHSA-gone", "MAL-2025-1"], {"GHSA-1": self.vuln("GHSA-1", "1.2.0")})
        self.assertIn("2 vulnerability detail(s)", self.ctx.sources["osv_error"])
        self.assertIn("GHSA-gone, MAL-2025-1", self.ctx.sources["osv_error"])
        self.check_ids(["GHSA-1"], {"GHSA-1": self.vuln("GHSA-1", "1.2.0")})
        self.assertNotIn("osv_error", self.ctx.sources)

    def test_missing_details_fail_the_ci_gate_and_still_list_the_package(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "package-lock.json"), "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"": {}, "node_modules/left": {"version": "1.0.0"}}}, fh)
        out, err = io.StringIO(), io.StringIO()
        with self.osv(["GHSA-gone"], {}), redirect_stdout(out), redirect_stderr(err):
            code = cli.main([tmp.name, "--format", "json", "--lang", "en"])
        self.assertEqual(code, 3)
        self.assertEqual([f["rule"] for f in json.loads(out.getvalue())["findings"]], ["DEP001"])

    def test_advisory_whose_details_did_not_download_is_still_reported(self):
        got = self.check_ids(["GHSA-gone"], {})
        self.assertEqual([(f.rule, f.severity) for f in got], [("DEP001", "medium")])
        p = got[0].params
        self.assertEqual(p["headline_en"], "GHSA-gone")
        self.assertNotIn("No fixed version yet", p["fix_en"])
        self.assertIn("did not send the details of GHSA-gone", p["fix_en"])
        self.assertIn("não mandou os detalhes de GHSA-gone", p["fix_pt"])

    def test_missing_details_do_not_count_as_unfixed(self):
        got = self.check_ids(["GHSA-1", "GHSA-gone"], {"GHSA-1": self.vuln("GHSA-1", "1.2.0")})
        p = got[0].params
        self.assertEqual((got[0].severity, p["fixed"]), ("high", "1.2.0"))
        self.assertNotIn("still unfixed", p["fix_en"])
        self.assertIn("did not send the details of GHSA-gone", p["fix_en"])

    def test_malicious_record_whose_details_did_not_download_is_still_reported(self):
        got = self.check_ids(["MAL-2025-1"], {})
        self.assertEqual([(f.rule, f.severity, f.params["vuln_id"]) for f in got], [("DEP002", "critical", "MAL-2025-1")])

    def test_alias_of_a_downloaded_advisory_is_not_reported_twice(self):
        got = self.check_ids(["GHSA-1", "CVE-1"], {"GHSA-1": self.vuln("GHSA-1", "1.2.0")})
        self.assertEqual(len(got[0].params["vulns"]), 1)

    def test_range_floor_with_missing_details(self):
        got = self.check_ids(["GHSA-gone"], {}, {"package.json": {"dependencies": {"left": "^1.0.0"}}})
        self.assertEqual(sorted((f.rule, f.severity) for f in got), [("DEP003", "low"), ("DEP004", "low")])


class ListingLimits(unittest.TestCase):
    def test_max_files_stops_early(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(30):
                with open(os.path.join(d, f"f{i}.py"), "w") as fh:
                    fh.write("x = 1\n")
            self.assertEqual(len(scan.list_files(d, max_files=10)), 10)

    def test_git_that_cannot_start_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, ".git"))
            with mock.patch("subprocess.run", side_effect=OSError("no git")):
                self.assertIsNone(gitsafe.run(d, "ls-files"))
                self.assertIsNone(scan.git_tracked(d))


class SecretEngine(unittest.TestCase):
    """O motor que mascara segredos no relatório: tudo que sai dele não pode conter o valor original."""

    TOKEN = "ghp_" + "Zq8vN3kL0pR7tY2wX5mB9cD4eF6gH1jK2lM3"

    def test_masks_common_shapes(self):
        samples = [
            f'{{"api_key": "{self.TOKEN}"}}',
            f'{{\\"password\\": \\"{self.TOKEN}\\"}}',
            f"Authorization: Bearer {self.TOKEN}",
            f"export GITHUB_TOKEN={self.TOKEN}",
            f"postgres://admin:{self.TOKEN}@db.example.com/app",
            f"GET /api/reset/{self.TOKEN}?x=1",
            f"https://example.com/cb?token={self.TOKEN}&ok=1",
            f"url=https%3A%2F%2Fexample.com%2F%3Ftoken%3D{self.TOKEN}",
        ]
        for s in samples:
            with self.subTest(sample=s[:30]):
                out = redact.sanitize_text(s)
                self.assertNotIn(self.TOKEN[4:20], out)
                self.assertIn("[REDACTED:", out)

    def test_idempotent_and_keeps_stack_frames(self):
        s = f'File "/app/main.py", line 12, in handler\n  token = "{self.TOKEN}"'
        once = redact.sanitize_text(s)
        self.assertEqual(redact.sanitize_text(once), once)
        self.assertIn('File "/app/main.py", line 12', once)

    def test_find_and_contains(self):
        self.assertTrue(redact.contains_secret(f"key={self.TOKEN}"))
        self.assertIn("github_token", redact.find_secrets(f"key={self.TOKEN}"))
        self.assertFalse(redact.contains_secret("hello world"))

    def test_objects_are_walked(self):
        obj = {"user": "ana", "auth": {"token": self.TOKEN}, "items": [f"Bearer {self.TOKEN}", 3, None],
               "path": f"/v1/files/{self.TOKEN}"}
        out = json.dumps(redact.sanitize_obj(obj))
        self.assertNotIn(self.TOKEN[4:20], out)
        self.assertIn('"user": "ana"', out)

    def test_never_raises_on_odd_input(self):
        for x in (None, 3, b"bytes", ["a", {"b": object()}], "x" * 10_000, "%" * 50, "a=" * 500):
            redact.sanitize_text(x) if not isinstance(x, (list, dict)) else redact.sanitize_obj(x)

    def test_truncate(self):
        self.assertEqual(redact.truncate("abc", 10), "abc")
        self.assertEqual(redact.truncate("a" * 50, 20), "a" * 20 + "…[truncado]")
        # Sanitiza antes de cortar e nunca deixa meio marcador: o pedaço do segredo não sobra.
        out = redact.truncate(f"token={self.TOKEN} and more text", 12)
        self.assertNotIn(self.TOKEN[4:12], out)
        self.assertNotIn("[REDACTED:" + "…", out)


class ModuleEntryPoint(unittest.TestCase):
    def test_python_dash_m(self):
        r = subprocess.run([sys.executable, "-m", "stingward", "--version"], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"^stingward \d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
