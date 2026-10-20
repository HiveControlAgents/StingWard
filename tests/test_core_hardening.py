"""Revisão do núcleo: download de skill, leitura de arquivos, bases de vulnerabilidade, CLI e o mascaramento."""
import contextlib
import io
import os
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from stingward import _redact as redact, cli

LANG_VARS = ("STINGWARD_LANG", "LC_ALL", "LC_MESSAGES", "LANG")


def run_main(argv, env=None):
    """cli.main em processo, sem rede e sem clone: (código de saída, stdout, stderr)."""
    values = dict.fromkeys(LANG_VARS)
    values.update(env or {})
    out, err = io.StringIO(), io.StringIO()
    saved = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        with mock.patch("stingward.vulndb.fetch_json", side_effect=AssertionError("network access in a test")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as e:
                code = e.code
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return code, out.getvalue(), err.getvalue()


class MaskerOnHostileInput(unittest.TestCase):
    """O mascaramento roda em valores que vêm da skill auditada (config de MCP): não pode ficar quadrático."""

    def test_long_values_are_masked_in_linear_time(self):
        n = 40_000
        samples = {
            "word": "ab1" * (n // 3),
            "dotted": "a." * (n // 2),
            "slashes": "a/" * (n // 2),
            "colons": "a:" * (n // 2),
            "percent": "%41" * (n // 3) + "x" * n,
            "urls": "http://a" * (n // 8),
            "windows": "C:\\a\\" * (n // 5),
            "hyphens": "a.b-" * (n // 4),
        }
        for name, s in samples.items():
            with self.subTest(sample=name):
                t = time.perf_counter()
                redact.sanitize_text(s)
                self.assertLess(time.perf_counter() - t, 1.5, name)


class ErrorsFollowTheLanguage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.missing = os.path.join(self.tmp.name, "nope")

    def test_english(self):
        cases = [
            ([self.missing, "--offline"], "folder not found"),
            (["skill", self.missing, "--offline"], "folder not found"),
            (["--offline", "frobnicate", self.tmp.name], "unknown command: frobnicate"),
            ([self.tmp.name, "--only", "nope"], "--only takes deps,secrets,app,code,agents"),
        ]
        for argv, want in cases:
            for env in ({}, {"LANG": "pt_BR.UTF-8"}):
                with self.subTest(argv=argv, env=env):
                    code, out, err = run_main(argv + ["--lang", "en"], env=env)
                    self.assertEqual((code, out), (2, ""))
                    self.assertIn(want, err)
                    self.assertNotIn("não", err)

    def test_portuguese(self):
        cases = [
            ([self.missing, "--offline"], "pasta não encontrada"),
            (["--offline", "frobnicate", self.tmp.name], "comando desconhecido: frobnicate"),
            ([self.tmp.name, "--only", "nope"], "--only aceita deps,secrets,app,code,agents"),
        ]
        for argv, want in cases:
            with self.subTest(argv=argv):
                code, _, err = run_main(argv, env={"STINGWARD_LANG": "pt"})
                self.assertEqual(code, 2)
                self.assertIn(want, err)



class SkillDownload(unittest.TestCase):
    """`stingward skill <url>`: falha no download é erro (código 2), em qualquer idioma, sem deixar pasta temporária."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(tempfile, "tempdir", self.tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _main(self, side_effect, lang="en"):
        with mock.patch("subprocess.run", side_effect=side_effect):
            code, out, err = run_main(["skill", "https://github.com/acme/skill", "--offline", "--lang", lang])
        self.assertEqual(os.listdir(self.tmp.name), [], "temporary clone left behind")
        return code, out, err

    def test_git_error(self):
        code, out, err = self._main([subprocess.CompletedProcess([], 128, "", "fatal: repository not found")])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("could not download https://github.com/acme/skill: fatal: repository not found", err)
        code, _, err = self._main([subprocess.CompletedProcess([], 128, "", "fatal: x")], lang="pt")
        self.assertEqual(code, 2)
        self.assertIn("não consegui baixar https://github.com/acme/skill", err)

    def test_clone_that_takes_too_long(self):
        code, out, err = self._main(subprocess.TimeoutExpired(["git"], 180))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("could not download", err)
        self.assertIn("180", err)

    def test_git_not_installed(self):
        code, out, err = self._main(FileNotFoundError(2, "No such file or directory", "git"))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("could not download", err)
        self.assertIn("git", err)

    def test_interrupted_clone_is_cleaned_up(self):
        with mock.patch("subprocess.run", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                cli._fetch("https://github.com/acme/skill")
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_git_output_that_is_not_utf8_is_not_fatal(self):
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as run:
            try:
                cli._fetch("https://github.com/acme/skill")
            except cli.FetchError:
                pass
        kw = run.call_args[1]
        self.assertEqual((kw.get("encoding"), kw.get("errors")), ("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
