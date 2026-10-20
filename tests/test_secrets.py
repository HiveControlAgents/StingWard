"""Testes do secrets.py: formatos, falsos positivos, mascaramento e entrada hostil.

Segredos falsos são montados por concatenação, para o repositório continuar limpo na própria auditoria.
"""
import os
import tempfile
import time
import unittest
from unittest import mock

from stingward import scan
from stingward.checks import secrets

R36 = "aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uVwX2y"          # 36 caracteres aleatórios

_DIRS = []


def tearDownModule():
    for d in _DIRS:
        d.cleanup()


def scan_files(files, mode="project", tracked=None):
    d = tempfile.TemporaryDirectory()
    _DIRS.append(d)
    for rel, content in files.items():
        p = os.path.join(d.name, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    if tracked is None:
        return scan.run(d.name, mode=mode, offline=True)[1]
    with mock.patch.object(scan, "git_tracked", return_value=set(tracked)):
        return scan.run(d.name, mode=mode, offline=True)[1]


def brief(findings, *rules):
    return sorted((f.rule, f.file, f.line, f.severity) for f in findings if not rules or f.rule in rules)


class Case(unittest.TestCase):
    def assertFast(self, fn, *args, limit=1.0):
        start = time.perf_counter()
        out = fn(*args)
        self.assertLess(time.perf_counter() - start, limit)
        return out


# =========================================================================== entrada hostil

class HostileInput(Case):
    def test_env_line_with_a_long_run_of_spaces_is_linear(self):
        # (?P<val>.*?)\s*$ retried the trailing spaces at every character of the value: quadratic.
        text = "A=x" + " " * 60000 + "y\n"
        self.assertFalse(self.assertFast(secrets._env_has_secret, text))
        files = {".env": "API_SECRET=" + R36 + " " * 3 + "\n"}
        self.assertEqual(brief(scan_files(files, tracked=files), "SEC002"), [("SEC002", ".env", None, "high")])


if __name__ == "__main__":
    unittest.main()
