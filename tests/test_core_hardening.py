"""Revisão do núcleo: download de skill, leitura de arquivos, bases de vulnerabilidade, CLI e o mascaramento."""
import os
import time
import unittest

from stingward import _redact as redact


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


if __name__ == "__main__":
    unittest.main()
