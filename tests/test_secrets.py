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

    def test_masking_command_line_flags_is_linear(self):
        # mask() runs on code excerpts; "-keykeykey..." made the flag pattern backtrack quadratically (5 s for 18 KB).
        self.assertFast(secrets._mask_flags, "-" + "key" * 6000)
        self.assertFast(secrets._mask_flags, "--token " + "-key" * 6000)
        self.assertFast(secrets._mask_flags, "a-" * 10000)

    def test_many_generic_findings_in_one_file_are_linear(self):
        # Each assignment looked through every finding of the file so far to skip a second one on the same line.
        text = "\n".join(f'  token_{i}: "Ab3{i:06d}xYz9Qw"' for i in range(15000))
        found = self.assertFast(secrets.scan_text, text, "src/gen.ts", limit=3.0)
        self.assertEqual(len(found), len({f.line for f in found}))
        self.assertGreater(len(found), 14000)
        both = 'API_TOKEN = "' + "ghp_" + R36 + '"; secret_key = "Q8w3E5r7T9y1"\n'
        self.assertEqual([f.params["kind_en"] for f in secrets.scan_text(both, "src/a.py")], ["GitHub token"])

    def test_command_line_flags_are_still_masked(self):
        pw = "Tr0ub4dor" + "77xK"
        cases = [
            (f"run --api-key {pw} --verbose", "run --api-key [REDACTED] --verbose"),
            (f"run --token={pw}", "run --token=[REDACTED]"),
            (f"run -p --db-password '{pw}'", "run -p --db-password '[REDACTED]'"),
            (f'x --name demo --auth-token="{pw}"', 'x --name demo --auth-token="[REDACTED]"'),
            (f"cli --Client-Secret {pw}", "cli --Client-Secret [REDACTED]"),
            ("run --token short --port 8080", "run --token short --port 8080"),
            (f"run --name {pw}", f"run --name {pw}"),
        ]
        for raw, want in cases:
            with self.subTest(raw=raw):
                self.assertEqual(secrets.mask(raw), want)
        self.assertNotIn(pw, secrets.mask(f"foo-token={pw}"))


# =========================================================================== senha em URL

class UrlPasswords(Case):
    def test_urls_built_by_code_are_not_hard_coded_passwords(self):
        lines = [
            'DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASSWORD}@{settings.DB_HOST}:5432/app"',
            'url = "postgresql://{}:{}@{}/{}".format(user, pw, host, db)',
            'url = "postgresql://{0}:{1}@{2}/app".format(user, pw, host)',
            'url = "mysql://%s:%s@%s/%s" % (user, pw, host, db)',
            'url = "mysql://%(user)s:%(password)s@%(host)s/db" % cfg',
            'dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", u, p, h, port, db)',
            'url = "postgres://#{user}:#{password}@#{host}/db"',
            'let url = "postgres://\\(user):\\(password)@\\(host)/db"',
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/db.py": line + "\n"}), "SEC001"), [])

    def test_translated_placeholders_are_not_passwords(self):
        lines = [
            '"Enter proxy URL (e.g. https://user:password@host:port)": "Proksi URL (m\u0259s. https://istifad\u0259\u00e7i:\u015fifr\u0259@host:port)",',
            '"proxy": "Zadejte URL proxy (nap\u0159. https://uzivatel:heslo@hostitel:port)",',
            '"proxy": "Kirjoita osoite (esim. https://k\u00e4ytt\u00e4j\u00e4:salasana@host:portti)",',
            '"proxy": "URL del proxy (p. ej. https://usuario:contrase\u00f1a@servidor/db)",',
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/i18n/locale.json": line + "\n"}), "SEC001"), [])

    def test_real_passwords_in_urls_still_fire(self):
        pw = "Tr0ub4dor" + "77xK"
        lines = [f"DATABASE_URL = 'postgres://app:{pw}@db.prod.acme-corp.net:5432/app'",
                 f'MONGO = "mongodb+srv://admin:{pw}@cluster0.abcde.mongodb.net/?retryWrites=true"',
                 f'REDIS = "redis://:{pw}@cache.acme-corp.net:6379/0"',
                 f'url = f"postgresql://app:{pw}@{{host}}/app"', f'url = f"postgresql://app:{pw}@{{DB_HOST}}:{{DB_PORT}}/app"']
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/db.py": line + "\n"}), "SEC001"), [("SEC001", "src/db.py", 1, "high")])


if __name__ == "__main__":
    unittest.main()
