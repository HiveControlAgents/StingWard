"""Testes do secrets.py: formatos, falsos positivos, mascaramento e entrada hostil.

Segredos falsos são montados por concatenação, para o repositório continuar limpo na própria auditoria.
"""
import base64
import hashlib
import hmac
import json
import os
import re
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
        # The old pattern was cubic here: 36 s for "-key-" over 4 KB, 7 s for "-a" over 20 KB.
        self.assertFast(secrets._mask_flags, "-key-" * 820)
        self.assertFast(secrets._mask_flags, "-a" * 10000)
        self.assertEqual(secrets._mask_flags("-key-" * 820 + " Tr0ub4dor77xK").count("[REDACTED]"), 1)

    def test_many_generic_findings_in_one_file_are_linear(self):
        # Each assignment looked through every finding of the file so far to skip a second one on the same line.
        text = "\n".join(f'  token_{i}: "Ab3{i:06d}xYz9Qw"' for i in range(15000))
        found = self.assertFast(secrets.scan_text, text, "src/gen.ts", limit=3.0)
        self.assertEqual(len(found), len({f.line for f in found}))
        self.assertGreater(len(found), 14000)
        both = 'API_TOKEN = "' + "ghp_" + R36 + '"; secret_key = "' + "Q8w3E5r7" + 'T9y1"\n'
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
            'let url = "postgres://\\(user):' + '\\(password)@\\(host)/db"',
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/db.py": line + "\n"}), "SEC001"), [])

    def test_translated_placeholders_are_not_passwords(self):
        lines = [
            '"Enter proxy URL (e.g. https://user:password@host:port)": "Proksi URL (m\u0259s. https://istifad\u0259\u00e7i:\u015fifr\u0259@host:port)",',
            '"proxy": "Zadejte URL proxy (nap\u0159. https://uzivatel:heslo@hostitel:port)",',
            '"proxy": "Kirjoita osoite (esim. https://k\u00e4ytt\u00e4j\u00e4:salasana@host:portti)",',
            '"proxy": "URL del proxy (p. ej. https://usuario:' + 'contrase\u00f1a@servidor/db)",',
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


# =========================================================================== chave privada

BEGIN = "-----BEGIN " + "PRIVATE KEY-----"
END = "-----END " + "PRIVATE KEY-----"
RSA_BEGIN = "-----BEGIN RSA " + "PRIVATE KEY-----"
# Corpo de mentira com cara de base64 de verdade (linhas de 64 caracteres, maiúsculas, minúsculas e dígitos).
BODY = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" + R36[:12],
        R36 + "Zq8W3e5R7t9Y1u3I5o7P9a1S3d5F7g9H0jK2"[:28]]


class PrivateKeys(Case):
    def test_code_that_handles_keys_is_not_a_key(self):
        files = {
            "src/pem.ts": f'const PEM_HEADER = "{BEGIN}";\nconst PEM_FOOTER = "{END}";\n',
            "src/strip.js": f"const body = key.replace('{BEGIN}', '').replace('{END}', '');\n",
            "src/check.ts": f"if (!pk.includes('{RSA_BEGIN}')) throw new Error('bad key')\n",
            "src/form.tsx": f'<Textarea\n  placeholder="{BEGIN}"\n  rows={{4}}\n/>\n',
            "src/fields.tsx": f"  : '{BEGIN}\\n...\\n{END}'\n",
            "src/sa.py": f'SA = {{"private_key": "{BEGIN}\\nYOUR_PRIVATE_KEY\\n{END}\\n"}}\n',
            "src/doc.py": f'"""Example:\n\n    PRIVATE_KEY="{RSA_BEGIN}\n    ...\n"""\n',
        }
        self.assertEqual(brief(scan_files(files), "SEC001"), [])

    def test_real_keys_still_fire(self):
        one_line = BEGIN + "\\n" + "\\n".join(BODY) + "\\n" + END + "\\n"
        multi = BEGIN + "\n" + "\n".join(BODY) + "\n" + END + "\n"
        files = {
            "config/service-account.json": '{\n  "type": "service_account",\n  "private_key": "' + one_line + '",\n}\n',
            "src/key.ts": "export const KEY = `" + multi + "`\n",
            "src/key.py": 'KEY = (\n    "' + BEGIN + '\\n"\n    "' + BODY[0] + '\\n"\n)\n',
            "src/enc.txt": "-----BEGIN RSA " + "PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B\n\n" + BODY[0] + "\n",
        }
        self.assertEqual(brief(scan_files(files), "SEC001"), [
            ("SEC001", "config/service-account.json", 3, "critical"), ("SEC001", "src/enc.txt", 1, "critical"),
            ("SEC001", "src/key.py", 2, "critical"), ("SEC001", "src/key.ts", 1, "critical")])

    def test_multi_line_key_in_a_committed_env_is_still_a_secret(self):
        files = {".env": "APP_NAME=demo\nPRIVATE_KEY=\"" + BEGIN + "\n" + "\n".join(BODY) + "\n" + END + "\"\n"}
        self.assertEqual(brief(scan_files(files, tracked=files), "SEC002"), [("SEC002", ".env", None, "high")])


    def test_a_header_alone_in_docs_is_not_a_key(self):
        pgp = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
        files = {
            "README.md": f"Paste your key:\n\n{RSA_BEGIN}\n\nThen save the file.\n",
            "docs/keys.md": f"```\n{RSA_BEGIN}\n...\n-----END RSA " + "PRIVATE KEY-----\n```\n",
            "docs/gpg.md": f"Export it; the file starts with `{pgp}`.\n\n{pgp}\n\n(base64 here)\n",
            "src/last.ts": f"const h = `{BEGIN}",
        }
        self.assertEqual(brief(scan_files(files), "SEC001"), [])

    PGP_BEGIN = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
    PGP_END = "-----END PGP " + "PRIVATE KEY BLOCK-----"
    # The shape of a pattern that also takes PGP blocks (the private_key pattern comes from _redact).
    PGP_RX = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
                        r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")

    def test_pgp_blocks_need_a_body_too(self):
        armored = self.PGP_BEGIN + "\nVersion: GnuPG v2\n\n" + "\n".join(BODY) + "\n=Ab3d\n" + self.PGP_END + "\n"
        bare = self.PGP_BEGIN + "\n\n" + "\n".join(BODY) + "\n" + self.PGP_END + "\n"
        files = {"keys/armored.asc.txt": armored, "keys/bare.txt": bare,
                 "src/one_line.json": '{"key": "' + self.PGP_BEGIN + "\\n\\n" + BODY[0] + "\\n" + self.PGP_END + '"}\n',
                 "README.md": f"Starts with:\n\n{self.PGP_BEGIN}\n\n...\n\n{self.PGP_END}\n",
                 "src/check.py": f"if text.startswith('{self.PGP_BEGIN}'):\n    pass\n"}
        patterns = [("private_key", self.PGP_RX)] + secrets.TOKEN_PATTERNS[1:]
        with mock.patch.object(secrets, "TOKEN_PATTERNS", patterns):
            got = brief(scan_files(files), "SEC001")
        self.assertEqual(got, [("SEC001", "keys/armored.asc.txt", 1, "critical"), ("SEC001", "keys/bare.txt", 1, "critical"),
                               ("SEC001", "src/one_line.json", 1, "critical")])

    def test_key_files_are_read(self):
        ssh = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA" + R36 + "\n-----END OPENSSH " + "PRIVATE KEY-----\n"
        pem = BEGIN + "\n" + "\n".join(BODY) + "\n" + END + "\n"
        cert = "-----BEGIN CERTIFICATE-----\n" + BODY[0] + "\n-----END CERTIFICATE-----\n"
        files = {"deploy/id_rsa": ssh, "deploy/id_rsa.pub": "ssh-ed25519 AAAAC3Nza" + R36 + " me@host\n",
                 "certs/server.key": pem, "certs/server.pem": cert, "keys/AuthKey_7QW3ER5TY8.p8": pem}
        self.assertEqual(brief(scan_files(files), "SEC001"), [
            ("SEC001", "certs/server.key", 1, "critical"), ("SEC001", "deploy/id_rsa", 1, "critical"),
            ("SEC001", "keys/AuthKey_7QW3ER5TY8.p8", 1, "critical")])


# =========================================================================== formatos de token

META = "EAA" + "BwzLixnjYBOZBq3ZAy7ZCZAkZBN8Vx" + R36


class TokenFormats(Case):
    def test_meta_prefix_inside_base64_data_is_not_a_token(self):
        # Binary data (images, fonts, wasm) in base64 is full of "AAAA", and "/EAA..." or "+EAA..." started a Meta token.
        blob = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHe/" + META[:40] + "+AAAAElFTkSuQmCC"
        wasm = "AGFzbQEAAAABJ" + "+" + META[:30] + "/AX9gAX8AYAJ/fwBgBH9/f38Bf2AAAGADf39/AALLAQgDZW52"
        files = {"src/logo.ts": f'export const LOGO = "data:image/png;base64,{blob}";\n',
                 "src/wasm.js": f'module.exports = Buffer.from("{wasm}", "base64");\n',
                 "src/end.js": f'const b = "AAAA/{META[:40]}";\n'}
        self.assertEqual(brief(scan_files(files), "SEC001"), [])

    def test_meta_tokens_still_fire(self):
        files = {"src/fb.py": f'FB_TOKEN = "{META}"\n',
                 "src/graph.js": f'fetch("https://graph.facebook.com/v18.0/me?access_token={META}&fields=id")\n',
                 "src/env.sh": f"export FB_TOKEN={META}\n"}
        self.assertEqual(brief(scan_files(files), "SEC001"), [
            ("SEC001", "src/env.sh", 1, "high"), ("SEC001", "src/fb.py", 1, "high"), ("SEC001", "src/graph.js", 1, "high")])


    def test_random_tokens_that_contain_seu_or_sua_are_found(self):
        # "seu" and "sua" (Portuguese "your") were placeholder words anywhere in the value: about 1 in 100 real
        # OpenAI project keys has one of them somewhere in its random part, and those keys were silently skipped.
        cases = [("GitHub token", "ghp_" + R36[:10] + "sua" + R36[13:]),
                 ("OpenAI API key", "sk-" + "proj-" + R36 + "Seu" + R36),
                 ("Anthropic API key", "sk-ant-" + "api03-" + R36 + "xSUAx" + R36 + "AA")]
        for kind, value in cases:
            with self.subTest(kind=kind):
                f = scan_files({"src/keys.py": f'KEY = "{value}"\n'})
                self.assertEqual([(x.rule, x.params["kind_en"], x.severity) for x in f], [("SEC001", kind, "critical")])

    def test_portuguese_placeholders_stay_silent(self):
        lines = ['OPENAI_API_KEY = "sk-sua-chave-aqui-1234567890abcdef"', 'OPENAI_API_KEY = "sk-SuaChaveAqui1234567890xyz"',
                 'GITHUB_TOKEN = "ghp_seu_token_aqui_1234567890abcdefghijkl"', 'api_token = "SEU_TOKEN_AQUI_123"',
                 'api_token = "sua-chave-secreta-42"']
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/keys.py": line + "\n"}), "SEC001"), [])


    # Each value is built from pieces, so the whole token never appears in this file.
    NEW_FORMATS = [
        ("Google OAuth client secret", "high", "GOCSPX-" + R36[:28]),
        ("Replicate API token", "critical", "r8_" + R36 + "Q"),
        ("Pinecone API key", "critical", "pcsk_" + "4Ab9z" + "_" + (R36 * 2)[:63]),
        ("Shopify token", "critical", "shp" + "at_" + "0a1b2c3d4e5f6a7b" * 2),
        ("Shopify token", "critical", "shp" + "ss_" + "9f8e7d6c5b4a3f2e" * 2),
        ("Notion API token", "critical", "ntn_" + "41234567890" + R36[:35]),
        ("Linear API key", "critical", "lin_" + "api_" + R36 + "Qw9x"),
        ("Resend API key", "critical", "re_" + "Ab3dE5gH" + "_" + R36[:24]),
    ]

    def test_more_service_formats_are_found(self):
        for kind, sev, value in self.NEW_FORMATS:
            with self.subTest(kind=kind):
                f = scan_files({"src/client.py": f'client = Client("{value}")\n'})
                self.assertEqual([(x.rule, x.params["kind_en"], x.severity) for x in f], [("SEC001", kind, sev)])
                f = scan_files({"tests/test_client.py": f'client = Client("{value}")\n'})
                self.assertEqual([(x.rule, x.severity) for x in f], [("SEC001", "low")])

    def test_near_misses_of_the_new_formats_stay_silent(self):
        lines = [
            "GOCSPX-" + R36[:27], "GOCSPX-" + R36[:29], "GOCSPX-" + "your-client-secret-here-1234",
            "r8_" + R36, "r8_" + R36.lower() + "q", "r8_" + "0" * 37,
            "pcsk_" + R36 + R36[:30], "pcsk_" + "4Ab9z" + "_" + R36,
            "shp" + "at_" + "0a1b2c3d4e5f6a7b" * 2 + "0", "shp" + "at_" + "zz1b2c3d4e5f6a7b" * 2, "shpxx_" + "0a1b2c3d4e5f6a7b" * 2,
            "ntn_" + "4123456789" + R36[:36], "ntn_" + "41234567890" + R36[:34],
            "lin_" + "api_" + R36 + "Qw9", "lin_" + "api_" + "x" * 40,
            "re_" + "123456789", "re_" + "compile_" + "pattern_with_a_long_name", "re_" + "abcdefgh" + "_" + "abcdefghijklmnopqrstuvwx",
            "re_" + "Ab3dE5gH" + "_" + R36[:23],
            # The prefix does not count as the digit or the lower case letter: r8_ has both, re_ has lower case.
            "r8_" + R36.upper() + "Q", "r8_" + ("aBcDeFgHiJkLmNoPqRsT" * 2)[:37], "re_" + "AB3DE5GH" + "_" + R36.upper()[:24],
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/client.py": f'client = Client("{line}")\n'}), "SEC001"), [])

    def test_openai_and_npm_prefixes_do_not_supply_a_letter_case(self):
        # sk-, sk-proj- and npm_ are lower case: after them a real key still has both cases and a digit (OpenAI keys
        # carry "T3BlbkFJ"; npm tokens are 36 random letters and digits). Upper case and digits only is a made-up value.
        silent = ["npm_" + "ABCDEFGHIJ1234567890KLMNOPQRSTUVWXYZ", "npm_" + R36.upper(), "npm_" + R36.lower(),
                  "sk-" + "ABCDEFGHIJKLMNOP1234QRST", "sk-" + "proj-" + R36.upper() + "_ABC-123",
                  "sk-" + "svcacct-" + R36.upper(), "sk-" + "admin-" + R36.upper()]
        for value in silent:
            with self.subTest(value=value[:12]):
                self.assertEqual(brief(scan_files({"src/client.py": f'client = Client("{value}")\n'}), "SEC001"), [])
        found = [("npm token", "npm_" + R36), ("npm token", "npm_" + R36[::-1]),
                 ("OpenAI API key", "sk-" + R36.upper()[:20] + "T3Blbk" + "FJ" + R36.upper()[:20]),
                 ("OpenAI API key", "sk-" + "proj-" + R36 + "T3Blbk" + "FJ" + R36[::-1]),
                 ("OpenAI API key", "sk-" + "svcacct-" + R36 + "_x-" + R36),
                 ("OpenAI API key", "sk-" + "admin-" + R36[::-1])]
        for kind, value in found:
            with self.subTest(value=value[:12]):
                f = scan_files({"src/client.py": f'client = Client("{value}")\n'})
                self.assertEqual([(x.rule, x.params["kind_en"], x.severity) for x in f], [("SEC001", kind, "critical")])

    def test_new_formats_are_masked_and_linear(self):
        for _, _, value in self.NEW_FORMATS:
            self.assertNotIn(value[8:20], secrets.mask(f"Bash(curl -H 'Authorization: {value}' https://api.acme.dev)"))
        for text in ("GOCSPX-" * 20000, "r8_" + "a" * 60000, "pcsk_" + "a_" * 30000, "shpat_" * 20000, "ntn_" + "1" * 60000,
                     "lin_api_" * 10000, "re_" + "a" * 8 + "_" * 60000):
            with self.subTest(text=text[:10]):
                self.assertFast(secrets.scan_text, text, "src/x.py", limit=1.0)

    def test_hugging_face_tokens_without_a_digit_are_found(self):
        # About 1 in 400 real tokens (34 random letters and digits) has no digit at all; both letter cases are enough.
        letters = "aBcDeFgHiJkLmNoPqRsTuVwXyZ"
        for value in ("hf_" + letters + letters[:8], "hf_" + R36[:34]):
            with self.subTest(value=value[:8]):
                f = scan_files({"src/hub.py": f'hub = Hub("{value}")\n'})
                self.assertEqual([(x.rule, x.params["kind_en"], x.severity) for x in f],
                                 [("SEC001", "Hugging Face token", "critical")])
        for value in ("hf_" + letters.lower() + "abcdefgh", "hf_" + letters.upper() + "ABCDEFGH", "hf_" + "1234567890" * 4):
            with self.subTest(value=value[:8]):
                self.assertEqual(brief(scan_files({"src/hub.py": f'hub = Hub("{value}")\n'}), "SEC001"), [])

    def test_clerk_secret_keys_are_named_clerk(self):
        # Clerk secret keys share Stripe's sk_live_/sk_test_ shape; the line says which service it is.
        live, test = "sk_" + "live_" + R36 + "Qw9x", "sk_" + "test_" + R36 + "Qw9x"
        cases = [(f'const clerk = createClerkClient({{ secretKey: "{live}" }})', "Clerk secret key", "critical"),
                 (f'CLERK_SECRET_KEY = "{test}"', "Clerk secret key", "low"),
                 (f'const stripe = new Stripe("{live}")', "Stripe key", "critical"),
                 (f'stripe.api_key = "{test}"', "Stripe key", "low")]
        for line, kind, sev in cases:
            with self.subTest(line=line[:30]):
                f = scan_files({"src/billing.ts": line + "\n"})
                self.assertEqual([(x.rule, x.params["kind_en"], x.severity) for x in f], [("SEC001", kind, sev)])
        self.assertEqual(scan_files({"src/a.ts": f'const clerk = createClerkClient({{ secretKey: "{live}" }})\n'})[0]
                         .params["kind_pt"], "chave secreta do Clerk")

    def test_webhook_is_judged_by_its_own_url_not_by_the_rest_of_the_line(self):
        slack = "https://hooks.slack.com/services/" + "T01ABCDEF/B02GHIJKL/" + "q8W3e5R7t9Y1u3I5o7P9a1S3"
        discord = "https://discord.com/api/webhooks/" + "112233445566778899/" + "Zq8W3e5R7t9Y1u3I5o7P9a1S3d5F7g9H"
        real = {"src/notify.js": f'await axios.post("{slack}", {{ text: "your build finished" }})\n',
                "src/alert.ts": f'const hook = process.env.DISCORD_WEBHOOK || "{discord}"\n'}
        self.assertEqual(brief(scan_files(real), "SEC001"), [("SEC001", "src/alert.ts", 1, "high"),
                                                              ("SEC001", "src/notify.js", 1, "high")])
        examples = {"src/a.js": 'post("https://hooks.slack.com/services/' + 'T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")\n',
                    "src/b.js": 'post("https://hooks.slack.com/services/YOUR/WEBHOOK/URL")\n',
                    "src/c.js": 'post("https://discord.com/api/webhooks/123456/your-webhook-token")\n'}
        self.assertEqual(brief(scan_files(examples), "SEC001"), [])


# =========================================================================== atribuição a campo sensível

class GenericAssignments(Case):
    def test_values_that_are_not_secrets(self):
        lines = [
            '"password_complexity_requirement": "数字、大文字、1文字以上",',
            '"Tokens": "توکن\\u200cها",',
            'placeholder={`{"X-api-key": "1234567890"}`}',
            "'AUTOMATIC1111_API_AUTH': 'image_generation.automatic1111.api_auth',",
            "export const DUCKLAKE_S3_SECRET_ENV_VAR = 'DUCKLAKE_S3_SECRET'",
            'access_token: "MOCK_ACCESS_TOKEN_OAUTH2",',
            "api_key: 'sb_publishable_ltaNA7nnVozoSCOcZIjg',",
            'const stripe = { apiKey: "pk_live_51H8xYz2eZvKYlo2C0aBcDeFg" }',
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/app.ts": line + "\n"}), "SEC001"), [])

    def test_hard_coded_secrets_still_fire(self):
        lines = ['ORACLE_DB_PASSWORD = "' + 'Welcome123456"', 'password: "' + 'ADMINadmin2022!",', 'const password = "' + 'Tr0ub4dor-77-xK"',
                 "JWT_SECRET = '" + "super-secret-jwt-token-with-at-least-32-characters-long'",
                 'api_token = "' + '0cc0e6c35519bba620c9360cfe3e68d0"', 'secret = "' + 'A1B2C3D4E5F6G7H8"']
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(brief(scan_files({"src/app.py": line + "\n"}), "SEC001"), [("SEC001", "src/app.py", 1, "high")])



# =========================================================================== mascaramento

class Masking(Case):
    """mask() is what text, Markdown and JSON reports show of a line (AGT001 permission entries, hidden messages):
    the value must never come through, even for a format the detector does not know or an unusual length."""

    def test_prefixed_tokens_of_any_length_are_masked(self):
        tails = {"hf_": R36[:33], "gsk_": R36 + R36[:20], "xai-": R36 * 2 + R36[:12], "sbp_": "0a1b2c3d4e5f" * 3,
                 "glpat-": R36[:20] + "-x.01.ab", "sb_secret_": R36[:30], "GOCSPX-": R36[:28], "r8_": R36[:37],
                 "pcsk_": "4Ab9z_" + R36 + R36[:20], "shpat_": "0a1b2c3d4e5f" * 3, "ntn_": R36 + R36[:10],
                 "lin_api_": R36 + "Qw9x", "re_": "Ab3dE5gH_" + R36[:24], "dop_v1_": "0a1b2c3d" * 8,
                 "SG.": R36[:20] + "." + R36}
        for prefix, tail in tails.items():
            for tmpl in ("{}", "use the token {} to log in", "Bash(curl https://api.example.com/v1?q=1&k={})"):
                with self.subTest(prefix=prefix, tmpl=tmpl):
                    self.assertNotIn(tail[6:18], secrets.mask(tmpl.format(prefix + tail)))

    def test_credentials_in_urls_and_command_lines_are_masked(self):
        pw = "Tr0ub4dor" + "77xK"
        for line in (f"curl https://maps.example.com/api?q=x&key={pw}", f"Bash(curl -u admin:{pw} https://x)",
                     f"curl --user=admin:{pw} https://x", f"curl --user admin:{pw}", f"sshpass -p {pw} ssh host",
                     f"Bash(mysql -uroot -p{pw} app:*)", f"mysqldump -u root -p{pw} --all-databases"):
            with self.subTest(line=line):
                self.assertNotIn(pw, secrets.mask(line))

    def test_ordinary_command_lines_are_left_alone(self):
        for line in ("git push -u origin main", "docker run -u 1000:1000 image", "mkdir -p build/out",
                     "curl https://example.com/list?sort=key&page=2", "npm_config_cache=/tmp/npm",
                     "ssh -p 2222 host", "mysql -p", "hf_hub_download(repo_id)", "re_compile_pattern"):
            with self.subTest(line=line):
                self.assertEqual(secrets.mask(line), line)

    def test_new_masks_are_linear(self):
        for text in ("-u " + "a" * 50000, "-u" + " " * 50000 + "x", "?key=" * 20000, "mysql " + "-p" * 30000,
                     "sshpass" + " -p" * 30000, "hf_" * 30000, "gsk_" + "a" * 60000):
            with self.subTest(text=text[:12]):
                self.assertFast(secrets._mask_loose, text, limit=0.5)


# =========================================================================== .env no git

def jwt(payload):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(payload) + "." + "Ab3dE5gH7jK9lM1nP3qR5sT7uV9wX1yZ3aB5cD7eF9g"


def signed_jwt(payload, secret):
    b = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    head = b(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()) + "." + \
        b(json.dumps(payload, separators=(",", ":")).encode())
    return head + "." + b(hmac.new(secret, head.encode(), hashlib.sha256).digest())


class CommittedEnv(Case):
    HEX = "03f1e0f2c3b4a5968778695a4b3c2d1e0f9e8d7c6b5a49382716051f2e3d4c5b"
    CIPHER = "encrypted:BDqDBibm4wsYqMpCjTQ6BsDHmMadg9K3dAt+Z9HPMfLEIRVz50hmLXPXRuDBXaJi/LwWYEVUNiq0HIS" + R36

    def sev(self, name, text):
        files = {name: text}
        return [f.severity for f in scan_files(files, tracked=files) if f.rule == "SEC002"]

    def test_public_values_only_is_low(self):
        anon = jwt({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "anon"})
        self.assertEqual(self.sev(".env", "NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnop.supabase.co\n"
                                          f"NEXT_PUBLIC_SUPABASE_ANON_KEY={anon}\nSUPABASE_ANON_KEY=\"{anon}\"\n"), ["low"])

    def test_supabase_local_demo_keys_only_is_low(self):
        # The .env that supabase start prints: local URL, the demo anon key and the demo service_role key.
        secret = b"super-secret-jwt-token-with-at-least-" + b"32-characters-long"
        demo = lambda role: signed_jwt({"iss": "supabase-demo", "role": role, "exp": 1983812996}, secret)
        text = (f"SUPABASE_URL=http://127.0.0.1:54321\nSUPABASE_ANON_KEY={demo('anon')}\n"
                f"SUPABASE_SERVICE_ROLE_KEY={demo('service_role')}\n")
        self.assertEqual(self.sev(".env", text), ["low"])
        other = signed_jwt({"iss": "supabase-demo", "role": "service_role"}, b"project-own-secret-" + b"Q8w3E5r7T9y1")
        self.assertEqual(self.sev(".env", f"SUPABASE_SERVICE_ROLE_KEY={other}\n"), ["high"])

    VAULT = ("#/-------------------.env.vault---------------------/\n#/         cloud-agnostic vaulting standard      /\n"
             "#/--------------------------------------------------/\n\n# development\n"
             'DOTENV_VAULT_DEVELOPMENT="' + R36 + R36[::-1] + '"\nDOTENV_VAULT_DEVELOPMENT_VERSION=2\n\n'
             '# production\nDOTENV_VAULT_PRODUCTION="' + R36[::-1] + R36 + '"\nDOTENV_VAULT_PRODUCTION_VERSION=2\n')

    def test_dotenv_vault_file_is_made_to_be_committed(self):
        # dotenv-vault encrypts every environment into .env.vault, and its docs say to commit it: no "remove it from
        # git" (SEC002) and no "add it to .gitignore" (SEC003). The keys that open it (.env.keys) still count.
        for tracked in ({".env.vault"}, set()):
            with self.subTest(tracked=tracked):
                f = scan_files({".env.vault": self.VAULT}, tracked=tracked)
                self.assertEqual(brief(f, "SEC002", "SEC003"), [])
        f = scan_files({"api/.env.vault": self.VAULT + "STRIPE_SECRET=Tr0ub4dor77xKq9\n"}, tracked={"api/.env.vault"})
        self.assertEqual(brief(f, "SEC002", "SEC003"), [("SEC002", "api/.env.vault", None, "high")])
        keys = 'DOTENV_KEY_PRODUCTION="dotenv://:key_' + "0dec82bea24ada79a983dcc11b431e28" * 2 + \
               '@dotenv.local/vault/.env.vault?environment=production"\n'
        self.assertEqual(self.sev(".env.keys", keys), ["high"])
        self.assertEqual(brief(scan_files({".env.keys": keys}, tracked=set()), "SEC003"), [("SEC003", ".env.keys", None, "medium")])

    def test_dotenv_vault_login_token_is_a_secret(self):
        # .env.me holds DOTENV_ME, the token that logs in to the dotenv-vault account and pulls every environment.
        self.assertEqual(self.sev(".env.me", "DOTENV_ME=me_" + "0dec82bea24ada79a983dcc11b431e28" * 2 + "\n"), ["high"])
        self.assertEqual(self.sev(".env.me", "DOTENV_ME=me_your_token_here\n"), ["low"])

    def test_dotenvx_encrypted_file_is_low(self):
        text = (f'#/---[DOTENV_PUBLIC_KEY]---/\nDOTENV_PUBLIC_KEY="{self.HEX}"\nDOTENV_PUBLIC_KEY_PRODUCTION="{self.HEX}"\n\n'
                f'OPENAI_API_KEY="{self.CIPHER}"\nDB_PASSWORD={self.CIPHER}\n')
        self.assertEqual(self.sev(".env", text), ["low"])
        self.assertEqual(self.sev(".env.production", text), ["low"])

    def test_plain_urls_under_sensitive_names_are_low(self):
        for line in ("SUPABASE_AUTH_ADDITIONAL_REDIRECT_URLS=http://localhost:3000,https://app.acme.dev/auth/callback",
                     "AUTH_CALLBACK=https://app.acme.dev/api/auth/callback", 'OAUTH_REDIRECT_URIS="https://a.acme.dev/cb"'):
            with self.subTest(line=line):
                self.assertEqual(self.sev(".env", line + "\n"), ["low"])
        for line in ("AUTH_WEBHOOK=https://hooks.acme.dev/x?token=Q8w3E5r7T9y1U2",
                     "DATABASE_PASSWORD_URL=postgres://app:" + "Tr0ub4dor77xK@db.prod.acme.dev/app"):
            with self.subTest(line=line):
                self.assertEqual(self.sev(".env", line + "\n"), ["high"])

    def test_real_secrets_stay_high(self):
        svc = jwt({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "service_role"})
        for name, text in ((".env", f"SUPABASE_SERVICE_ROLE_KEY={svc}\n"),
                           (".env.keys", f'DOTENV_PRIVATE_KEY="{self.HEX}"\n'),
                           (".env", f'OPENAI_API_KEY="{self.CIPHER}"\nSTRIPE_SECRET=Tr0ub4dor77xKq9\n'),
                           (".env", f"NEXT_PUBLIC_SUPABASE_ANON_KEY={svc}\n")):
            with self.subTest(text=text[:30]):
                self.assertEqual(self.sev(name, text), ["high"])

if __name__ == "__main__":
    unittest.main()
