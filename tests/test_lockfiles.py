"""Testes dos leitores de lockfile e manifesto. Só arquivos locais em diretório temporário, nenhum acesso à rede."""
import json
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from stingward import lockfiles

D = textwrap.dedent
DEEP_JSON = "[" * 100000  # nesting far beyond the json decoder recursion limit


class LockfileCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, rel, content, encoding="utf-8"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding=encoding)
        return rel

    def full(self, rel, content, encoding="utf-8"):
        """Full parse() output: (ecosystem, name, version, file, line)."""
        self.write(rel, content, encoding)
        return lockfiles.parse(self.root, rel)

    def pkgs(self, rel, content, encoding="utf-8"):
        return [x[:3] for x in self.full(rel, content, encoding)]

    def assertNoCrash(self, rel, contents):
        """Malformed input must never raise: empty or partial results only."""
        for content in contents:
            with self.subTest(content=content[:60]):
                got = self.pkgs(rel, content)
                self.assertIsInstance(got, list)

    def ranges(self, rel, content):
        self.write(rel, content)
        return lockfiles.open_ranges(self.root, rel)


# --------------------------------------------------------------------------- dispatch


class Dispatch(LockfileCase):
    def test_is_dependency_file(self):
        yes = ["package-lock.json", "npm-shrinkwrap.json", "web/yarn.lock", "pnpm-lock.yaml", "bun.lock",
               "package.json", "requirements.txt", "requirements-dev.txt", "requirements_test.txt",
               "requirements.prod.txt", "poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "svc/go.mod",
               "Cargo.lock", "Gemfile.lock", "composer.lock", "src/App/packages.lock.json", "dev-requirements.txt",
               "ci/test-requirements.txt", "docs_requirements.txt"]
        no = ["requirements.in", "dev-requirements.in", "nonrequirements.txt", "dev-requirements.txt.bak", "package.json.bak", "Cargo.toml", "pyproject.toml",
              "Pipfile", "Gemfile", "go.sum", "bun.lockb", "yarn.lock.orig", "README.md"]
        for rel in yes:
            self.assertTrue(lockfiles.is_dependency_file(rel), rel)
        for rel in no:
            self.assertFalse(lockfiles.is_dependency_file(rel), rel)

    def test_unknown_missing_and_directory_return_empty(self):
        self.write("Cargo.toml", '[package]\nname = "x"\nversion = "1.0.0"\n')
        self.assertEqual(lockfiles.parse(self.root, "Cargo.toml"), [])
        self.assertEqual(lockfiles.parse(self.root, "package-lock.json"), [])
        (self.root / "yarn.lock").mkdir()
        self.assertEqual(lockfiles.parse(self.root, "yarn.lock"), [])

    def test_nested_rel_path_is_kept_in_results(self):
        got = self.full("apps/web/requirements-dev.txt", "pytest==7.4.0\n")
        self.assertEqual(got, [("PyPI", "pytest", "7.4.0", "apps/web/requirements-dev.txt", 1)])

    def test_shrinkwrap_uses_npm_parser(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/ms": {"version": "2.1.3"}}})
        self.assertEqual(self.pkgs("npm-shrinkwrap.json", lock), [("npm", "ms", "2.1.3")])

    def test_utf8_bom_is_tolerated(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/ms": {"version": "2.1.3"}}})
        cases = [("requirements.txt", "Django==3.2.0\nflask==2.0.1\n", [("PyPI", "Django", "3.2.0"), ("PyPI", "flask", "2.0.1")]),
                 ("package-lock.json", lock, [("npm", "ms", "2.1.3")]),
                 ("poetry.lock", '[[package]]\nname = "a"\nversion = "1.0"\n', [("PyPI", "a", "1.0")])]
        for rel, content, want in cases:
            with self.subTest(rel=rel):
                self.assertEqual(self.pkgs(rel, content, encoding="utf-8-sig"), want)

    def test_utf16_with_bom_is_read(self):
        # Windows PowerShell 5 writes UTF-16 LE with a BOM for `pip freeze > requirements.txt`.
        lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/ms": {"version": "2.1.3"}}})
        cases = [("requirements.txt", "requests==2.19.0\r\nflask==0.12\r\n", [("PyPI", "requests", "2.19.0"), ("PyPI", "flask", "0.12")]),
                 ("package-lock.json", lock, [("npm", "ms", "2.1.3")])]
        for encoding in ("utf-16", "utf-16-be"):
            for rel, content, want in cases:
                with self.subTest(rel=rel, encoding=encoding):
                    data = content.encode(encoding)
                    if encoding == "utf-16-be":
                        data = b"\xfe\xff" + data
                    (self.root / rel).write_bytes(data)
                    self.assertEqual([x[:3] for x in lockfiles.parse(self.root, rel)], want)
        # Bytes, not write_text: on Windows text mode would turn each \r\n into \r\r\n.
        (self.root / "requirements.txt").write_bytes("requests==2.19.0\r\nflask>=0.12\r\n".encode("utf-16"))
        self.assertEqual([(r.name, r.floor, r.line) for r in lockfiles.ranges(self.root, "requirements.txt")], [("flask", "0.12", 2)])
        self.assertEqual(lockfiles.open_ranges(self.root, "requirements.txt"), 1)

    def test_utf16_requirements_are_audited_by_a_scan(self):
        from stingward import scan
        (self.root / "requirements.txt").write_bytes("requests==2.19.0\r\nflask==0.12\r\n".encode("utf-16"))
        self.assertEqual(scan.run(str(self.root), offline=True)[0].sources["packages"], 2)

    def test_deeply_nested_json_does_not_crash(self):
        for rel in ("package-lock.json", "package.json", "Pipfile.lock", "composer.lock"):
            with self.subTest(rel=rel):
                self.assertEqual(self.pkgs(rel, DEEP_JSON), [])

    def test_line_numbers_count_only_newlines(self):
        # \f, \v, \x1c, \x85 and U+2028 are line breaks for str.splitlines() but not for editors or SARIF
        lock = '{\n  "description": "a\u2028b\x85c",\n  "lockfileVersion": 3,\n  "packages": {\n' \
               '    "node_modules/ms": {"version": "2.1.3"}\n  }\n}\n'
        cases = [("requirements.txt", "# page\x0cbreak\x0bhere\nDjango==3.2.0\n", 2),
                 ("yarn.lock", "# a\x1cb\x85c\n\nms@^2:\n  version \"2.1.3\"\n", 3),
                 ("go.mod", "module x // a\x0bb\n\nrequire a.b/c v1.0.0\n", 3),
                 ("Gemfile.lock", "GEM\n  remote: x\x0cy\n  specs:\n    rake (13.0.6)\n", 4),
                 ("poetry.lock", '# x\u2028y\n[[package]]\nname = "a"\nversion = "1.0"\n', 2),
                 ("package-lock.json", lock, 5)]
        for rel, content, want in cases:
            with self.subTest(rel=rel):
                self.assertEqual([x[4] for x in self.full(rel, content)], [want])


# --------------------------------------------------------------------------- npm


class NpmLock(LockfileCase):
    def test_v1_nested_scoped_dev_and_non_registry(self):
        lock = {
            "name": "app", "version": "1.0.0", "lockfileVersion": 1, "requires": True,
            "dependencies": {
                "@babel/code-frame": {"version": "7.12.13", "resolved": "https://registry.npmjs.org/@babel/code-frame/-/code-frame-7.12.13.tgz",
                                      "integrity": "sha512-x", "dev": True, "requires": {"@babel/highlight": "^7.10.4"}},
                "@babel/highlight": {"version": "7.13.10", "dev": True},
                "express": {"version": "4.17.1", "requires": {"debug": "2.6.9"},
                            "dependencies": {"debug": {"version": "2.6.9", "dependencies": {"ms": {"version": "2.0.0"}}}}},
                "debug": {"version": "4.3.1"},
                "local-lib": {"version": "file:../local-lib"},
                "gitdep": {"version": "git+https://github.com/x/gitdep.git#abc123", "from": "git+https://github.com/x/gitdep.git"},
                "tarball": {"version": "https://example.com/tarball-1.0.0.tgz"},
                "noversion": {"resolved": "https://example.com/x.tgz"},
                "weird": "not-a-dict",
            },
        }
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock, indent=2)), [
            ("npm", "@babel/code-frame", "7.12.13"), ("npm", "@babel/highlight", "7.13.10"),
            ("npm", "express", "4.17.1"), ("npm", "debug", "2.6.9"), ("npm", "ms", "2.0.0"), ("npm", "debug", "4.3.1"),
        ])

    def test_v1_npm_alias(self):
        lock = {"lockfileVersion": 1, "dependencies": {
            "string-width-cjs": {"version": "npm:string-width@4.2.3",
                                 "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"}}}
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock)), [("npm", "string-width", "4.2.3")])

    def test_v2_reads_packages_and_ignores_legacy_dependencies(self):
        lock = {
            "name": "app", "lockfileVersion": 2, "requires": True,
            "packages": {
                "": {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "^4.17.0"}},
                "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            },
            "dependencies": {"lodash": {"version": "4.17.21"}, "only-in-legacy": {"version": "9.9.9"}},
        }
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock, indent=2)), [("npm", "lodash", "4.17.21")])

    def test_v3_nested_scoped_dev_optional_and_alias(self):
        lock = {
            "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {
                "": {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.17.1"}},
                "node_modules/@babel/core": {"version": "7.2.0", "dev": True},
                "node_modules/express": {"version": "4.17.1"},
                "node_modules/express/node_modules/debug": {"version": "2.6.9"},
                "node_modules/@org/a/node_modules/@org/b": {"version": "1.0.0", "devOptional": True},
                "node_modules/fsevents": {"version": "2.3.2", "optional": True},
                "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3"},
                "node_modules/bundler/node_modules/inner": {"version": "0.1.0", "inBundle": True},
                "node_modules/no-version": {"resolved": "https://example.com/x.tgz"},
            },
        }
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock, indent=2)), [
            ("npm", "@babel/core", "7.2.0"), ("npm", "express", "4.17.1"), ("npm", "debug", "2.6.9"),
            ("npm", "@org/b", "1.0.0"), ("npm", "fsevents", "2.3.2"), ("npm", "string-width", "4.2.3"),
            ("npm", "inner", "0.1.0"),
        ])

    def test_v3_line_points_at_package_key(self):
        text = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/express": {"version": "4.17.1"},
            "node_modules/express/node_modules/debug": {"version": "2.6.9"}}}, indent=2)
        lines = text.splitlines()
        want = {n: next(i for i, ln in enumerate(lines, 1) if f'"node_modules/{n}"' in ln)
                for n in ("express", "express/node_modules/debug")}
        got = self.full("package-lock.json", text)
        self.assertEqual(got, [("npm", "express", "4.17.1", "package-lock.json", want["express"]),
                               ("npm", "debug", "2.6.9", "package-lock.json", want["express/node_modules/debug"])])

    def test_v3_link_entries_skipped(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "root"},
            "node_modules/my-lib": {"resolved": "../my-lib", "link": True},
            "node_modules/linked-with-version": {"version": "1.0.0", "resolved": "../linked", "link": True},
            "node_modules/react": {"version": "18.2.0"}}}
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock, indent=2)), [("npm", "react", "18.2.0")])

    def test_v3_workspace_folders_not_reported_as_registry_packages(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "root", "workspaces": ["packages/*"]},
            "node_modules/@acme/app": {"resolved": "packages/app", "link": True},
            "packages/app": {"name": "@acme/app", "version": "0.3.0", "dependencies": {"react": "^18.2.0"}},
            "node_modules/react": {"version": "18.2.0"}}}
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock, indent=2)), [("npm", "react", "18.2.0")])

    def test_large_lockfile_parses_in_linear_time(self):
        # 12k packages used to take ~20 s: each line lookup scanned the file from the top
        pkgs = {"": {"name": "big", "version": "1.0.0"}}
        for i in range(12000):
            n = f"pkg-{i:05d}"
            pkgs[f"node_modules/{n}"] = {"version": f"1.0.{i}", "resolved": f"https://registry.npmjs.org/{n}/-/{n}-1.0.{i}.tgz",
                                         "integrity": "sha512-" + "a" * 86, "dependencies": {"ms": "^2.1.3"}}
        text = json.dumps({"name": "big", "lockfileVersion": 3, "requires": True, "packages": pkgs}, indent=2)
        self.write("package-lock.json", text)
        t0 = time.monotonic()
        got = lockfiles.parse(self.root, "package-lock.json")
        elapsed = time.monotonic() - t0
        self.assertEqual(len(got), 12000)
        lines = text.splitlines()
        self.assertEqual(got[-1][1:], ("pkg-11999", "1.0.11999", "package-lock.json",
                                       lines.index('    "node_modules/pkg-11999": {') + 1))
        self.assertLess(elapsed, 2.0)

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("package-lock.json", [
            "", "   ", "{", '{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}', "[]", "null", "42",
            '"str"', '{"packages": []}', '{"packages": "abc"}', '{"packages": {"node_modules/x": null}}',
            '{"packages": {"node_modules/x": ["1.0.0"]}}', '{"dependencies": "x"}', '{"dependencies": [1, 2]}',
            '{"dependencies": {"a": {"version": "1.0.0", "dependencies": ["x"]}}}', "\x00\xff garbage",
        ])
        self.assertEqual(self.pkgs("package-lock.json", "{}"), [])
        self.assertEqual(self.pkgs("package-lock.json", '{"packages": {}, "dependencies": {}}'), [])


# --------------------------------------------------------------------------- yarn


class YarnLock(LockfileCase):
    CLASSIC = D('''\
        # THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
        # yarn lockfile v1


        "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
          version "7.12.13"
          resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826b"
          integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==
          dependencies:
            "@babel/highlight" "^7.12.13"

        "@babel/highlight@^7.12.13":
          version "7.13.10"
          resolved "https://registry.yarnpkg.com/@babel/highlight/-/highlight-7.13.10.tgz#a8b2a66f"

        lodash@^4.17.15, lodash@^4.17.19, lodash@^4.17.20:
          version "4.17.21"
          resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c5"

        js-tokens@^4.0.0:
          version "4.0.0"
        ''')
    BERRY = D('''\
        # This file is generated by running "yarn install" inside your project.
        # Manual changes might be lost - proceed with caution!

        __metadata:
          version: 6
          cacheKey: 8

        "@babel/core@npm:^7.0.0, @babel/core@npm:^7.1.0":
          version: 7.2.0
          resolution: "@babel/core@npm:7.2.0"
          dependencies:
            debug: ^4.1.0
          checksum: 2a8e3f1a
          languageName: node
          linkType: hard

        "debug@npm:^4.1.0":
          version: 4.3.4
          resolution: "debug@npm:4.3.4"
          dependencies:
            ms: 2.1.2
          peerDependenciesMeta:
            supports-color:
              optional: true
          checksum: 3dbad1d7
          languageName: node
          linkType: hard

        "ms@npm:2.1.2":
          version: 2.1.2
          resolution: "ms@npm:2.1.2"
          checksum: 673cdb2c
          languageName: node
          linkType: hard

        "__internal@npm:1.0.0":
          version: 1.0.0
          resolution: "__internal@npm:1.0.0"
        ''')

    def test_classic(self):
        got = self.full("yarn.lock", self.CLASSIC)
        self.assertEqual([x[:3] for x in got], [
            ("npm", "@babel/code-frame", "7.12.13"), ("npm", "@babel/highlight", "7.13.10"),
            ("npm", "lodash", "4.17.21"), ("npm", "js-tokens", "4.0.0")])
        headers = [i for i, ln in enumerate(self.CLASSIC.splitlines(), 1) if ln.endswith(":") and not ln.startswith(" ")]
        self.assertEqual([x[4] for x in got], headers)  # header line of each entry
        self.assertEqual(headers[0], 5)

    def test_classic_crlf_line_endings(self):
        self.assertEqual(self.pkgs("yarn.lock", self.CLASSIC.replace("\n", "\r\n"))[2], ("npm", "lodash", "4.17.21"))

    def test_berry_multi_specifier_quoted_and_dunder_skipped(self):
        self.assertEqual(self.pkgs("yarn.lock", self.BERRY), [
            ("npm", "@babel/core", "7.2.0"), ("npm", "debug", "4.3.4"), ("npm", "ms", "2.1.2")])

    def test_classic_npm_alias(self):
        lock = D('''\
            "string-width-cjs@npm:string-width@^4.2.0":
              version "4.2.3"
              resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#269c7117"
            ''')
        self.assertEqual(self.pkgs("yarn.lock", lock), [("npm", "string-width", "4.2.3")])

    def test_berry_npm_alias(self):
        lock = D('''\
            "string-width-cjs@npm:string-width@^4.2.0":
              version: 4.2.3
              resolution: "string-width@npm:4.2.3"
              languageName: node
              linkType: hard
            ''')
        self.assertEqual(self.pkgs("yarn.lock", lock), [("npm", "string-width", "4.2.3")])

    def test_berry_patch_entry_uses_package_name(self):
        lock = D('''\
            "resolve@patch:resolve@^1.20.0#~builtin<compat/resolve>, resolve@patch:resolve@^1.22.1#~builtin<compat/resolve>":
              version: 1.22.1
              resolution: "resolve@patch:resolve@npm%3A1.22.1#~builtin<compat/resolve>::version=1.22.1&hash=c3c19d"
              languageName: node
              linkType: hard

            "@types/node@patch:@types/node@npm%3A20.11.5#./.yarn/patches/node.patch::locator=app%40workspace%3A.":
              version: 20.11.5
              resolution: "@types/node@patch:@types/node@npm%3A20.11.5#./.yarn/patches/node.patch::version=20.11.5"
            ''')
        self.assertEqual(self.pkgs("yarn.lock", lock), [("npm", "resolve", "1.22.1"), ("npm", "@types/node", "20.11.5")])

    def test_berry_workspace_entry_not_reported(self):
        lock = D('''\
            "my-app@workspace:.":
              version: 0.0.0-use.local
              resolution: "my-app@workspace:."
              languageName: unknown
              linkType: soft

            "ms@npm:2.1.2":
              version: 2.1.2
              resolution: "ms@npm:2.1.2"
            ''')
        self.assertEqual(self.pkgs("yarn.lock", lock), [("npm", "ms", "2.1.2")])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("yarn.lock", [
            "", "\n\n", '  version "1.0.0"\n', "lodash@^4:\n", "lodash@^4:\n  resolved x\n\nms@2:\n",
            '"@":\n  version "1.0.0"\n', ":\n  version\n", "\x00\xff garbage:\n  version: \n",
        ])
        # a version line without a header is ignored; a header without version does not leak into the next
        self.assertEqual(self.pkgs("yarn.lock", '  version "1.0.0"\nlodash@^4:\n  resolved "x"\n\nms@^2:\n  version "2.1.3"\n'),
                         [("npm", "ms", "2.1.3")])


# --------------------------------------------------------------------------- pnpm


class PnpmLock(LockfileCase):
    def test_v6_keys(self):
        lock = D('''\
            lockfileVersion: '6.0'

            settings:
              autoInstallPeers: true
              excludeLinksFromLockfile: false

            dependencies:
              react-dom:
                specifier: ^17.0.2
                version: 17.0.2(react@17.0.2)

            devDependencies:
              '@babel/core':
                specifier: ^7.2.0
                version: 7.2.0

            packages:

              /@babel/core@7.2.0:
                resolution: {integrity: sha512-xxx}
                engines: {node: '>=6.9.0'}
                dev: true

              /js-tokens@4.0.0:
                resolution: {integrity: sha512-yyy}

              /loose-envify@1.4.0:
                resolution: {integrity: sha512-zzz}
                hasBin: true
                dependencies:
                  js-tokens: 4.0.0

              /react-dom@17.0.2(react@17.0.2):
                resolution: {integrity: sha512-aaa}
                peerDependencies:
                  react: 17.0.2
                dependencies:
                  loose-envify: 1.4.0
                  react: 17.0.2

              /react@17.0.2:
                resolution: {integrity: sha512-bbb}

              /@scope/peer-user@1.0.0(@babel/core@7.2.0)(react@17.0.2):
                resolution: {integrity: sha512-ccc}

              /local-lib@file:packages/local-lib:
                resolution: {directory: packages/local-lib, type: directory}
            ''')
        got = self.full("pnpm-lock.yaml", lock)
        self.assertEqual([x[:3] for x in got], [
            ("npm", "@babel/core", "7.2.0"), ("npm", "js-tokens", "4.0.0"), ("npm", "loose-envify", "1.4.0"),
            ("npm", "react-dom", "17.0.2"), ("npm", "react", "17.0.2"), ("npm", "@scope/peer-user", "1.0.0")])
        self.assertEqual(got[0][4], lock.splitlines().index("  /@babel/core@7.2.0:") + 1)

    def test_v9_keys_packages_and_snapshots_deduped(self):
        lock = D('''\
            lockfileVersion: '9.0'

            settings:
              autoInstallPeers: true
              excludeLinksFromLockfile: false

            importers:

              .:
                dependencies:
                  react-dom:
                    specifier: ^17.0.2
                    version: 17.0.2(react@17.0.2)

            packages:

              '@babel/core@7.2.0':
                resolution: {integrity: sha512-xxx}

              js-tokens@4.0.0:
                resolution: {integrity: sha512-yyy}

              react-dom@17.0.2:
                resolution: {integrity: sha512-aaa}
                peerDependencies:
                  react: 17.0.2

              react@17.0.2:
                resolution: {integrity: sha512-bbb}

            snapshots:

              '@babel/core@7.2.0': {}

              js-tokens@4.0.0: {}

              react-dom@17.0.2(react@17.0.2):
                dependencies:
                  react: 17.0.2

              react@17.0.2: {}

              '@types/only-in-snapshots@1.0.0': {}
            ''')
        self.assertEqual(self.pkgs("pnpm-lock.yaml", lock), [
            ("npm", "@babel/core", "7.2.0"), ("npm", "js-tokens", "4.0.0"), ("npm", "react-dom", "17.0.2"),
            ("npm", "react", "17.0.2"), ("npm", "@types/only-in-snapshots", "1.0.0")])

    def test_v5_slash_keys_without_peers(self):
        lock = "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: x}\n" \
               "\n  /@babel/core/7.2.0:\n    resolution: {integrity: y}\n    dev: true\n"
        self.assertEqual(self.pkgs("pnpm-lock.yaml", lock), [("npm", "lodash", "4.17.21"), ("npm", "@babel/core", "7.2.0")])

    def test_v5_peer_suffix(self):
        lock = "lockfileVersion: 5.4\n\npackages:\n\n  /react-dom/17.0.2_react@17.0.2:\n    resolution: {integrity: x}\n" \
               "\n  /@testing-library/react/12.1.5_react-dom@17.0.2+react@17.0.2:\n    resolution: {integrity: y}\n"
        self.assertEqual(self.pkgs("pnpm-lock.yaml", lock), [("npm", "react-dom", "17.0.2"),
                                                             ("npm", "@testing-library/react", "12.1.5")])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("pnpm-lock.yaml", [
            "", "packages:\n", "packages:\n  \n", "packages: {}\n", "packages:\n  /:\n  '@':\n  @/1:\n",
            "packages:\n  github.com/user/repo/abc123:\n    resolution: {tarball: x}\n", "\x00\xff:\n  x@1:\n",
        ])
        self.assertEqual(self.pkgs("pnpm-lock.yaml", "importers:\n  lodash@4.17.21:\n    x: 1\n"), [])


# --------------------------------------------------------------------------- bun


class BunLock(LockfileCase):
    def test_bun_lock(self):
        lock = D('''\
            {
              "lockfileVersion": 1,
              "workspaces": {
                "": {
                  "name": "my-app",
                  "dependencies": {
                    "lodash": "^4.17.21",
                    "string-width-cjs": "npm:string-width@^4.2.0",
                  },
                  "devDependencies": {
                    "@types/node": "^20.0.0",
                  },
                },
                "packages/lib": {
                  "name": "@acme/lib",
                  "version": "0.1.0",
                },
              },
              "packages": {
                "@acme/lib": ["@acme/lib@workspace:packages/lib"],

                "@types/node": ["@types/node@20.11.5", "", { "dependencies": { "undici-types": "~5.26.4" } }, "sha512-aaa"],

                "chalk/ansi-styles": ["ansi-styles@4.3.0", "", {}, "sha512-bbb"],

                "gitdep": ["gitdep@github:user/gitdep#abc123", {}],

                "lodash": ["lodash@4.17.21", "", {}, "sha512-ccc"],

                "string-width-cjs": ["string-width@4.2.3", "", { "dependencies": {} }, "sha512-ddd"],

                "undici-types": ["undici-types@5.26.5", "", {}, "sha512-eee"],
              }
            }
            ''')
        self.assertEqual(self.pkgs("bun.lock", lock), [
            ("npm", "@types/node", "20.11.5"), ("npm", "ansi-styles", "4.3.0"), ("npm", "lodash", "4.17.21"),
            ("npm", "string-width", "4.2.3"), ("npm", "undici-types", "5.26.5")])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("bun.lock", ["", "{", '  "x": [', '  "x": ["@1.0.0"]', '  "x": ["a@"]', "\x00\xff"])


# --------------------------------------------------------------------------- package.json


class PackageJson(LockfileCase):
    def test_only_exact_versions(self):
        pkg = {
            "name": "app", "version": "1.0.0",
            "dependencies": {"react": "18.2.0", "lodash": "^4.17.21", "axios": "=1.6.0", "next": "14.0.0-canary.1",
                             "left-pad": "~1.3.0", "local": "file:../local", "gh": "github:user/repo", "star": "*",
                             "tag": "latest", "x": "1.x", "hyphen": "1.2.3 - 2.0.0",
                             "either": "1.2.3 || 1.2.4", "build": "1.0.0+build.7", "num": 1},
            "devDependencies": {"typescript": "5.3.3", "jest": ">=29"},
            "optionalDependencies": {"fsevents": "2.3.3"},
            "peerDependencies": {"react-dom": "18.2.0"},
            "overrides": {"semver": "7.5.2"},
        }
        self.assertEqual(self.pkgs("package.json", json.dumps(pkg, indent=2)), [
            ("npm", "react", "18.2.0"), ("npm", "axios", "1.6.0"), ("npm", "next", "14.0.0-canary.1"),
            ("npm", "build", "1.0.0+build.7"), ("npm", "typescript", "5.3.3"), ("npm", "fsevents", "2.3.3")])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("package.json", [
            "", "{", "[]", "null", '{"dependencies": null}', '{"dependencies": ["a"]}', '{"dependencies": "x"}',
            '{"dependencies": {"a": null, "b": {"version": "1.0.0"}}}', "\x00\xff",
        ])
        self.assertEqual(self.pkgs("package.json", '{"dependencies": {"a": null, "b": "1.0.0"}}'), [("npm", "b", "1.0.0")])


# --------------------------------------------------------------------------- requirements*.txt


class Requirements(LockfileCase):
    REQ = D('''\
        # Production deps
        -r requirements-base.txt
        -c constraints.txt
        --index-url https://pypi.org/simple
        Django==3.2.0
        requests>=2.25
        flask[async,dotenv]==2.0.1  # web framework
        urllib3 == 1.26.5
        numpy==1.21.0; python_version < "3.10"
        pywin32==301 ; sys_platform == "win32"
        cryptography==3.4.7 \\
            --hash=sha256:0f1212a66329c80d68aeeefda81fcc1e2ce2cac21cd0e1e1d15e8a2ba5e0f9ac \\
            --hash=sha256:1e056c28420c072c5e3cb36e2b23ee55e260cb04eee08f702e0edfec3fb51959
        idna==3.2 --hash=sha256:14475042e284991034cb48e06f6851428fb14c4dc953acd9be9a5e95c7b6dd7a
        -e git+https://github.com/org/proj.git@v1.0#egg=proj
        -e .
        ./local/pkg
        https://files.example.com/pkg-1.0-py3-none-any.whl
        mypkg @ https://files.example.com/mypkg-2.0.tar.gz
        git+https://github.com/org/other.git@v2.0#egg=other
        pkg-with-epoch==1!2.0
        attrs===21.2.0
        # commented==1.0.0
        six~=1.16
        black!=22.1.0
        zope.interface==5.4.0
        backports.zoneinfo==0.2.1
        Sphinx_RTD-theme==1.0.0rc1
        ''')

    def test_pins_extras_markers_hashes_and_ignored_lines(self):
        got = self.full("requirements.txt", self.REQ)
        self.assertEqual([x[:3] for x in got], [
            ("PyPI", "Django", "3.2.0"), ("PyPI", "flask", "2.0.1"), ("PyPI", "urllib3", "1.26.5"),
            ("PyPI", "numpy", "1.21.0"), ("PyPI", "pywin32", "301"), ("PyPI", "cryptography", "3.4.7"),
            ("PyPI", "idna", "3.2"), ("PyPI", "pkg-with-epoch", "1!2.0"), ("PyPI", "attrs", "21.2.0"),
            ("PyPI", "zope.interface", "5.4.0"), ("PyPI", "backports.zoneinfo", "0.2.1"),
            ("PyPI", "Sphinx_RTD-theme", "1.0.0rc1")])
        lines = self.REQ.splitlines()
        self.assertEqual(got[0][4], lines.index("Django==3.2.0") + 1)
        self.assertEqual(got[5][4], lines.index("cryptography==3.4.7 \\") + 1)

    def test_r_includes_are_not_followed_but_parsed_on_their_own(self):
        self.write("requirements-base.txt", "sqlalchemy==1.4.0\n")
        self.assertEqual(self.pkgs("requirements.txt", "-r requirements-base.txt\nalembic==1.7.0\n"), [("PyPI", "alembic", "1.7.0")])
        self.assertTrue(lockfiles.is_dependency_file("requirements-base.txt"))
        self.assertEqual([x[:3] for x in lockfiles.parse(self.root, "requirements-base.txt")], [("PyPI", "sqlalchemy", "1.4.0")])

    def test_variant_file_names_use_requirements_parser(self):
        for rel in ("requirements-dev.txt", "requirements_test.txt", "requirements.prod.txt", "sub/requirements-ci.txt"):
            with self.subTest(rel=rel):
                self.assertEqual(self.pkgs(rel, "pytest==7.4.0\n"), [("PyPI", "pytest", "7.4.0")])
        self.assertEqual(self.pkgs("requirements.in", "pytest==7.4.0\n"), [])

    def test_files_in_a_requirements_folder_use_requirements_parser(self):
        for rel in ("requirements/base.txt", "app/requirements/production.txt"):
            with self.subTest(rel=rel):
                self.assertTrue(lockfiles.is_dependency_file(rel))
                self.assertEqual(self.pkgs(rel, "-r base.txt\ndjango==4.2.0\n"), [("PyPI", "django", "4.2.0")])
        for rel in ("requirements/README.md", "docs/notes.txt", "requirements.txt/x.txt"):
            with self.subTest(rel=rel):
                self.assertFalse(lockfiles.is_dependency_file(rel))

    def test_includes_with_r_and_c_resolve_against_the_file_folder(self):
        self.write("app/requirements.txt", D('''\
            -r requirements/prod.txt
            --requirement=dev-requirements.txt
            -c ../constraints.txt  # shared pins
            --constraint  pins.txt
            -rcompact.txt
            -r https://example.com/remote.txt
            -e .
            django==4.2.0
            '''))
        self.assertEqual(lockfiles.requirement_includes(self.root, "app/requirements.txt"), [
            "app/requirements/prod.txt", "app/dev-requirements.txt", "constraints.txt", "app/pins.txt", "app/compact.txt"])

    def test_include_scan_is_linear(self):
        self.write("requirements.txt", "-r" + " " * 50000 + "\n")
        t = time.perf_counter()
        self.assertEqual(lockfiles.requirement_includes(self.root, "requirements.txt"), [])
        self.assertLess(time.perf_counter() - t, 0.5)

    def test_wildcard_pin_is_not_an_exact_version(self):
        self.assertEqual(self.pkgs("requirements.txt", "django==3.2.*\n"), [])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("requirements.txt", ["", "\n\n", "==1.0\n", "django==\n", "-\n", "[x]==1\n", "\\\n", "\x00\xff==1\n"])
        self.assertEqual(self.pkgs("requirements.txt", "==1.0\ndjango==\nflask==2.0\n"), [("PyPI", "flask", "2.0")])


# --------------------------------------------------------------------------- TOML lockfiles


class TomlLocks(LockfileCase):
    def test_poetry_lock(self):
        lock = D('''\
            # This file is automatically @generated by Poetry 1.8.2 and should not be changed by hand.

            [[package]]
            name = "certifi"
            version = "2024.2.2"
            description = "Python package for providing Mozilla's CA Bundle."
            optional = false
            python-versions = ">=3.6"
            files = [
                {file = "certifi-2024.2.2-py3-none-any.whl", hash = "sha256:dc383c07b76109f368f6106eee2b593b04a011ea4d55f652c6ca24a754d1cdd1"},
            ]

            [[package]]
            name = "jinja2"
            version = "2.10"
            description = "A very fast and expressive template engine."
            optional = false
            python-versions = "*"
            files = []

            [package.dependencies]
            MarkupSafe = ">=0.23"

            [package.extras]
            i18n = ["Babel (>=0.8)"]

            [[package]]
            name = "pytest"
            version = "8.0.0"
            description = "pytest: simple powerful testing with Python"
            optional = false
            python-versions = ">=3.8"
            files = []

            [metadata]
            lock-version = "2.0"
            python-versions = "^3.8"
            content-hash = "abc"
            ''')
        got = self.full("poetry.lock", lock)
        self.assertEqual([x[:3] for x in got], [("PyPI", "certifi", "2024.2.2"), ("PyPI", "jinja2", "2.10"), ("PyPI", "pytest", "8.0.0")])
        self.assertEqual(got[0][4], 3)  # line of the [[package]] header

    def test_uv_lock(self):
        lock = D('''\
            version = 1
            requires-python = ">=3.12"

            [[package]]
            name = "anyio"
            version = "4.4.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "idna" },
                { name = "sniffio" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/anyio-4.4.0.tar.gz", hash = "sha256:aaa", size = 1 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/anyio-4.4.0-py3-none-any.whl", hash = "sha256:bbb", size = 1 },
            ]

            [package.optional-dependencies]
            trio = [
                { name = "trio" },
            ]

            [[package]]
            name = "idna"
            version = "3.7"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "sniffio"
            version = "1.3.1"
            source = { registry = "https://pypi.org/simple" }
            ''')
        self.assertEqual(self.pkgs("uv.lock", lock), [("PyPI", "anyio", "4.4.0"), ("PyPI", "idna", "3.7"), ("PyPI", "sniffio", "1.3.1")])

    def test_uv_lock_local_project_not_reported(self):
        lock = D('''\
            version = 1

            [[package]]
            name = "my-project"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
                { name = "idna" },
            ]

            [package.metadata]
            requires-dist = [{ name = "idna", specifier = ">=3" }]

            [[package]]
            name = "idna"
            version = "3.7"
            source = { registry = "https://pypi.org/simple" }
            ''')
        self.assertEqual(self.pkgs("uv.lock", lock), [("PyPI", "idna", "3.7")])

    def test_uv_lock_virtual_path_and_directory_sources_not_reported(self):
        for source in ('{ virtual = "." }', '{ path = "libs/x-1.0.tar.gz" }', '{ directory = "../shared" }',
                       '{ editable = "packages/core" }'):
            with self.subTest(source=source):
                lock = f'version = 1\n\n[[package]]\nname = "local"\nversion = "0.1.0"\nsource = {source}\n\n' \
                       '[[package]]\nname = "idna"\nversion = "3.7"\nsource = { registry = "https://pypi.org/simple" }\n'
                self.assertEqual(self.pkgs("uv.lock", lock), [("PyPI", "idna", "3.7")])

    def test_pdm_lock(self):
        lock = D('''\
            # This file is @generated by PDM.
            # It is not intended for manual editing.

            [metadata]
            groups = ["default", "dev"]
            strategy = ["cross_platform", "inherit_metadata"]
            lock_version = "4.4.1"
            content_hash = "sha256:abc"

            [[package]]
            name = "certifi"
            version = "2024.2.2"
            requires_python = ">=3.6"
            summary = "Python package for providing Mozilla's CA Bundle."
            groups = ["default"]
            files = [
                {file = "certifi-2024.2.2.tar.gz", hash = "sha256:aaa"},
            ]

            [[package]]
            name = "pytest"
            version = "8.0.0"
            requires_python = ">=3.8"
            groups = ["dev"]
            dependencies = [
                "iniconfig",
                "packaging",
            ]
            ''')
        self.assertEqual(self.pkgs("pdm.lock", lock), [("PyPI", "certifi", "2024.2.2"), ("PyPI", "pytest", "8.0.0")])

    def test_cargo_lock_keeps_multiple_versions(self):
        lock = D('''\
            # This file is automatically @generated by Cargo.
            # It is not intended for manual editing.
            version = 3

            [[package]]
            name = "itoa"
            version = "1.0.10"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "b1a46d1a171d865aa5f83f92695765caa047a9b4cbae2cbf37dbd613a793fd4c"

            [[package]]
            name = "rand"
            version = "0.7.3"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            dependencies = [
             "rand_core 0.5.1",
            ]

            [[package]]
            name = "rand"
            version = "0.8.5"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "rand_core"
            version = "0.5.1"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            ''')
        self.assertEqual(self.pkgs("Cargo.lock", lock), [
            ("crates.io", "itoa", "1.0.10"), ("crates.io", "rand", "0.7.3"), ("crates.io", "rand", "0.8.5"),
            ("crates.io", "rand_core", "0.5.1")])

    def test_cargo_lock_local_crates_not_reported(self):
        lock = D('''\
            version = 3

            [[package]]
            name = "my-app"
            version = "0.1.0"
            dependencies = [
             "itoa",
            ]

            [[package]]
            name = "itoa"
            version = "1.0.10"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            ''')
        self.assertEqual(self.pkgs("Cargo.lock", lock), [("crates.io", "itoa", "1.0.10")])

    def test_field_order_and_first_value_wins(self):
        lock = '[[package]]\nversion = "1.0.0"\nname = "a"\n\n[package.dependencies]\nname = "other"\nversion = ">=9"\n'
        self.assertEqual(self.pkgs("poetry.lock", lock), [("PyPI", "a", "1.0.0")])

    def test_malformed_does_not_crash(self):
        for rel in ("poetry.lock", "uv.lock", "pdm.lock", "Cargo.lock"):
            with self.subTest(rel=rel):
                self.assertNoCrash(rel, ["", "[[package]]", '[[package]]\nname = "a"\n', '[[package]]\nversion = "1"\n',
                                         'name = "top"\nversion = "1"\n', "[[package\nname = \"x\"\n", "\x00\xff"])
                # incomplete packages are dropped, complete ones survive
                complete = '[[package]]\nname = "a"\n\n[[package]]\nname = "b"\nversion = "2"\nsource = "registry+https://x"\n'
                self.assertEqual(self.pkgs(rel, complete)[0][1:], ("b", "2"))
                self.assertEqual(self.pkgs(rel, 'name = "top"\nversion = "1"\n'), [])


# --------------------------------------------------------------------------- Pipfile.lock


class NonRegistrySources(LockfileCase):
    """Git and local-folder packages do not come from the registry: a private package that shares its name with a
    public one must not inherit the public one's advisories (or its MAL- record). npm v1 and Gemfile.lock already
    skip them; every other lockfile has to as well."""

    def test_npm_v3_git_and_local_tarball_entries_skipped(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"private-lib": "github:acme/private-lib", "vendored": "file:vendor/vendored-1.0.0.tgz"}},
            "node_modules/private-lib": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/acme/private-lib.git#0123abcd"},
            "node_modules/vendored": {"version": "1.0.0", "resolved": "file:vendor/vendored-1.0.0.tgz"},
            "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
        }}
        self.assertEqual(self.pkgs("package-lock.json", json.dumps(lock, indent=2)), [("npm", "lodash", "4.17.21")])

    def test_yarn_classic_git_github_and_tarball_entries_skipped(self):
        lock = D('''\
            # yarn lockfile v1


            "private-lib@git+ssh://git@github.com/acme/private-lib.git#v1.0.0":
              version "1.0.0"
              resolved "git+ssh://git@github.com/acme/private-lib.git#0123abcd"

            forked@github:acme/forked#main:
              version "2.0.0"
              resolved "https://codeload.github.com/acme/forked/tar.gz/0123abcd"

            shorthand@acme/shorthand:
              version "3.0.0"
              resolved "https://codeload.github.com/acme/shorthand/tar.gz/0123abcd"

            "tarball@https://example.com/tarball-1.0.0.tgz":
              version "1.0.0"
              resolved "https://example.com/tarball-1.0.0.tgz"

            lodash@^4.17.21:
              version "4.17.21"
            ''')
        self.assertEqual(self.pkgs("yarn.lock", lock), [("npm", "lodash", "4.17.21")])

    def test_yarn_berry_git_entry_skipped(self):
        lock = D('''\
            __metadata:
              version: 8

            "private-lib@git+ssh://git@github.com/acme/private-lib.git#commit=0123abcd":
              version: 1.0.0
              resolution: "private-lib@git+ssh://git@github.com/acme/private-lib.git#commit=0123abcd"

            "lodash@npm:^4.17.21":
              version: 4.17.21
              resolution: "lodash@npm:4.17.21"
            ''')
        self.assertEqual(self.pkgs("yarn.lock", lock), [("npm", "lodash", "4.17.21")])

    def test_poetry_git_directory_and_file_sources_skipped_private_index_kept(self):
        lock = D('''\
            [[package]]
            name = "private-lib"
            version = "1.0.0"
            optional = false
            python-versions = "*"
            files = []
            develop = false

            [package.source]
            type = "git"
            url = "https://github.com/acme/private-lib.git"
            reference = "HEAD"
            resolved_reference = "0123abcd"

            [[package]]
            name = "shared"
            version = "0.1.0"
            files = []
            develop = true

            [package.dependencies]
            requests = ">=2"

            [package.source]
            type = "directory"
            url = "../shared"

            [[package]]
            name = "vendored"
            version = "1.0.0"
            files = [
                {file = "vendored-1.0.0-py3-none-any.whl", hash = "sha256:aaa"},
            ]

            [package.source]
            type = "file"
            url = "vendor/vendored-1.0.0-py3-none-any.whl"

            [[package]]
            name = "internal-sdk"
            version = "2.1.0"
            files = []

            [package.source]
            type = "legacy"
            url = "https://pypi.acme.example/simple"
            reference = "acme"

            [[package]]
            name = "requests"
            version = "2.31.0"
            files = []
            ''')
        self.assertEqual(self.pkgs("poetry.lock", lock), [("PyPI", "internal-sdk", "2.1.0"), ("PyPI", "requests", "2.31.0")])

    def test_uv_git_source_skipped(self):
        lock = 'version = 1\n\n[[package]]\nname = "private-lib"\nversion = "1.0.0"\n' \
               'source = { git = "https://github.com/acme/private-lib?rev=v1#0123abcd" }\n\n' \
               '[[package]]\nname = "idna"\nversion = "3.7"\nsource = { registry = "https://pypi.org/simple" }\n'
        self.assertEqual(self.pkgs("uv.lock", lock), [("PyPI", "idna", "3.7")])

    def test_pdm_git_and_path_packages_skipped(self):
        lock = D('''\
            [[package]]
            name = "private-lib"
            version = "1.0.0"
            git = "https://github.com/acme/private-lib.git"
            ref = "main"
            revision = "0123abcd"
            groups = ["default"]

            [[package]]
            name = "shared"
            version = "0.1.0"
            path = "./libs/shared"
            editable = true
            groups = ["default"]

            [[package]]
            name = "certifi"
            version = "2024.2.2"
            files = [
                {file = "certifi-2024.2.2.tar.gz", hash = "sha256:aaa"},
            ]
            ''')
        self.assertEqual(self.pkgs("pdm.lock", lock), [("PyPI", "certifi", "2024.2.2")])

    def test_cargo_git_source_skipped(self):
        lock = D('''\
            version = 3

            [[package]]
            name = "bincode"
            version = "2.0.1"
            source = "git+https://github.com/acme/bincode.git?branch=patches#0123abcd"

            [[package]]
            name = "itoa"
            version = "1.0.10"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            ''')
        self.assertEqual(self.pkgs("Cargo.lock", lock), [("crates.io", "itoa", "1.0.10")])


class PipfileLock(LockfileCase):
    def test_default_and_develop(self):
        lock = {
            "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6, "requires": {"python_version": "3.9"},
                      "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True}]},
            "default": {
                "requests": {"hashes": ["sha256:aaa"], "index": "pypi", "version": "==2.25.1"},
                "urllib3": {"hashes": [], "markers": "python_version >= '2.7'", "version": "==1.26.5"},
                "mylib": {"editable": True, "path": "."},
                "gitdep": {"git": "https://github.com/x/gitdep.git", "ref": "abc"},
                "loose": {"version": "*"},
            },
            "develop": {"pytest": {"hashes": [], "version": "==6.2.2"}},
        }
        self.assertEqual(self.pkgs("Pipfile.lock", json.dumps(lock, indent=4)), [
            ("PyPI", "requests", "2.25.1"), ("PyPI", "urllib3", "1.26.5"), ("PyPI", "pytest", "6.2.2")])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("Pipfile.lock", [
            "", "{", "[]", "null", '{"default": null}', '{"default": ["x"]}', '{"default": {"x": "==1.0"}}',
            '{"default": {"x": {"version": null}}}', '{"default": {"x": {"version": 2}}}', "\x00\xff",
        ])
        self.assertEqual(self.pkgs("Pipfile.lock", '{"default": {"x": null, "y": {"version": "==1.0"}}}'), [("PyPI", "y", "1.0")])


# --------------------------------------------------------------------------- go.mod


class GoMod(LockfileCase):
    def test_require_blocks_single_line_indirect_and_other_directives(self):
        mod = D('''\
            module example.com/app

            go 1.21

            toolchain go1.21.5

            require (
            \tgithub.com/gin-gonic/gin v1.9.1
            \tgithub.com/google/uuid v1.5.0 // indirect
            \tgolang.org/x/net v0.0.0-20220722155237-a158d28d115b // indirect
            \tgithub.com/docker/docker v20.10.24+incompatible
            \texample.com/mod/v2 v2.3.0
            )

            require github.com/pkg/errors v0.9.1

            require golang.org/x/sys v0.15.0 // indirect

            require (
            \tgopkg.in/yaml.v3 v3.0.1 // indirect
            )

            exclude github.com/gin-gonic/gin v1.6.0

            retract v1.0.0

            retract (
            \tv1.0.1
            \t[v1.1.0, v1.1.9]
            )

            replace github.com/old/thing => github.com/new/thing v1.2.0

            replace (
            \texample.com/local => ../local
            \tgithub.com/a/b v1.0.0 => github.com/a/b v1.0.1
            )
            ''')
        got = self.full("go.mod", mod)
        self.assertEqual([x[:3] for x in got], [
            ("Go", "github.com/gin-gonic/gin", "v1.9.1"), ("Go", "github.com/google/uuid", "v1.5.0"),
            ("Go", "golang.org/x/net", "v0.0.0-20220722155237-a158d28d115b"),
            ("Go", "github.com/docker/docker", "v20.10.24+incompatible"), ("Go", "example.com/mod/v2", "v2.3.0"),
            ("Go", "github.com/pkg/errors", "v0.9.1"), ("Go", "golang.org/x/sys", "v0.15.0"), ("Go", "gopkg.in/yaml.v3", "v3.0.1")])
        self.assertEqual(got[0][4], mod.splitlines().index("\tgithub.com/gin-gonic/gin v1.9.1") + 1)

    def test_replace_directives_change_the_effective_module(self):
        mod = D('''\
            module example.com/app

            require (
            \tgolang.org/x/text v0.3.0
            \texample.com/local v0.0.0
            )

            replace golang.org/x/text v0.3.0 => golang.org/x/text v0.3.8

            replace example.com/local => ../local
            ''')
        self.assertEqual(self.pkgs("go.mod", mod), [("Go", "golang.org/x/text", "v0.3.8")])

    def test_replace_block_and_version_specific_replace(self):
        mod = D('''\
            module example.com/app

            require (
            \tgithub.com/a/b v1.0.0
            \tgithub.com/c/d v1.2.0
            \tgithub.com/e/f v0.1.0
            \tgithub.com/g/h v2.0.0+incompatible
            )

            replace (
            \tgithub.com/a/b => github.com/fork/b v1.0.5 // fork with the fix
            \tgithub.com/c/d v1.1.0 => github.com/c/d v1.1.9
            \tgithub.com/e/f => ./third_party/f
            )
            ''')
        got = self.full("go.mod", mod)
        self.assertEqual([x[:3] for x in got], [("Go", "github.com/fork/b", "v1.0.5"), ("Go", "github.com/c/d", "v1.2.0"),
                                                ("Go", "github.com/g/h", "v2.0.0+incompatible")])
        self.assertEqual(got[0][4], mod.splitlines().index("\tgithub.com/a/b => github.com/fork/b v1.0.5 // fork with the fix") + 1)

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("go.mod", ["", "require\n", "require (\n", "require (\n\tgithub.com/x\n", "require x y z\n",
                                      "require (\n\tgithub.com/a/b v1.0.0\n", "\x00\xff v1\n"])
        # unterminated block still yields what it has
        self.assertEqual(self.pkgs("go.mod", "require (\n\tgithub.com/a/b v1.0.0\n"), [("Go", "github.com/a/b", "v1.0.0")])


# --------------------------------------------------------------------------- Gemfile.lock


class GemfileLock(LockfileCase):
    def test_gem_specs_and_platform_suffix(self):
        lock = D('''\
            GEM
              remote: https://rubygems.org/
              specs:
                actionpack (6.1.4)
                  rack (~> 2.0, >= 2.0.9)
                nokogiri (1.13.10-x86_64-linux)
                  racc (~> 1.4)
                nokogiri (1.13.10-arm64-darwin)
                  racc (~> 1.4)
                racc (1.6.2)
                rack (2.2.3)
                rails-html-sanitizer (1.4.4)
                rake (13.0.6)

            PLATFORMS
              arm64-darwin
              x86_64-linux

            DEPENDENCIES
              nokogiri (>= 1.13)
              rake (~> 13.0)

            BUNDLED WITH
               2.4.10
            ''')
        got = self.full("Gemfile.lock", lock)
        self.assertEqual([x[:3] for x in got], [
            ("RubyGems", "actionpack", "6.1.4"), ("RubyGems", "nokogiri", "1.13.10"), ("RubyGems", "nokogiri", "1.13.10"),
            ("RubyGems", "racc", "1.6.2"), ("RubyGems", "rack", "2.2.3"), ("RubyGems", "rails-html-sanitizer", "1.4.4"),
            ("RubyGems", "rake", "13.0.6")])
        self.assertEqual(got[0][4], 4)

    def test_path_gems_not_reported(self):
        lock = D('''\
            GIT
              remote: https://github.com/rails/rails.git
              revision: 0f1e2d3c
              specs:
                rails (7.1.0.alpha)
                  actionpack (= 7.1.0.alpha)

            PATH
              remote: .
              specs:
                mygem (0.1.0)
                  rake

            GEM
              remote: https://rubygems.org/
              specs:
                rake (13.0.6)
            ''')
        self.assertEqual(self.pkgs("Gemfile.lock", lock), [("RubyGems", "rake", "13.0.6")])

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("Gemfile.lock", ["", "GEM\n  specs:\n", "    rails ()\n", "    (1.0)\n", "    rails (1.0\n", "\x00\xff"])


# --------------------------------------------------------------------------- composer.lock


class NugetLock(LockfileCase):
    LOCK = {"version": 1, "dependencies": {
        "net8.0": {
            "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1",
                                "contentHash": "ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A=="},
            "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},
            "Microsoft.Extensions.Logging": {"type": "CentralTransitive", "requested": "[8.0.0, )", "resolved": "8.0.0"},
            "MyCompany.Shared": {"type": "Project", "dependencies": {"Newtonsoft.Json": "[13.0.1, )"}},
        },
        "net8.0/linux-x64": {"System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"}},
    }}

    def test_packages_lock_json(self):
        got = self.full("src/App/packages.lock.json", json.dumps(self.LOCK, indent=2))
        self.assertEqual(sorted(set(x[:3] for x in got)), [
            ("NuGet", "Microsoft.Extensions.Logging", "8.0.0"), ("NuGet", "Newtonsoft.Json", "13.0.1"),
            ("NuGet", "System.Text.Json", "8.0.0")])
        self.assertTrue(lockfiles.is_dependency_file("src/App/packages.lock.json"))

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("packages.lock.json", ["", "{", "[]", '{"dependencies": []}', '{"dependencies": {"net8.0": []}}',
                                                  '{"dependencies": {"net8.0": {"A": "x"}}}', DEEP_JSON])


class ComposerLock(LockfileCase):
    def test_packages_and_packages_dev(self):
        lock = {
            "_readme": ["This file locks the dependencies of your project to a known state"],
            "content-hash": "abc",
            "packages": [
                {"name": "monolog/monolog", "version": "2.3.5", "source": {"type": "git", "reference": "fd4380d"},
                 "require": {"php": ">=7.2"}},
                {"name": "symfony/console", "version": "v5.4.0"},
                {"name": "laravel/framework", "version": "v8.83.27"},
                {"name": "acme/no-version"},
                {"version": "1.0.0"},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "9.5.10"},
                {"name": "mockery/mockery", "version": "1.4.4"},
            ],
            "aliases": [], "minimum-stability": "stable",
        }
        text = json.dumps(lock, indent=4)
        got = self.full("composer.lock", text)
        self.assertEqual([x[:3] for x in got], [
            ("Packagist", "monolog/monolog", "2.3.5"), ("Packagist", "symfony/console", "5.4.0"),
            ("Packagist", "laravel/framework", "8.83.27"), ("Packagist", "phpunit/phpunit", "9.5.10"),
            ("Packagist", "mockery/mockery", "1.4.4")])
        self.assertEqual(got[0][4], next(i for i, ln in enumerate(text.splitlines(), 1) if '"name": "monolog/monolog"' in ln))

    def test_malformed_does_not_crash(self):
        self.assertNoCrash("composer.lock", [
            "", "{", "[]", "null", '{"packages": null}', '{"packages": {}}', '{"packages": {"a": 1}}', '{"packages": [null]}',
            '{"packages": "x"}', '{"packages-dev": [1, 2]}', "\x00\xff",
        ])
        self.assertEqual(self.pkgs("composer.lock", '{"packages": [], "packages-dev": [{"name": "a/b", "version": "1.0"}]}'),
                         [("Packagist", "a/b", "1.0")])


# --------------------------------------------------------------------------- open_ranges


class OpenRanges(LockfileCase):
    def test_package_json_counts_open_specs(self):
        pkg = {"dependencies": {"a": "^1.0.0", "b": "1.2.3", "c": "file:../c", "d": "workspace:*", "e": "latest",
                                "f": "link:../f", "g": "=2.0.0", "h": "1.0.0-rc.1"},
               "devDependencies": {"i": "~2.0.0", "j": "3.0.0", "k": "*"},
               "optionalDependencies": {"l": "^1"}, "peerDependencies": {"m": "^1"}}
        self.assertEqual(self.ranges("package.json", json.dumps(pkg)), 4)  # a, e, i, k

    def test_requirements_counts_unpinned_lines(self):
        req = D('''\
            # comment
            django==3.2.0
            requests>=2.25
            flask
            numpy~=1.21
            black!=22.1.0
            attrs===21.2.0
            -r base.txt
            -e .
            --hash=sha256:abc
            pinned==1.0  # inline comment

            ''')
        self.assertEqual(self.ranges("requirements.txt", req), 4)  # requests, flask, numpy, black
        self.assertEqual(self.ranges("requirements-dev.txt", "pytest\n"), 1)

    def test_lines_that_are_not_requirements_are_not_open_versions(self):
        prose = "The system shall export reports.\nUsers can log in with SSO (single sign-on).\nflask\n"
        self.assertEqual(self.ranges("docs/functional-requirements.txt", prose), 1)
        self.assertEqual(self.ranges("requirements.txt", "requests [socks] >= 2\nnumpy; python_version<'3.8'\nDjango\n"), 3)

    def test_requirements_marker_with_equals_is_still_open(self):
        self.assertEqual(self.ranges("requirements.txt", 'requests>=2; python_version=="3.8"\n'), 1)
        self.assertEqual(self.ranges("requirements.txt", 'requests==2.31.0; python_version=="3.8"\n'), 0)

    def test_requirements_wildcard_pin_is_open(self):
        self.assertEqual(self.ranges("requirements.txt", "django==3.2.*\nflask==2.0.1\n"), 1)

    def test_bom_is_tolerated(self):
        self.write("requirements.txt", "flask\ndjango==3.2.0\n", encoding="utf-8-sig")
        self.assertEqual(lockfiles.open_ranges(self.root, "requirements.txt"), 1)
        self.write("package.json", '{"dependencies": {"a": "^1.0.0"}}', encoding="utf-8-sig")
        self.assertEqual(lockfiles.open_ranges(self.root, "package.json"), 1)

    def test_other_files_and_missing_files_return_zero(self):
        self.assertEqual(self.ranges("go.mod", "require (\n\tgithub.com/a/b v1.0.0\n)\n"), 0)
        self.assertEqual(self.ranges("poetry.lock", '[[package]]\nname = "a"\nversion = "1"\n'), 0)
        self.assertEqual(lockfiles.open_ranges(self.root, "package.json"), 0)
        self.assertEqual(lockfiles.open_ranges(self.root, "requirements.txt"), 0)

    def test_invalid_json_returns_zero(self):
        for content in ("", "{", "not json", '{"dependencies": {"a": 1, "b": null}}', '{"dependencies": null}'):
            with self.subTest(content=content):
                self.assertEqual(self.ranges("package.json", content), 0)

    def test_package_json_with_unexpected_shapes_does_not_crash(self):
        for content in ("[]", "null", '"x"', '{"dependencies": ["a"]}', '{"devDependencies": "x"}'):
            with self.subTest(content=content):
                self.assertEqual(self.ranges("package.json", content), 0)

    def test_package_json_deeply_nested_does_not_crash(self):
        self.assertEqual(self.ranges("package.json", DEEP_JSON), 0)


# --------------------------------------------------------------------------- lowest version of a range (DEP004)


class PythonFloor(unittest.TestCase):
    def test_specs_with_a_floor(self):
        cases = [
            # requirement, (floor, upper, upper inclusive)
            ("Pillow>=10", ("10", None, False)),
            ("Pillow >= 10", ("10", None, False)),
            ("foo[bar]>=1.2", ("1.2", None, False)),
            ("foo [bar, baz] >= 1.2 , < 2", ("1.2", "2", False)),
            ("requests~=2.25", ("2.25", "3", False)),
            ("requests~=2.25.1", ("2.25.1", "2.26", False)),
            ("Django==3.2.*", ("3.2", "3.3", False)),
            ("Django==10.*", ("10", "11", False)),
            ("Django>=3.2,<=3.2.10", ("3.2", "3.2.10", True)),
            ("Django>=3.2,<4,<3.9", ("3.2", "3.9", False)),
            ("pkg>=1.0,>=1.5", ("1.5", None, False)),
            ("pkg>=1.0,!=1.2", ("1.0", None, False)),
            ("pkg>=2.0rc1", ("2.0rc1", None, False)),
            ("pkg (>=1.0)", ("1.0", None, False)),
            ('pkg>=1; python_version < "3.8"', ("1", None, False)),
            ("pkg==1.2.3", ("1.2.3", "1.2.3", True)),
        ]
        for req, want in cases:
            with self.subTest(req=req):
                got = lockfiles.python_floor(req)
                self.assertIsNotNone(got)
                self.assertEqual(got[3:], want)

    def test_name_extras_and_spec_as_written(self):
        self.assertEqual(lockfiles.python_floor("foo [bar, baz] >= 1.2 , < 2")[:3], ("foo", "[bar,baz]", ">= 1.2 , < 2"))
        self.assertEqual(lockfiles.python_floor("my.pkg_name-x>=1")[:3], ("my.pkg_name-x", "", ">=1"))
        self.assertEqual(lockfiles.python_floor("pkg (>=1.0)")[2], ">=1.0")

    def test_specs_without_a_floor(self):
        for req in ["pkg", "pkg>1.0", "pkg<2", "pkg<=2", "pkg!=1.0", "pkg>=1.0,>1.5", "pkg>=1.0,!=1.0", "pkg>=1.0,!=1.*",
                    "pkg>=0", "pkg>=0.0", "pkg>=2,<1", "pkg>=1.0,<1.0", "pkg>=1.*", "pkg>=abc", "pkg>=1!2.0",
                    "pkg===foobar", "pkg @ https://example.com/pkg-1.0.whl", "pkg[x] @ git+https://example.com/x.git",
                    "git+https://example.com/x.git", "./local", "../sibling", "https://example.com/x.tgz", "-e .", "",
                    "pkg>=", "pkg >= 1 2"]:
            with self.subTest(req=req):
                self.assertIsNone(lockfiles.python_floor(req))


class NpmFloor(unittest.TestCase):
    def test_specs_with_a_floor(self):
        cases = [
            ("^1.6.0", ("1.6.0", "2.0.0", False)),
            ("^0.2.3", ("0.2.3", "0.3.0", False)),
            ("^0.0.3", ("0.0.3", "0.0.4", False)),
            ("^1.2", ("1.2.0", "2.0.0", False)),
            ("^1", ("1.0.0", "2.0.0", False)),
            ("^0.2", ("0.2.0", "0.3.0", False)),
            ("^1.x", ("1.0.0", "2.0.0", False)),
            ("~1.2.3", ("1.2.3", "1.3.0", False)),
            ("~1.2", ("1.2.0", "1.3.0", False)),
            ("~1", ("1.0.0", "2.0.0", False)),
            ("~>1.2", ("1.2.0", "1.3.0", False)),
            (">=1.2.3", ("1.2.3", None, False)),
            (">=1.2", ("1.2.0", None, False)),
            (">= 1.2.3 < 2", ("1.2.3", "2.0.0", False)),
            (">=1.2.3 <2.0.0", ("1.2.3", "2.0.0", False)),
            (">=1.2.3 <=1.9.0", ("1.2.3", "1.9.0", True)),
            (">=1.2.3 <=1.9", ("1.2.3", "1.10.0", False)),
            ("^1.2.3 <1.5", ("1.2.3", "1.5.0", False)),
            ("1.2.x", ("1.2.0", "1.3.0", False)),
            ("1.2.*", ("1.2.0", "1.3.0", False)),
            ("1.x", ("1.0.0", "2.0.0", False)),
            ("1.x.x", ("1.0.0", "2.0.0", False)),
            ("1.2", ("1.2.0", "1.3.0", False)),
            ("1", ("1.0.0", "2.0.0", False)),
            ("=1.2", ("1.2.0", "1.3.0", False)),
            ("1.2.3 - 2.3.4", ("1.2.3", "2.3.4", True)),
            ("1.2 - 2.3", ("1.2.0", "2.4.0", False)),
            ("^1.2.3-beta.1", ("1.2.3-beta.1", "2.0.0", False)),
            ("v1.2.3", ("1.2.3", "1.2.3", True)),
            (" ^1.6.0 ", ("1.6.0", "2.0.0", False)),
        ]
        for spec, want in cases:
            with self.subTest(spec=spec):
                self.assertEqual(lockfiles.npm_floor(spec), want)

    def test_specs_without_a_floor(self):
        for spec in ["*", "", "x", "X", "latest", "next", "beta", ">=1 || <0.5", "^1.0.0 || ^2.0.0", ">1.2.3", "<2.0.0",
                     "<=2", ">1.2.3 <2", ">=1.2.3 >1.5.0", "^0.0", "^0.x", ">=0.0.0", "0.x", "^1.0.0 <1.0.0",
                     "git+https://example.com/x.git", "git://example.com/x.git", "github:user/repo", "user/repo",
                     "file:../x", "link:../x", "workspace:*", "workspace:^1.0.0", "portal:../x", "catalog:",
                     "https://example.com/x.tgz", "npm:foo", "1.2.3.4", "^abc", "<*", "1.2.3 - x", "abc - 1.2.3"]:
            with self.subTest(spec=spec):
                self.assertIsNone(lockfiles.npm_floor(spec))


class HostileRanges(unittest.TestCase):
    """A hostile repository chooses the text of its manifests: a range must not make the scan hang."""

    def assertFast(self, fn, arg, limit=1.0):
        start = time.perf_counter()
        fn(arg)
        self.assertLess(time.perf_counter() - start, limit, arg[:40])

    def test_long_version_that_fails_to_parse_is_linear(self):
        # The old version pattern backtracked exponentially on a long run of letters that ends in a bad character.
        self.assertFast(lockfiles.python_floor, "foo>=1" + "a" * 26 + "*")
        self.assertFast(lockfiles.npm_floor, "^1.2.3-" + "a" * 26 + ".")
        self.assertIsNone(lockfiles.python_floor("foo>=1" + "a" * 26 + "*"))
        self.assertIsNone(lockfiles.npm_floor("^1.2.3-" + "a" * 26 + "."))
        # what the pattern accepts did not change
        self.assertEqual(lockfiles.python_floor("foo>=1.0.0rc1")[3], "1.0.0rc1")
        self.assertEqual(lockfiles.python_floor("foo>=1.0+local.7")[3], "1.0+local.7")
        self.assertEqual(lockfiles.npm_floor(">=1.0.0-20210101-abc"), ("1.0.0-20210101-abc", None, False))

    def test_long_poetry_caret_that_fails_to_parse_is_linear(self):
        for spec in ("^" + "1" * 20000 + "!", "~" + "1" * 20000 + "!", "^1.2." + "3" * 20000 + "!"):
            self.assertFast(lockfiles._poetry_pep440, spec)
            self.assertIsNone(lockfiles.python_floor("x" + lockfiles._poetry_pep440(spec)))
        self.assertEqual(lockfiles._poetry_pep440("^1.2.3b1"), ">=1.2.3b1,<2.0.0")
        self.assertEqual(lockfiles._poetry_pep440("~=1.4"), "~=1.4")

    def test_long_whitespace_in_requirements_is_linear(self):
        # Cutting the pip options (--hash...) off a line was quadratic in a long run of spaces.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "requirements.txt").write_text("foo>=1.0" + " " * 60000 + "x\nbar>=2.0   --hash=sha256:abc\n", "utf-8")
        start = time.perf_counter()
        got = lockfiles.ranges(root, "requirements.txt")
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertEqual([(r.name, r.req) for r in got], [("bar", "bar>=2.0")])


class PyprojectRequirements(unittest.TestCase):
    def test_project_dependencies_and_optional_dependencies(self):
        doc = D('''\
            [build-system]
            requires = ["setuptools>=40"]

            [project]
            name = "sample"
            description = """
            dependencies = ["not-a-dependency>=1"]
            """
            version = "1.0"  # comment
            authors = [{name = "A", email = "a@example.com"}]
            dependencies = [
                "Pillow>=10",  # imaging
                'foo[bar,baz]>=1.2; python_version < "3.10"',
                "quote\\"d>=1",
                # "commented>=1",
                "trailing>=2",
            ]
            optional-dependencies.extra = ["dotted>=3"]

            [project.optional-dependencies]
            dev = ["pytest>=7", "black[jupyter]>=23.1"]
            docs = [
              "sphinx>=5",
            ]

            [tool.hatch.envs.default]
            dependencies = ["other-table>=1"]

            [tool.poetry.dependencies]
            requests = "^2.28"

            [[tool.custom]]
            when = 1979-05-27 07:32:00
            ''')
        self.assertEqual(lockfiles.pyproject_requirements(doc), [
            ("Pillow>=10", 12), ('foo[bar,baz]>=1.2; python_version < "3.10"', 13), ('quote"d>=1', 14),
            ("trailing>=2", 16), ("dotted>=3", 18), ("pytest>=7", 21), ("black[jupyter]>=23.1", 21), ("sphinx>=5", 23)])

    def test_other_toml_shapes(self):
        cases = [
            ('[project]\noptional-dependencies = { dev = ["a>=1"], test = ["b>=2"] }\ndependencies=["c>=3"]\n',
             [("a>=1", 2), ("b>=2", 2), ("c>=3", 3)]),
            ('project.dependencies = ["root>=1"]\n[project."optional-dependencies"]\nq = [\'quoted>=1\']\n',
             [("root>=1", 1), ("quoted>=1", 3)]),
            ("[ project ]\ndependencies = ['''multi>=1''', \"\"\"\nnl>=2\"\"\"]\n", [("multi>=1", 2), ("\nnl>=2", 2)]),
            ('[project]\r\ndependencies = [\r\n  "crlf>=1",\r\n]\r\n', [("crlf>=1", 3)]),
            ('[project]\nx = """a""""\ny = """b\\"""c"""\ndependencies = ["after>=1"]\n', [("after>=1", 4)]),
            ('[project]\ndependencies = ["caf\\u00e9>=1", "tab\\there>=1"]\n', [("caf\u00e9>=1", 2), ("tab\there>=1", 2)]),
            ('[project]\ndependencies = []\n', []),
            ('[tool.x]\ndependencies = ["a>=1"]\n[project]\nname = "x"\n', []),
            ("[project]\n'dependencies' = ['literal-key>=1']\n", [("literal-key>=1", 2)]),
            ('[project]\nname = "x" junk\nx = \r\ndependencies = ["after-junk>=1"]\n', [("after-junk>=1", 4)]),
            ('[project]\noptional-dependencies = { dev = ["lost>=1"] junk }\ndependencies = ["kept>=1"]\n', [("kept>=1", 3)]),
        ]
        for doc, want in cases:
            with self.subTest(doc=doc[:50]):
                self.assertEqual(lockfiles.pyproject_requirements(doc), want)

    def test_dependency_groups_and_uv_dev_dependencies(self):
        doc = D('''\
            [dependency-groups]
            test = ["pytest>=8", "coverage[toml]>=7.4"]
            dev = [{include-group = "test"}, "ruff>=0.4"]

            [tool.uv]
            dev-dependencies = ["mypy>=1.8"]

            [tool.uv.sources]
            mylib = { path = "../mylib" }
            ''')
        self.assertEqual(lockfiles.pyproject_requirements(doc), [
            ("pytest>=8", 2), ("coverage[toml]>=7.4", 2), ("ruff>=0.4", 3), ("mypy>=1.8", 6)])

    def test_malformed_lines_are_skipped_not_fatal(self):
        doc = D('''\
            [project]
            name = "unterminated
            dependencies = [
             "a>=1",
             not toml at all
            ]
            weird = ]
            [project.optional-dependencies
            [project.optional-dependencies]
            z = ["z>=1"]
            ''')
        self.assertEqual(lockfiles.pyproject_requirements(doc), [("a>=1", 4), ("z>=1", 10)])
        deep = '[project]\ndependencies = ' + "[" * 50 + '"deep>=1"' + "]" * 50 + '\n[project.optional-dependencies]\nok = ["ok>=1"]\n'
        self.assertEqual(lockfiles.pyproject_requirements(deep), [("ok>=1", 4)])
        for doc in ["[" * 100000, '[project]\ndependencies = ["a>=1"', '[project]\ndependencies = """x', "\x00\xff", "= 1",
                    '[project]\ndependencies = ["\\U99999999"]\n', "[project]\n" + "dependencies = [" * 5000]:
            with self.subTest(doc=doc[:40]):
                self.assertIsInstance(lockfiles.pyproject_requirements(doc), list)


class Ranges(LockfileCase):
    def got(self, rel, content):
        self.write(rel, content)
        return [(r.eco, r.name, r.spec, r.req, r.floor, r.upper, r.inclusive, r.line) for r in lockfiles.ranges(self.root, rel)]

    def test_requirements_txt(self):
        req = D('''\
            # comment
            Pillow>=10
            django==4.2.1
            -r base.txt
            -e .
            requests>=2.25 \\
                --hash=sha256:abc
            flask
            numpy~=1.21  # inline
            foo[bar] >= 1.2, < 2 ; python_version < "3.12"
            pinned (==1.0)
            https://example.com/x.whl
            ''')
        self.assertEqual(self.got("requirements.txt", req), [
            ("PyPI", "Pillow", ">=10", "Pillow>=10", "10", None, False, 2),
            ("PyPI", "requests", ">=2.25", "requests>=2.25", "2.25", None, False, 6),
            ("PyPI", "numpy", "~=1.21", "numpy~=1.21", "1.21", "2", False, 9),
            ("PyPI", "foo", ">= 1.2, < 2", "foo[bar] >= 1.2, < 2", "1.2", "2", False, 10),
            ("PyPI", "pinned", "==1.0", "pinned (==1.0)", "1.0", "1.0", True, 11)])
        self.assertTrue(lockfiles.ranges(self.root, "requirements.txt")[-1].exact)
        self.assertFalse(lockfiles.ranges(self.root, "requirements.txt")[0].exact)

    def test_package_json(self):
        pkg = '{\n  "name": "app",\n  "dependencies": {\n    "axios": "^1.6.0",\n    "react": "18.2.0",\n' \
              '    "lib": "file:../lib",\n    "my-lodash": "npm:lodash@~4.17.0",\n    "tagged": "latest"\n  },\n' \
              '  "devDependencies": {\n    "jest": ">=29 <30"\n  },\n  "optionalDependencies": {\n    "fsevents": "2.x"\n  },\n' \
              '  "peerDependencies": {\n    "react-dom": "^18"\n  }\n}\n'
        self.assertEqual(self.got("package.json", pkg), [
            ("npm", "axios", "^1.6.0", '"axios": "^1.6.0"', "1.6.0", "2.0.0", False, 4),
            ("npm", "lodash", "~4.17.0", '"my-lodash": "npm:lodash@~4.17.0"', "4.17.0", "4.18.0", False, 7),
            ("npm", "jest", ">=29 <30", '"jest": ">=29 <30"', "29.0.0", "30.0.0", False, 11),
            ("npm", "fsevents", "2.x", '"fsevents": "2.x"', "2.0.0", "3.0.0", False, 14)])

    def test_pyproject_toml(self):
        doc = '[project]\nname = "x"\ndependencies = [\n  "Pillow>=10",\n  "flask",\n  "attrs==23.1.0",\n]\n' \
              '[project.optional-dependencies]\ndev = ["pytest~=7.4"]\n'
        self.assertEqual(self.got("pyproject.toml", doc), [
            ("PyPI", "Pillow", ">=10", "Pillow>=10", "10", None, False, 4),
            ("PyPI", "attrs", "==23.1.0", "attrs==23.1.0", "23.1.0", "23.1.0", True, 6),
            ("PyPI", "pytest", "~=7.4", "pytest~=7.4", "7.4", "8", False, 9)])

    def test_poetry_dependencies(self):
        doc = D('''\
            [tool.poetry.dependencies]
            python = "^3.9"
            requests = "^2.28"
            Django = "~4.2.1"
            attrs = "23.1.0"
            numpy = ">= 1.24, < 2"
            urllib3 = { version = "^1.26", extras = ["socks"] }
            anything = "*"
            either = "^1.0 || ^2.0"
            mylib = { path = "../mylib", develop = true }
            fork = { git = "https://github.com/acme/fork.git", tag = "v1.0" }
            multi = [{ version = "^1.0", python = "<3.10" }, { version = "^2.0", python = ">=3.10" }]
            zerover = "^0.2.3"
            wild = "1.4.*"

            [tool.poetry.dependencies.boto3]
            version = "~1.34"
            optional = true

            [tool.poetry.dev-dependencies]
            black = "^23.1"

            [tool.poetry.group.test.dependencies]
            pytest = "^7.4"

            [tool.poetry.group.test]
            optional = true
            ''')
        self.assertEqual(self.got("pyproject.toml", doc), [
            ("PyPI", "requests", "^2.28", 'requests = "^2.28"', "2.28", "3.0.0", False, 3),
            ("PyPI", "Django", "~4.2.1", 'Django = "~4.2.1"', "4.2.1", "4.3.0", False, 4),
            ("PyPI", "attrs", "23.1.0", 'attrs = "23.1.0"', "23.1.0", "23.1.0", True, 5),
            ("PyPI", "numpy", ">= 1.24, < 2", 'numpy = ">= 1.24, < 2"', "1.24", "2", False, 6),
            ("PyPI", "urllib3", "^1.26", 'version = "^1.26"', "1.26", "2.0.0", False, 7),
            ("PyPI", "zerover", "^0.2.3", 'zerover = "^0.2.3"', "0.2.3", "0.3.0", False, 13),
            ("PyPI", "wild", "1.4.*", 'wild = "1.4.*"', "1.4", "1.5", False, 14),
            ("PyPI", "boto3", "~1.34", 'version = "~1.34"', "1.34", "1.35.0", False, 17),
            ("PyPI", "black", "^23.1", 'black = "^23.1"', "23.1", "24.0.0", False, 21),
            ("PyPI", "pytest", "^7.4", 'pytest = "^7.4"', "7.4", "8.0.0", False, 24)])
        self.assertTrue(lockfiles.ranges(self.root, "pyproject.toml")[2].exact)
        self.assertEqual(lockfiles.raised(lockfiles.ranges(self.root, "pyproject.toml")[0], "2.32.4"),
                         'requests = ">=2.32.4,<3.0.0"')

    def test_poetry_and_project_dependencies_together_keep_file_order(self):
        doc = '[project]\ndependencies = ["flask>=2"]\n[tool.poetry.dependencies]\nrequests = "^2.28"\n' \
              '[dependency-groups]\ndev = ["ruff>=0.4"]\n'
        self.write("pyproject.toml", doc)
        self.assertEqual([(r.name, r.line) for r in lockfiles.ranges(self.root, "pyproject.toml")],
                         [("flask", 2), ("requests", 4), ("ruff", 6)])

    def test_other_and_broken_files(self):
        self.assertEqual(self.got("go.mod", "require x v1.0.0\n"), [])
        self.assertEqual(lockfiles.ranges(self.root, "requirements.txt"), [])  # missing file
        for content in ("", "{", "[]", "null", '{"dependencies": ["a"]}', '{"dependencies": {"a": 1}}', DEEP_JSON):
            with self.subTest(content=content[:20]):
                self.assertEqual(self.got("package.json", content), [])

    def test_rewriting_the_minimum(self):
        def raised(spec_file, content, version):
            self.write(spec_file, content)
            return lockfiles.raised(lockfiles.ranges(self.root, spec_file)[0], version)
        self.assertEqual(raised("requirements.txt", "Pillow>=10\n", "12.3.0"), "Pillow>=12.3.0")
        self.assertEqual(raised("requirements.txt", "foo [bar] >= 1.2, < 2\n", "1.4.1"), "foo[bar]>=1.4.1,<2")
        self.assertEqual(raised("requirements.txt", "foo>=1.2,<2\n", "2.0.1"), "foo>=2.0.1")  # fix outside: range opens
        self.assertEqual(raised("requirements.txt", "requests~=2.25\n", "2.32.4"), "requests>=2.32.4,<3")
        self.assertEqual(raised("requirements.txt", "Django>=3.2,<=3.2.30\n", "3.2.25"), "Django>=3.2.25,<=3.2.30")
        cases = [('"^1.6.0"', "1.12.0", '"axios": "^1.12.0"'), ('"~1.6.0"', "1.6.8", '"axios": "~1.6.8"'),
                 ('"1.6.x"', "1.6.8", '"axios": "~1.6.8"'), ('"1.x"', "1.12.0", '"axios": "^1.12.0"'),
                 ('">=1.6.0"', "1.12.0", '"axios": ">=1.12.0"'), ('">=1.6.0 <1.10.0"', "1.8.2", '"axios": ">=1.8.2 <1.10.0"'),
                 ('">=1.6.0 <=1.9.0"', "1.8.2", '"axios": ">=1.8.2 <=1.9.0"'), ('">=0.2.0 <1"', "0.5.0", '"axios": ">=0.5.0 <1.0.0"'), ('"0.5.x"', "0.5.3", '"axios": "^0.5.3"'),
                 ('"~1.6.0"', "1.12.0", '"axios": "^1.12.0"'), ('"npm:axios@^1.6.0"', "1.12.0", '"axios": "npm:axios@^1.12.0"')]
        for spec, version, want in cases:
            with self.subTest(spec=spec):
                self.assertEqual(raised("package.json", '{"dependencies": {"axios": %s}}' % spec, version), want)

    def test_python_versions_follow_pep_440(self):
        # In PEP 440 "1.0-1" is the post-release 1.0.post1, after 1.0; the generic order took it for a pre-release.
        self.write("requirements.txt", "foo>=0.9,<1.0.post1\nbar>=1.0,>=1.0-1\nbaz>=1.0.post1,<=1.0-1\n")
        foo, bar, baz = lockfiles.ranges(self.root, "requirements.txt")
        self.assertEqual([lockfiles.in_range(foo, v) for v in ("0.9", "1.0", "1.0-1", "1.0.post1")], [True, True, False, False])
        self.assertEqual(bar.floor, "1.0-1")
        self.assertTrue(baz.exact)
        self.assertEqual(lockfiles.raised(foo, "1.0-1"), "foo>=1.0-1")  # outside the range: it opens

    def test_in_range(self):
        self.write("package.json", '{"dependencies": {"a": "^1.6.0", "b": ">=1.0.0 <=1.9.0", "c": ">=2.0.0"}}')
        a, b, c = lockfiles.ranges(self.root, "package.json")
        self.assertEqual([lockfiles.in_range(a, v) for v in ("1.5.9", "1.6.0", "1.99.0", "2.0.0")], [False, True, True, False])
        self.assertEqual([lockfiles.in_range(b, v) for v in ("1.9.0", "1.9.1")], [True, False])
        self.assertTrue(lockfiles.in_range(c, "99.0.0"))


# --------------------------------------------------------------------------- what deps.collect reads


class Collect(LockfileCase):
    def collect(self, files):
        from stingward import scan
        from stingward.checks import deps
        from stingward.model import Context
        for rel, content in files.items():
            self.write(rel, content if isinstance(content, str) else json.dumps(content))
        return deps.collect(Context(root=str(self.root), files=scan.list_files(str(self.root))))

    MEMBER = {"name": "web", "dependencies": {"next": "^14.1.0", "react": "^18.2.0"}}
    LOCK = {"lockfileVersion": 3, "packages": {"": {}, "apps/web": {"name": "web"},
                                                "node_modules/next": {"version": "14.1.0"},
                                                "node_modules/react": {"version": "18.2.0"}}}

    def test_workspace_members_are_covered_by_the_root_lockfile(self):
        layouts = {
            "npm": {"package.json": {"name": "root", "workspaces": ["apps/*", "packages/*", "!packages/legacy"]},
                    "package-lock.json": self.LOCK},
            "yarn object form": {"package.json": {"name": "root", "workspaces": {"packages": ["./apps/*", "packages/**"]}},
                                 "yarn.lock": 'next@^14.1.0:\n  version "14.1.0"\n'},
            "pnpm": {"package.json": {"name": "root"}, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
                     "pnpm-workspace.yaml": "packages:\n  - 'apps/*'   # apps\n  - \"packages/**\"\n  - '!packages/legacy'\ncatalog:\n  react: ^18\n"},
        }
        for name, root in layouts.items():
            with self.subTest(layout=name):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                self.root = Path(tmp.name)
                files = dict(root, **{"apps/web/package.json": self.MEMBER, "packages/ui/package.json": self.MEMBER,
                                      "packages/legacy/package.json": self.MEMBER, "tools/script/package.json": self.MEMBER})
                _, open_manifests, ranges = self.collect(files)
                want = ["tools/script/package.json"] if name == "yarn object form" else \
                    ["packages/legacy/package.json", "tools/script/package.json"]
                self.assertEqual(sorted(rel for rel, _ in open_manifests), want)

    def test_shrinkwrap_and_nuget_lockfiles_are_audited_but_not_scanned_as_text(self):
        from stingward import scan
        token = "gh" + "p_" + "aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uVwX2y"
        shrink = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/left-pad": {
            "version": "1.3.0", "resolved": f"https://npm.acme.dev/left-pad/-/left-pad-1.3.0.tgz?token={token}"}}}
        nuget = {"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1",
                                                                               "contentHash": token}}}}
        pkgs, _, _ = self.collect({"npm-shrinkwrap.json": shrink, "package.json": {"name": "app"},
                                   "src/App/packages.lock.json": nuget})
        self.assertEqual(sorted(p[:4] for p in pkgs), [
            ("NuGet", "Newtonsoft.Json", "12.0.1", "src/App/packages.lock.json"),
            ("npm", "left-pad", "1.3.0", "npm-shrinkwrap.json")])
        found = scan.run(str(self.root), offline=True, only={"secrets"})[1]
        self.assertEqual([f.file for f in found if f.rule.startswith("SEC")], [])

    def test_a_folder_below_a_lockfile_without_workspaces_is_not_covered(self):
        _, open_manifests, _ = self.collect({"package.json": {"name": "root"}, "package-lock.json": self.LOCK,
                                             "functions/package.json": self.MEMBER})
        self.assertEqual(open_manifests, [("functions/package.json", 2)])

    def test_unreferenced_dash_requirements_files_are_read(self):
        pkgs, open_manifests, ranges = self.collect({"dev-requirements.txt": "pytest==7.0.0\nruff>=0.4\n",
                                                     "ci/test-requirements.txt": "coverage==7.4.0\n"})
        self.assertEqual(sorted((n, v, f) for _, n, v, f, _ in pkgs), [
            ("coverage", "7.4.0", "ci/test-requirements.txt"), ("pytest", "7.0.0", "dev-requirements.txt")])
        self.assertEqual([(r.name, r.floor) for r in ranges], [("ruff", "0.4")])
        self.assertEqual(open_manifests, [("dev-requirements.txt", 1)])

    def test_poetry_and_dependency_groups_are_read_without_a_lockfile(self):
        doc = '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "^2.28"\nattrs = "23.1.0"\n' \
              '[dependency-groups]\ndev = ["ruff>=0.4"]\n[tool.uv]\ndev-dependencies = ["mypy>=1.8"]\n'
        pkgs, open_manifests, ranges = self.collect({"pyproject.toml": doc})
        self.assertEqual([p[:4] for p in pkgs], [("PyPI", "attrs", "23.1.0", "pyproject.toml")])
        self.assertEqual([(r.name, r.floor) for r in ranges], [("requests", "2.28"), ("ruff", "0.4"), ("mypy", "1.8")])
        self.assertEqual(open_manifests, [])
        pkgs, _, ranges = self.collect({"poetry.lock": ""})
        self.assertEqual((pkgs, ranges), ([], []))

    def test_requirements_folder_and_included_files_are_read(self):
        pkgs, open_manifests, ranges = self.collect({
            "requirements.txt": "-r requirements/production.txt\n-c constraints.txt\n-r ../outside.txt\n",
            "requirements/base.txt": "django==4.2.0\ncelery>=5.3\n",
            "requirements/production.txt": "-r base.txt\ngunicorn==21.2.0\n",
            "constraints.txt": "urllib3==1.26.0\n",
            "lint.txt": "ruff==0.4.0\n",
        })
        self.assertEqual(sorted((n, v, f) for _, n, v, f, _ in pkgs), [
            ("django", "4.2.0", "requirements/base.txt"), ("gunicorn", "21.2.0", "requirements/production.txt"),
            ("urllib3", "1.26.0", "constraints.txt")])
        self.assertEqual([(r.name, r.floor, r.file) for r in ranges], [("celery", "5.3", "requirements/base.txt")])
        self.assertEqual(open_manifests, [("requirements/base.txt", 1)])


if __name__ == "__main__":
    unittest.main()
