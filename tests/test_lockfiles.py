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
               "Cargo.lock", "Gemfile.lock", "composer.lock"]
        no = ["requirements.in", "dev-requirements.txt", "package.json.bak", "Cargo.toml", "pyproject.toml",
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


if __name__ == "__main__":
    unittest.main()
