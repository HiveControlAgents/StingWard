# Contributing to Stingward

[Português](CONTRIBUTING.pt-BR.md)

Thanks for helping. The most useful contributions are **false positives and misses with a minimal sample**, new rules for mistakes you see in AI-built projects, and fixes to the explanations so they stay clear for people who are not security experts.

## Set up

Stingward is pure Python 3.9+ with no dependencies, so there is nothing to install:

```bash
git clone https://github.com/HiveControlAgents/StingWard.git
cd StingWard
python -m stingward --offline .                                 # run it on itself
python -m unittest discover -s tests -t .                       # offline tests, a few seconds
STINGWARD_ONLINE=1 python -m unittest discover -s tests -t .    # also hits OSV, KEV, EPSS and NVD
```

To try the README demos: `python scripts/demo/fixtures.py demo`, then `python -m stingward skill demo/pdf-helper` and `python -m stingward demo/my-saas`.

To build the website: `python site/build.py _site`, then open `_site/index.html`. Add `--online` to include the dependency results from OSV.dev, as the published site does.

## Where things live

| Path | What |
|---|---|
| `stingward/cli.py` | Command line, exit codes, downloading a skill from GitHub |
| `stingward/scan.py` | File listing, running the checks, `.stingwardignore`, context-aware severity |
| `stingward/checks/` | `deps.py`, `secrets.py`, `app.py`, `code.py` (flaws in Python and JavaScript code, and in code that calls a model), `agents.py` (agents, MCP and skills) |
| `stingward/rules.py` | Every rule's title, why and fix, in Portuguese and English, plus the standard IDs |
| `stingward/report.py` | Text, Markdown, JSON and SARIF output, grade and badge |
| `stingward/lockfiles.py`, `vulndb.py`, `net.py` | Lockfile parsers, OSV/KEV/EPSS/NVD clients, HTTP with cache and retries |
| `stingward/gitsafe.py` | The only way Stingward calls git (see below) |
| `skills/stingward/` | The Claude Code skill shipped by the plugin |
| `action.yml` | The GitHub Action |
| `npm/` | The npm launcher (`scripts/build-npm.sh` copies the Python package into it) |
| `docs/` | Rules reference and README assets |
| `site/` | The website: `build.py` fills `page.html` with `text.json` and real Stingward reports, and `.github/workflows/pages.yml` publishes it |

## Adding or changing a rule

1. Write the texts in `stingward/rules.py`, in Portuguese and English, for someone who built the app with AI: what it is, why it matters, what to do. Add its standard IDs to `STANDARDS`.
2. Implement it in the right file under `stingward/checks/`.
3. Add tests for what it must catch **and** for the look-alikes it must not flag. Every false positive we fix becomes a regression test in `tests/test_fp_regressions.py`.
4. Document it in `docs/rules.md` and `docs/rules.pt-BR.md`, and add it to the rules tables. `tests/test_docs.py` fails if a rule is missing from the docs or its standards differ.

## Rules for the code

- **Audited content is hostile.** Never execute it, never import from the audited folder, and call git only through `stingward/gitsafe.py`, which stops git from discovering a repository inside audited files.
- **Never print a secret**, not even part of it. Snippets go through `secrets.mask()`.
- **Standard library only**, compatible with Python 3.9, working on Linux, macOS and Windows.
- **A finding in a third-party skill can be lowered, never dropped**, so an attacker cannot hide it with wording.
- Keep the surrounding style: short functions, comments only where the reason is not obvious (existing comments are in Portuguese).

## Pull requests

Keep them focused, include tests, and make sure CI is green on all three systems. Describe the before and after in plain words. By contributing you agree that your work is released under the [Apache 2.0 license](LICENSE).

## Releases (maintainers)

Bump the version in `pyproject.toml`, `stingward/__init__.py`, `npm/package.json` and `.claude-plugin/plugin.json`, add the entry to `CHANGELOG.md`, and merge to `main`. When CI passes, the release workflow publishes to PyPI and npm with trusted publishing, tags `vX.Y.Z`, moves `v0` and creates the GitHub release. `tests/test_docs.py` checks that the versions match.

## Conduct and security

Be kind; see the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities in Stingward itself privately, as described in [SECURITY.md](SECURITY.md).
