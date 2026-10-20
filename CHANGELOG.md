# Changelog

All notable changes to Stingward. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Human review for audits you hand over. `--review-template FILE` writes a JSON file with one entry per finding (and keeps what was already reviewed when it runs again); the reviewer sets each `status` to `confirmed`, `false_positive`, `accepted_risk` or `fixed` and writes a `comment`. `--review FILE` applies it to every report: the HTML shows the status and comment on each finding, moves false positives to an appendix and says in the scope section that a person reviewed the report and how many findings were confirmed or discarded. False positives and findings fixed during the audit leave the grade, the fix-first list and `--fail-on`; accepted risks still count toward the grade but leave the fix-first list, and the plan lists them, with what was fixed, under "no action planned". The text and Markdown reports follow the same rules, and the JSON gets each finding's review, a review summary and the grade after the review.
- `--client NAME` puts "Prepared for" on the cover of the HTML report, and `--notes FILE` adds the analyst summary at the top of the executive summary, written in a small Markdown subset (paragraphs, `-` lists, `**bold**`, `` `code` ``). Comments, notes and the client and reviewer names are escaped and go through the same secret masking as code excerpts; on top of that, any value that masking removed from a flagged line of the audited project (or from any line of a small file flagged as a whole, such as `.env`) is masked wherever it shows up in them, even in pieces.
- Every finding in the JSON output has a `fingerprint`, also in SARIF as `properties.fingerprint`. It comes from the rule, the file, the package, variable or table, and the masked text of the flagged line, not from the line number, so it survives edits elsewhere in the file. The rest of the JSON and SARIF output is unchanged.
- DEP004 checks the lowest version each range allows when there is no lockfile: `requirements*.txt` and `package.json` without a lockfile beside them, and the `[project]` dependencies and optional dependencies of a `pyproject.toml` without `poetry.lock`, `uv.lock` or `pdm.lock`. `Pillow>=10` lets a machine keep Pillow 10.0.0, which has 18 known vulnerabilities, one of them on the CISA KEV list; the finding says how many, names the worst and gives the new minimum (`Pillow>=12.3.0`). The lowest versions go to OSV.dev in the same batch as the pinned packages, and a package pinned elsewhere in the project is left to DEP001. Severity is medium at most, since the installed version is often newer, unless the range's upper bound leaves out the fix.
- An exact version written in a way the lockfile readers did not catch, such as `"Pillow==10.0.0"` in `pyproject.toml` or `foo (==1.0)` in `requirements.txt`, is now audited by DEP001.
- `--format html` and `--html FILE`: a single-file report in English or Portuguese to hand over or print to PDF (A4). It has a cover with the grade and verdict, an executive summary with what to fix first, a remediation plan with rough effort, findings grouped by area with the code excerpt, standards and references, and the scope, sources and limitations of the audit. It needs no network: no scripts, fonts or images are loaded, and a content security policy allows only its inline styles. Secrets in code excerpts are masked and everything from the audited project is escaped.
- A new `code` check (`--only code`) that reads the project's own code: Python with `ast`, JavaScript and TypeScript (including the `<script>` of `.vue`, `.svelte` and `.astro` files) with tight patterns that follow request data inside each function. Tests, examples and fixtures drop to low, and minified bundles are skipped.
- COD001 to COD011: SQL injection, shell command injection, code injection (`eval`, `exec`, `new Function`, `render_template_string`), `pickle` and unsafe YAML, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`), TLS checks turned off (also `NODE_TLS_REJECT_UNAUTHORIZED=0` in `.env` files), path traversal, SSRF, open redirects, `Math.random` or `random` for secrets, and passwords hashed with MD5 or SHA.
- APP009 to APP013, for code that calls a model: its answer or a tool's arguments reaching `eval`, a shell, SQL or HTML; request input inside the system prompt; AI routes with no login and no rate limit (OWASP LLM06); `trust_remote_code=True`, `allow_dangerous_deserialization=True` and `torch.load` without `weights_only=True`; agents with a Python REPL or shell tool, `allow_dangerous_code=True` or AutoGen without Docker.
- The demo app built by `scripts/demo/fixtures.py` now also reports APP011 on its chat route.

### Changed
- The DEP003 docs no longer list `pyproject.toml`: it never raised DEP003, since libraries declare ranges on purpose.
- Text and Markdown reports list the same problem (same rule, title and explanation) once, with every place it was found, and start with a short "fix these first" list when there are critical or high findings. JSON and SARIF still have one record per finding.
- Test and example code is recognized in more places (`e2e/`, `samples/`, `testdata/`, `__mocks__/`, `cookbooks/`, `test_*.py`, `conftest.py`), and findings there are lowered as they already were in `tests/` and `examples/`.

## [0.1.5] - 2026-10-20

### Changed
- Stingward is now under the Apache 2.0 license, which adds an explicit patent grant and states that the license does not cover the Stingward name. Version 0.1.4 and earlier stay under MIT.

### Added
- A website at https://hivecontrolagents.github.io/StingWard/, in Portuguese and English, built from real Stingward reports and published from this repository.

## [0.1.4] - 2026-10-20

### Changed
- The secret masking module is now `stingward/_redact.py`. Reports and behavior are the same.

## [0.1.3] - 2026-10-20

### Added
- SKL011 flags reverse shells in skills and agent scripts (`bash -i >& /dev/tcp/...`, `nc -e`, `socat exec:`, Python `pty.spawn`, PowerShell `TCPClient`).
- SKL002 also catches downloading a file and running it on the same line (`curl -o x ... && chmod +x x`).
- SKL005 understands "follow the instructions on the page".

### Changed
- SKL009 is high, not medium, when an install script downloads and runs code from the internet.
- SKL004 no longer treats `env=dict(os.environ)` as reading credentials: copying the environment to a child process is normal. Sending the whole environment (`json=dict(os.environ)`, `json.dumps(os.environ)`, `params=os.environ`) is still critical.

## [0.1.2] - 2026-10-20

### Changed
- The Action's description is shorter, within the GitHub Marketplace limit of 125 characters.
- GitHub release notes now come from this changelog.

## [0.1.1] - 2026-10-20

### Added
- README in English, Portuguese and Spanish, with demo GIFs of real runs, a logo and banners.
- Rules reference with severity, examples and fixes for all 31 rules, in English and Portuguese ([docs/rules.md](docs/rules.md)).
- `scripts/demo/fixtures.py`, which builds the two demo projects shown in the README.
- Contributing guide, code of conduct, changelog, issue and pull request templates.
- Tests for network retries and caching, skill downloads, report details, the secret engine, and for docs that must match the code.

### Changed
- SARIF findings link to the rule's entry in the rules reference.
- npm releases use trusted publishing only; no token is stored.
- The plugin launcher suggests `pipx install stingward` when no copy is found.

## [0.1.0] - 2026-10-20

First public release: CLI (`pipx`, `uvx`, `npx`), Claude Code plugin and skill, and GitHub Action. Checks dependencies (OSV.dev, CISA KEV, EPSS, NVD), secrets, AI-built app mistakes, agent and MCP setups, and skills, with reports in text, Markdown, JSON and SARIF in English and Portuguese.

[Unreleased]: https://github.com/HiveControlAgents/StingWard/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/HiveControlAgents/StingWard/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/HiveControlAgents/StingWard/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/HiveControlAgents/StingWard/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/HiveControlAgents/StingWard/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/HiveControlAgents/StingWard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/HiveControlAgents/StingWard/releases/tag/v0.1.0
