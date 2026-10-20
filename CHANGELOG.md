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
- APP009 to APP013, for code that calls a model: its answer reaching `eval`, a shell, SQL or HTML; request input inside the system prompt; AI routes with no login and no rate limit (OWASP LLM06); `trust_remote_code=True`, `allow_dangerous_deserialization=True` and `torch.load` without `weights_only=True`; agents with a Python REPL or shell tool, `allow_dangerous_code=True` or AutoGen without Docker.
- The demo app built by `scripts/demo/fixtures.py` now also reports APP011 on its chat route, and has the mistakes the code check and DEP004 catch: an agent route that runs the model's answer in a shell, SQL built from the request, a PDF route that reads any path, a link preview that fetches any URL, a chat component that renders the model's answer as HTML, and a Python worker whose `requests>=2.19.0` allows a version with known vulnerabilities. Every key in it is fake. The README demos were recorded again from it.
- The website shows the code check, the AI-specific rules and DEP004, links to a sample report (`/exemplo/` and `/en/example/`): the real HTML report of the demo app, built at deploy time, with a note on top and its content security policy kept. It also presents a security audit with a human review (US$ 149, delivered in 48 hours, with what it includes and what it does not cover) and a waitlist for a Team plan. Both buttons read their addresses from `links` in `site/text.json`; while an address is empty the button reads "Em breve" / "Coming soon" and is not a link, and a filled one must be an `https://` address. Parts of the page more than a screen away no longer sit hidden while they wait for their entrance, so a page read without scrolling through it shows no blank stretch.
- APP014, for MCP servers and agent tools: an argument the model writes reaching a shell command, `eval`/`exec`, a template, SQL, `pickle` or unsafe YAML, a file path, a URL the server fetches or HTML. Tool arguments are read from FastMCP `@mcp.tool()` and `mcp.add_tool(f)`, low-level `@server.call_tool()` handlers and their `arguments`, TypeScript `server.tool(...)`, `server.registerTool(...)` and `CallToolRequestSchema` handlers, LangChain `@tool` and `BaseTool._run`, AI SDK `tool({ execute })`, and `tool_call.function.arguments` or `block.input` from OpenAI and Anthropic responses, and are followed into helpers of the same file and into functions the tool imports from other files of the project, two levels deep. Critical when the argument is mixed into a command or code written in the code, high for SQL, deserialization and a path joined to the code's own folder, medium for other paths, URLs and HTML. Typed arguments (numbers, `Literal`, `Enum`, `Field(pattern=...)`, `z.number()`, `z.enum()`), injected parameters such as `ctx`, query parameters, argument lists whose program is written in the code, an argument passed first to a check such as `validate_name(arg)` or `validatePath(p)`, `shlex.quote`, `basename`, a resolve-and-prefix check, a fixed file name, a fixed host and an allow list of hosts are not reported. Each finding carries the CWE and OWASP Agentic entry of its sink besides `LLM03:2026`, in every report format, and keeps its full severity in `stingward skill`.
- COD002 also catches `["sh", "-c", cmd]` in Python and `spawn("sh", ["-c", cmd])`, `spawn(cmd, { shell: true })` and execa with `shell: true` in JavaScript.
- COD005 also catches HTML built from request data in Express `res.send`/`res.write`/`res.end` (with `.status()` and similar chained before), Hono `c.html`, and FastAPI routes with `response_class=HTMLResponse`; a Flask route that returns the HTML in a variable or in a `(body, status)` tuple counts too.
- COD010 also catches `Math.random()` in a module-level value or inside a callback that builds it, and a session id (`session_id`, `sessionId`, `sid`) made with `Math.random()` or `random` that goes into a cookie.
- COD001 in Python also catches SQL built from request data and passed to the project's own query helpers (`execute_query(f"...")`, `run_sql(...)`). COD007 in JavaScript also reads `fsp`, `fsPromises` and `fs-extra` calls and counts checks such as `validatePath(p)` or `isAllowedPath(p)` before the call. COD008 in JavaScript no longer takes the word `private` (a TypeScript `private` field) as a check of the address.

### Changed
- The DEP003 docs no longer list `pyproject.toml`: it never raised DEP003, since libraries declare ranges on purpose.
- Text and Markdown reports list the same problem (same rule, title and explanation) once, with every place it was found, and start with a short "fix these first" list when there are critical or high findings. JSON and SARIF still have one record per finding.
- Test and example code is recognized in more places (`e2e/`, `samples/`, `testdata/`, `__mocks__/`, `cookbooks/`, `test_*.py`, `conftest.py`), and findings there are lowered as they already were in `tests/` and `examples/`.

### Fixed
- A version range in `requirements*.txt`, `package.json` or `pyproject.toml` with a long version that does not parse (for example `foo>=1aaaaaaaaaaaaaaaaaaaaaaaaaaaa*`) no longer makes the scan hang: the version pattern backtracked exponentially.
- A long run of spaces on a line of `requirements*.txt` no longer slows the scan down quadratically.
- A committed `.env` with a long run of spaces inside a value no longer slows the scan down quadratically (60 000 spaces took 15 seconds).
- Masking of command-line options such as `--api-key` in code excerpts is linear: a long hyphenated word made it quadratic.
- A file with thousands of hard-coded values (generated config, fixtures) is scanned for secrets in linear time: 40 000 such lines took 44 seconds.
- SEC001 no longer reports a "password in URL" (high) where code builds the URL: `f"postgresql://{settings.DB_USER}:{settings.DB_PASSWORD}@..."`, `"{}:{}@{}".format(...)`, `"%s:%s@%s"`, `%(password)s`, Ruby `#{password}` and Swift `\(password)`. Translated examples such as `https://usuario:contraseña@servidor` or `https://uzivatel:heslo@hostitel:port` (a non-ASCII password, or a port written as a word) are not reported either; a real password next to a host and port the code fills in still is.
- SEC001 reports a private key only when its body is there (on the same line, as in a service account JSON, or on the next lines). Code that only writes the header, such as `key.replace('-----BEGIN PRIVATE KEY-----', '')`, `startsWith(...)`, a `placeholder="-----BEGIN PRIVATE KEY-----"` or an example with `\n...\n`, was a critical finding.
- SEC001 now reads key files that were never scanned: `id_rsa` (and the `dsa`, `ecdsa` and `ed25519` ones), `*.pem`, `*.key` and Apple's `*.p8`. A committed private key in one of them was missed; a certificate, which only holds the public part, is not reported.
- SEC001 no longer reports a "Meta/Facebook token" (high) inside base64 data such as an embedded image, font or WebAssembly module, where `/EAA...` and `+EAA...` show up all the time.
- Real keys are no longer skipped as placeholders because their random part contains `seu` or `sua` (Portuguese for "your"): about 1 in 100 OpenAI project keys and 1 in 150 Anthropic keys were missed. Those words now count only at the start of a word, as in `SUA_CHAVE` or `sk-sua-chave`.
- SEC001 no longer reports as a hard-coded value: translated text in i18n files (`"password_complexity_requirement": "数字、大文字..."`, `"Tokens": "...\u200c..."`), the example `1234567890`, a dotted config path (`image_generation.automatic1111.api_auth`), the name of an environment variable (`'DUCKLAKE_S3_SECRET'`, `MOCK_ACCESS_TOKEN`), and keys that are public by design (`sb_publishable_...`, Stripe `pk_live_`/`pk_test_`).
- A Slack or Discord webhook is no longer missed when something else on its line looks like an example, such as `{ text: "your build finished" }` or `process.env.SLACK_WEBHOOK || "https://hooks.slack.com/..."`: only the webhook's own token is checked for placeholders.
- DEP003 no longer reports the `package.json` of each workspace member in a monorepo whose lockfile sits at the root (npm, Yarn and Bun `workspaces`, `pnpm-workspace.yaml`, including `**` and `!` globs); a folder that is not a member still gets it.
- Packages installed from a git repository or a local folder or tarball are no longer looked up in the public registry's advisories: `package-lock.json` v2/v3 (`resolved` git or `file:`), `yarn.lock` (git, GitHub, `owner/repo` and URL entries), `poetry.lock` (`[package.source]` git, directory or file), `uv.lock` (git), `pdm.lock` (git or path) and `Cargo.lock` (`git+`). npm v1 lockfiles and `Gemfile.lock` already did this. A private package that shares its name with a public one no longer inherits that package's advisories.
- The `.txt` files of a `requirements/` folder (`requirements/base.txt`, `requirements/production.txt`) and the files a requirements file includes with `-r` or `-c` (`constraints.txt`, `dev-requirements.txt`) are now read for DEP001, DEP003 and DEP004. Before, a project with that layout had none of its pins audited.
- An advisory that OSV.dev lists for a package but whose details could not be downloaded is no longer dropped without a word: the package still gets a DEP001 or DEP004 (medium, with a note to check the advisory and run again), and a `MAL-` record still gets DEP002. The run counts as incomplete, like an OSV.dev outage: the CLI exits with 3, so a CI gate cannot pass on it. A headline no longer ends in empty parentheses when an advisory has no summary.
- The private-key body check also reads PGP blocks (`PRIVATE KEY BLOCK`, with armor headers such as `Version:` and the blank line before the body): a real block is critical, a header alone in a README or doc is not reported, and a key header the check does not know no longer stops the scan.

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
