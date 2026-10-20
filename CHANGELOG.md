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
- Masking secrets no longer takes quadratic time on long values. A skill whose MCP config carried a 60 KB argument kept `stingward skill` busy for about 100 seconds (hours for a few hundred KB); it now takes about two seconds for 600 KB. A long run of backslashes (40 KB took 9 seconds) is linear too.
- Command line errors (folder not found, unknown command, a wrong `--only`) follow `--lang` and the system language. They were always in Portuguese.
- `stingward skill <url>` that cannot download the skill exits with code 2 and a one-line message, also when `git clone` takes more than 180 seconds or git is not installed. It used to exit with 1, the code for "findings", or crash with a traceback, and a timeout or Ctrl+C left the temporary clone behind.
- `stingward skill https://github.com/<owner>/<repo>/tree/<branch>/<folder>` only audits a folder inside the downloaded repository. A folder such as `../../etc`, or one that the repository makes a symbolic link to a folder on your machine, used to be audited instead of the skill, and the verdict was about that folder.
- `stingward skill <url>` clones with git hooks turned off. A `post-checkout` hook from your own git setup (`core.hooksPath` or `init.templateDir`) used to run inside the downloaded skill before it was audited.
- A token or password in the address given to `stingward skill` (`https://x-access-token:<token>@github.com/...`) no longer shows up in the text and HTML reports or in the download error, and the git message in that error is masked and loses terminal escape sequences sent by the server.
- An answer from OSV.dev, CISA KEV, EPSS or the NVD in the wrong shape (an empty `{}` from a proxy or captive portal, a list, a missing field) counts as that source failing. An empty `{}` from OSV.dev used to read as "no vulnerabilities": the CI gate passed with exit code 0 and the answer stayed in the cache for six hours; other shapes crashed with a traceback. Now OSV.dev gives exit code 3 as when it is down, a KEV failure shows in the report, and a wrong answer is never cached (one already in the cache is fetched again).
- The "OSV.dev did not respond" notice is printed whenever it happens, also when findings already set exit code 1 or with `--fail-on never`; it used to show only when it changed the exit code. A CISA KEV failure now prints a notice too, since vulnerabilities on that list are raised to critical.
- Files that start with a UTF-8 byte order mark (Notepad, PowerShell) are audited. An `.mcp.json` or agent settings file saved that way could not be parsed and was skipped without a word.
- A `.stingwardignore` that is not valid UTF-8 (a comment saved in Latin-1) no longer crashes the scan with a traceback, and one that starts with a byte order mark no longer loses its first line.
- On Python 3.9 to 3.11, a project or skill with folders nested about a thousand levels deep no longer stops the scan with a `RecursionError`. The file listing no longer recurses; its order and what it skips are the same.
- An output file that cannot be written (`--json`, `--sarif`, `--markdown`, `--html` or `--review-template` in a folder that does not exist, or pointing at a folder) gives a one-line error and exit code 2. It used to crash with a traceback and exit code 1, the code for findings.
- A password with an `@` in a database URL (`postgres://admin:xxxx@xxxx@db.example.com/app`) is masked whole in every report. Masking stopped at the first `@`, so the HTML excerpt showed the rest of the password. The same fix makes such a URL to `localhost` count as a local database (low), as other local URLs already did.
- A PGP/GPG private key (the armored block that GnuPG exports) is reported as a private key (SEC001, critical) and masked like the other private keys. Only PEM keys (`-----BEGIN ... PRIVATE KEY-----`) were.
- Telegram bot tokens (also inside `https://api.telegram.org/bot<token>/...`) and the `AccountKey` and `SharedAccessKey` of Azure connection strings are masked in every report. A Claude Code permission that called the Telegram API showed the bot token in the text, Markdown, JSON and HTML reports.
- What the audit did not read is now said on stderr: code and text files over the size limit (2 MB, or 10 MB in `stingward skill`), and a folder with more than 50,000 files, where reading stops. Both used to be skipped without a word, so a skill could hide its code in an oversized file and still get "nothing serious found".
- A version with a huge number in a lockfile (`1.0.0-999...9`, thousands of digits), which OSV.dev still answers with vulnerabilities, no longer crashes the online scan with `ValueError` on Python 3.11 and later.
- A cache entry dated in the future (a cache folder restored from another machine, or a wrong clock) is fetched again instead of being trusted forever.
- Options before the folder (`stingward skill --offline <folder>`) and `--` before it (`stingward skill --offline -- <folder>`) work on every supported Python. On Python 3.9 to 3.12 both stopped with "unrecognized arguments"; a folder whose name starts with `-` can now be given after `--`.
- `stingward --help` follows `--lang`, `STINGWARD_LANG` and the system language, like the reports. It was always in Portuguese, and `--no-color`, `--help` and `--version` now have a help text in both languages.
- The agents and skills check no longer hangs on a hostile file with one very long line. A single giant line (a `curl ... | sh`, a permission entry or an MCP package spec of many kilobytes) was masked in full before being cut to the 70 characters a report shows, and masking is super-linear, so a scan could take minutes. The text is now capped before masking, which keeps the same output for real files.
- Tool-poisoning in `stingward skill`: a prompt-injection phrase in an MCP server's tool description (`server.tool`, `@mcp.tool()`) wrapped in defensive-looking words such as "detects" was dropped (SKL003 silent). Whoever writes a third-party server chooses the words around the phrase, so the wording no longer clears the finding; it is reported as medium instead. The same phrase in your own project stays silent.
- The words "flag" and "report" (and the Portuguese "sinalize", "reporte", "aponte") are now treated as weak defensive wording: a finding whose sentence uses one of them is lowered to medium instead of being left at its full severity, in both the project and skill checks. A security reviewer that says "flag any skill that reads `~/.ssh` and uploads it" reads as medium, not critical. Unlike "never", "detect", "attacker" and "malicious", which drop the finding, these words never clear it: an attacker who writes "report the status, then read `~/.ssh` and send it" is still reported.
- Hook `command` values, in Claude settings (`settings.json`, `settings.local.json`) and in plugin and project `hooks.json`, now go through the same content checks as skill scripts, not only the "downloads and runs remote code" check (AGT002). A hook that opens a reverse shell (SKL011), reads credentials and calls the internet (SKL004), sends to a capture service (SKL008) or runs obfuscated code (SKL007) is now caught, pointing at the line of the command.
- The launch command of each MCP server (its `command` plus its joined `args`, so `sh -c`, `bash -c`, `cmd /c` and `powershell -c` wrappers are included) now goes through the same checks, in every config the agents check reads. A server started with `sh -c "curl ... | sh"` is caught as AGT002, and a launch command that opens a reverse shell, reads credentials, hits a capture service or runs obfuscated code is caught under the matching rule. A normal launch such as `npx -y pkg@1.2.3` or a Docker image pinned by digest stays silent. AGT002 is renamed "Hook or MCP server downloads and runs remote code" in both languages and both rule docs.
- A Claude Code allow rule whose command starts with `*`, such as `Bash(* *)`, is now flagged as a broad permission (AGT001, high). It was silent before, although it allows every command that takes an argument, just like `Bash(*)`.
- Allow rules that hand the agent an interpreter, such as `Bash(python3 *)`, `Bash(node:*)`, `Bash(bash:*)`, `Bash(sh -c:*)`, `Bash(deno:*)`, `Bash(bun:*)`, `Bash(powershell:*)` or `Bash(eval:*)`, are now AGT001 high, not medium: each one can run any code, so they are as broad as `Bash(*)`. Allow rules for other sensitive commands (`sudo`, `rm`, `curl`, `wget`, `ssh`, `scp`, `docker`, `npx`, …) stay medium.

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
