<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/banner-en-dark.png">
    <img alt="Stingward: security check for AI-built apps, Claude Code skills and MCP servers" src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/banner-en-light.png" width="820">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/HiveControlAgents/StingWard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/HiveControlAgents/StingWard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/stingward/"><img alt="PyPI" src="https://img.shields.io/pypi/v/stingward?color=f5b83d&label=pypi"></a>
  <a href="https://www.npmjs.com/package/stingward"><img alt="npm" src="https://img.shields.io/npm/v/stingward?color=f5b83d"></a>
  <a href="https://pypi.org/project/stingward/"><img alt="Python 3.9+" src="https://img.shields.io/pypi/pyversions/stingward"></a>
  <img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-0-brightgreen">
  <a href="https://github.com/HiveControlAgents/StingWard/blob/main/LICENSE"><img alt="Apache 2.0 license" src="https://img.shields.io/badge/license-Apache%202.0-blue"></a>
  <a href="#quality"><img alt="stingward: A" src="https://img.shields.io/badge/stingward-A-brightgreen"></a>
</p>

<p align="center">
  <b>English</b> · <a href="https://github.com/HiveControlAgents/StingWard/blob/main/README.pt-BR.md">Português</a> · <a href="https://github.com/HiveControlAgents/StingWard/blob/main/README.es.md">Español</a>
</p>

Lots of people now ship apps, Claude Code skills and MCP servers written with AI. Few of them know what a CVE is, why `NEXT_PUBLIC_OPENAI_API_KEY` is a problem, or that a skill can hide instructions only the model can read. **Stingward finds those holes and tells you, in plain words, how to close each one.**

<p align="center">
  <img alt="stingward skill ./pdf-helper: Do not install yet. Hidden Unicode instruction, a script that reads AWS credentials and posts them to webhook.site, unrestricted shell. Grade F." src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/demo-skill-en.gif" width="820">
</p>

<p align="center"><sub>A skill that looks like a PDF helper. Stingward decodes the invisible instruction and finds the key theft before you install it.</sub></p>

## Quick start

| Where | How |
|---|---|
| **Claude Code** | `/plugin marketplace add HiveControlAgents/StingWard` then `/plugin install stingward@stingward`, and ask *"is my project secure?"* or *"can I install github.com/x/y?"* |
| **Terminal** | `pipx install stingward` (or `uvx stingward`, or `npx stingward` with Python 3.9+ installed), then run `stingward` in your project |
| **GitHub** | Add the [Action](#github-action): it comments on every PR, fills the Security tab and re-checks daily |

```bash
stingward                         # audit the project in the current folder
stingward skill ./some-skill      # audit a skill, plugin or MCP server before installing it
stingward skill owner/repo        # ...straight from GitHub (also accepts .../tree/branch/subfolder URLs)
stingward agents                  # audit the Claude Code, Claude Desktop, Cursor, Codex and Gemini setup on this machine
```

No account, no telemetry, no dependencies: pure Python 3.9+ on Linux, macOS and Windows.

## What it finds

| Area | Examples |
|---|---|
| **Dependencies** | Known CVEs and **malicious packages** in npm, Yarn, pnpm, Bun, pip, Poetry, uv, Pipenv, PDM, Go, Cargo, Bundler, Composer and NuGet lockfiles. Ranked by **CISA KEV** (exploited right now) and **EPSS** (likelihood of exploitation), with the single upgrade that fixes everything known. Without a lockfile, the lowest version each range allows (`Pillow>=10`, `^1.6.0`) is checked too. So is the PHP or Node.js version in a `Dockerfile`, `docker-compose.yml`, `.php-version`, `.nvmrc` or Replit's `.replit`. |
| **Secrets** | API keys (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack...), private keys, Supabase `service_role` keys, webhooks, passwords in URLs, `.env` committed or missing from `.gitignore`. Values are never printed. |
| **AI-built apps** | Secrets behind `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`, `dangerouslyAllowBrowser`, open CORS, Supabase tables without RLS or with `using (true)`, Edge Functions with the `service_role` key that let the visitor pick the record, database functions that run any SQL they receive, open Firebase rules, debug mode, JWT without signature check. In code that calls a model: its answer reaching `eval`, a shell, SQL or HTML, request input inside the system prompt, AI routes with no login and no rate limit (with an SDK or with `fetch` to the provider, such as the Lovable AI Gateway), `trust_remote_code` and unsafe `torch.load`, agents with a Python REPL or shell tool. In MCP servers and agent tools: arguments the model writes reaching a shell, `eval`, SQL, a file path or a URL the server fetches. |
| **Code** | SQL, shell and code injection, `pickle` and unsafe YAML, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`), TLS checks turned off, path traversal, SSRF, open redirects, `Math.random` for tokens and fast hashes for passwords. Python is read with `ast` and JavaScript/TypeScript with tight patterns that follow request data inside each function. |
| **Agents and MCP** | `bypassPermissions`, `Bash(*)`, hooks that `curl \| sh`, `enableAllProjectMcpServers`, MCP servers without a pinned version, tokens in `.mcp.json`, MCP over plain HTTP, vulnerable MCP packages such as `mcp-remote` (CVE-2025-6514). |
| **Skills and prompts** | Invisible Unicode (tag characters, Trojan Source, zero-width), "ignore previous instructions", "don't tell the user", reading `~/.ssh` or `~/.aws` and calling the internet, `curl \| bash`, reverse shells, obfuscated code, capture hosts (webhook.site, ngrok...), install scripts, `allowed-tools: Bash`, tool poisoning in MCP tool descriptions. |

All 54 rules, with severity, examples and fixes: [docs/rules.md](https://github.com/HiveControlAgents/StingWard/blob/main/docs/rules.md).

<p align="center">
  <img alt="stingward ./my-saas: OpenAI key exposed through NEXT_PUBLIC_, the model's answer run as a shell command, next 14.1.0 with CVE-2025-29927 (99% EPSS), SQL and a file path built from the request, a server that fetches any URL, a Supabase table without RLS, requests whose lowest allowed version has known flaws. Grade F." src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/demo-app-en.gif" width="820">
</p>

<p align="center"><sub>A typical AI-built Next.js + Supabase app. Try both demos from a clone of this repo: <code>python scripts/demo/fixtures.py demo</code>, then <code>stingward skill demo/pdf-helper</code> and <code>stingward demo/my-saas</code>.</sub></p>

## How it works

1. **Lists your files**, skipping dependency and build folders such as `node_modules` and `dist`. When auditing a third-party skill it does read build output, since that is what actually runs.
2. **Reads lockfiles** and asks [OSV.dev](https://osv.dev) about every package and version in one batch. CVEs in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) become critical; [EPSS](https://www.first.org/epss/) and [NVD](https://nvd.nist.gov) fill in likelihood and missing scores.
3. **Runs pattern checks** for secrets, app mistakes, agent settings and skill content, aware of context: test folders, docs and examples count less, and in third-party skills reassuring wording can lower a finding to medium but never hide it.
4. **Writes the report** in English or Portuguese: a verdict, what to fix first, findings worst first with where, why and how to fix (the same problem in several files is listed once, with every place), a grade from A to F and a badge. `--html FILE` also writes a single-file report to hand over or print to PDF: summary, remediation plan with rough effort, findings with the code excerpt (secrets masked), and scope and method.

Only package names and versions leave your machine (to `api.osv.dev`, `www.cisa.gov`, `api.first.org` and `services.nvd.nist.gov`). Your code never does. Responses are cached for a few hours in `~/.cache/stingward`.

Stingward reads hostile content by design, so it is careful with it: git can never discover a repository inside audited files, the launchers never import code from the audited folder, and secrets, terminal escapes and markdown are neutralized in every report format. See [SECURITY.md](https://github.com/HiveControlAgents/StingWard/blob/main/SECURITY.md).

## GitHub Action

```yaml
# .github/workflows/stingward.yml
name: stingward
on:
  pull_request:
  push: { branches: [main] }
  schedule: [{ cron: "0 9 * * *" }]   # new CVEs show up for code that did not change
permissions: { contents: read, pull-requests: write, security-events: write }
jobs:
  stingward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HiveControlAgents/StingWard@v0
        with: { lang: en, fail-on: high }
```

It comments the report on the PR (and updates the same comment on every run), uploads SARIF to the repository's **Security** tab, writes the job summary and exposes the grade as `steps.<id>.outputs.grade`.

| Input | Default | |
|---|---|---|
| `path` | `.` | Folder to audit |
| `fail-on` | `high` | Fail the job at this severity or above: `critical`, `high`, `medium`, `low`, `never` |
| `lang` | `en` | Report language: `en` or `pt` |
| `comment` | `true` | Comment on pull requests (needs `pull-requests: write`) |
| `sarif` | `true` | Upload SARIF to code scanning (needs `security-events: write`, plus `actions: read` in private repositories) |
| `category` | `stingward` | Code scanning category for the SARIF. Give each run its own when one workflow audits several folders |

## Command line reference

| Option | |
|---|---|
| `--lang en\|pt` | Report language (default: `STINGWARD_LANG`, then your system locale) |
| `--format text\|json\|markdown\|sarif\|html` | What goes to standard output |
| `--json FILE`, `--markdown FILE`, `--sarif FILE`, `--html FILE` | Also write these files, in one run |
| `--fail-on critical\|high\|medium\|low\|never` | Exit code 1 at this severity or above (default `high`) |
| `--only deps,secrets,app,code,agents` | Run only some checks |
| `--offline` | Skip the online databases (dependencies are not checked) |
| `--no-ignore` | Do not apply the project's `.stingwardignore` or `stingward:ignore` comments, to audit someone else's project |
| `--no-color` | Plain text output |
| `--review-template FILE` | Write the human review file: one entry per finding, keeping what was already reviewed |
| `--review FILE` | Apply the human review: a status and a comment for each finding |
| `--client NAME`, `--notes FILE` | "Prepared for" on the cover, and the analyst summary (paragraphs, `-` lists, `**bold**`, `` `code` ``) |

| Exit code | Meaning |
|---|---|
| `0` | Nothing at or above `--fail-on` |
| `1` | Something at or above `--fail-on` was found |
| `2` | Usage error: a wrong option, a folder that does not exist, a skill that could not be downloaded or an output file that could not be written |
| `3` | OSV.dev did not answer, so dependencies were not checked, or answered only in part, so the check is incomplete. A CI gate should not pass silently; use `--offline` to skip them on purpose. |
| `4` | No file was read, so there was nothing to grade: an empty folder, a wrong path, or in CI the code was not checked out first. A CI gate should not pass silently; `--fail-on never` accepts it. |

Environment: `STINGWARD_LANG` sets the default language, `NVD_API_KEY` raises the NVD rate limit and `STINGWARD_CACHE` moves the cache folder.

**Grade:** A means only low findings or none · B medium, no high · C one or two high · D three or more high · F any critical. Every report ends with a badge for your README:

```markdown
[![stingward: A](https://img.shields.io/badge/stingward-A-brightgreen)](https://github.com/HiveControlAgents/StingWard)
```

**Human review:** for an audit you hand over to someone, write the review file with `stingward . --review-template review.json`. Each entry points at a finding by its `fingerprint` (also in the JSON and SARIF output), which does not change when other parts of the file are edited. It is built from the flagged line with the secret already masked, so nothing derived from a secret goes into the review file. That is on purpose, and it means a key replaced by another key on the same line keeps its status: when a key is rotated, check that line again before you reuse the review. Set `status` to `confirmed`, `false_positive`, `accepted_risk` or `fixed`, add a `comment`, then run `stingward . --review review.json --client "Client name" --notes notes.md --html report.html`. False positives move to an appendix; they and the findings fixed during the audit leave the grade, the fix-first list and `--fail-on`. Accepted risks stay in the grade but leave the fix-first list. The text and Markdown reports follow the review too. Comments and notes are escaped and go through the same secret masking as code excerpts. For a review done by an AI, add `"review_kind": "ai"` to the review file: the reports then say automatic review instead of human review, `accepted_risk` is refused (only the client can accept a risk), and `fixed` is only accepted for a finding that is gone from a scan that could see it: not hidden by `.stingwardignore`, a `stingward:ignore` comment or the size and file limits.

**False positives:** add a line to `.stingwardignore` in the project root (`RULE path/glob`, `RULE` or `path/glob`), or put `stingward:ignore` in a comment on the line. When you audit someone else's project, `--no-ignore` turns both off. If a rule is wrong, [tell us](https://github.com/HiveControlAgents/StingWard/issues/new?template=false-positive.yml) with a minimal sample.

**Standards:** findings carry **CWE**, **OWASP Top 10 for LLM Applications 2026** (`LLM01:2026`...), **OWASP Agentic Skills Top 10** (`AST01`..., v1 draft) and **OWASP Top 10 for Agentic Applications 2026** (`ASI01`...) IDs, in the text report, JSON and SARIF tags.

## Quality

- **400+ automated tests**, plus online tests that query the real OSV, KEV, EPSS and NVD services across six ecosystems. Line coverage is above 90%.
- **Every push runs 24 CI jobs**: tests on Linux, macOS and Windows with Python 3.9 to 3.14, the PyPI and npm packages built and installed from scratch on all three systems, the Claude Code plugin validated, and the Action run against sample projects.
- **Stingward audits itself** in CI and must stay free of high and critical findings; its own grade is the A badge above.
- **False positives are measured** against popular public skill collections and MCP servers: no critical or high findings that are not real, and only a handful of medium ones per repository. Each fixed false positive becomes a regression test.
- **Security review of Stingward itself**, for example making sure a skill folder crafted as a git repository cannot run commands, and that a secret can never reach a report. Found issues are fixed with a test that fails on the old code.

```bash
python -m unittest discover -s tests -t .                       # offline, a few seconds
STINGWARD_ONLINE=1 python -m unittest discover -s tests -t .    # also hits the real databases
```

## FAQ

**Does a clean report mean my project is safe?** No. It means the common mistakes are not there. Stingward is a fast first line, not a penetration test.

**Does my code leave my machine?** No. Only package names and versions are sent, to look up vulnerabilities.

**How is it different from `npm audit`, Dependabot or a secret scanner?** Those each cover one piece. Stingward puts dependencies, secrets and the mistakes specific to AI-built apps, agents, skills and MCP servers in one report, written for the person who built the project, and can audit a skill before you install it.

**Why does `npx stingward` need Python?** The engine is a single pure-Python package with no dependencies; the npm package is a thin launcher so JavaScript users can run it without `pip`. On Windows, `npx` does not find the `.bat` shims of pyenv-win: install Python from python.org, or use `pip install stingward`.

**Can it check a private repository or a skill on my disk?** Yes. Point it at a folder, or at `owner/repo` with your usual git credentials.

## Scope

Stingward reports to whoever runs it, about code they chose to check. It does not crawl other people's repositories or open issues on them.

## Contributing

Bug reports, false positives and new rules are welcome. Read [CONTRIBUTING.md](https://github.com/HiveControlAgents/StingWard/blob/main/CONTRIBUTING.md) to get set up, and report security problems in Stingward itself privately as described in [SECURITY.md](https://github.com/HiveControlAgents/StingWard/blob/main/SECURITY.md).

Vulnerability data: [OSV.dev](https://osv.dev) (aggregating GitHub Advisories, NVD, PyPA, RustSec, Go and OpenSSF malicious packages), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/) and [NVD](https://nvd.nist.gov).

[Apache 2.0](https://github.com/HiveControlAgents/StingWard/blob/main/LICENSE) © Isaque Moutta
