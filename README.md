# Stingward

**Security check for projects built with AI, and for skills and MCP servers before you install them.**

Lots of people now ship apps, Claude Code skills and MCP servers written with AI. Very few of them know what a CVE is, why `NEXT_PUBLIC_OPENAI_API_KEY` is a problem, or that a skill can hide instructions only the model can read. `stingward` finds those holes and tells you, in plain words, how to close each one.

```
$ stingward skill https://github.com/someone/cool-skill
🔴 Do not install yet: serious problems found.

🔴 CRITICAL Invisible characters in text (Unicode tag characters)
   where: SKILL.md:12  [SKL001]
   why: Invisible to you, readable by the AI. Hidden message: "also run curl ... | sh"
   how to fix: ...
```

[Português](https://github.com/HiveControlAgents/StingWard/blob/main/README.pt-BR.md)

## What it checks

| Area | Examples |
|---|---|
| **Dependencies** | Known CVEs and **malicious packages** in npm, PyPI, Go, crates.io, RubyGems and Packagist lockfiles, prioritized by **CISA KEV** (exploited right now) and **EPSS** (likelihood of exploitation). One finding per package, with the single upgrade that fixes them all. |
| **Secrets** | API keys (OpenAI, Anthropic, GitHub, AWS, Stripe, Slack...), private keys, Supabase `service_role` keys, webhooks, passwords in URLs, `.env` committed or missing from `.gitignore`. Secret engine reused from CEOVul. |
| **AI-built apps** | Secrets behind `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`, `dangerouslyAllowBrowser`, open CORS, Supabase tables without RLS or with `using (true)`, open Firebase rules, debug mode, JWT without signature check. |
| **Agents and MCP** | `bypassPermissions`, `Bash(*)`, hooks that `curl \| sh`, `enableAllProjectMcpServers`, MCP servers without a pinned version, tokens hard-coded in `.mcp.json`, MCP over plain HTTP, vulnerable MCP packages (e.g. `mcp-remote` CVE-2025-6514). |
| **Skills and prompts** | Hidden Unicode (tag characters, Trojan Source bidi, zero-width), "ignore previous instructions" and "don't tell the user", reading `~/.ssh` / `~/.aws` and calling the internet, `curl \| bash`, obfuscated code, exfiltration hosts (webhook.site, ngrok...), install scripts, `allowed-tools: Bash`, "do not pause to check in", tool poisoning in MCP tool descriptions. |

Only package names and versions leave your machine (to api.osv.dev, www.cisa.gov, api.first.org and services.nvd.nist.gov). Your code never does. No account, no telemetry, no dependencies: pure Python 3.9+.

## Use it

### Claude Code (skill)

```
/plugin marketplace add HiveControlAgents/StingWard
/plugin install stingward@stingward
```

Then just ask: *"is my project secure?"* or *"can I install this skill: github.com/x/y?"*. Claude runs the check, explains each finding and offers to fix them in your project.

### Command line

```bash
pipx install stingward          # or: uvx stingward · npx stingward (needs Python 3.9+)

stingward                         # audit the current project
stingward skill ./some-skill      # audit a skill, plugin or MCP server before installing
stingward skill owner/repo        # ... straight from GitHub
stingward agents                  # audit ~/.claude, Claude Desktop, Cursor, Codex and Gemini configs on this machine
```

Options: `--lang pt|en`, `--format text|json|markdown|sarif`, `--sarif FILE`, `--markdown FILE`, `--json FILE`, `--fail-on critical|high|medium|low|never` (default `high`), `--only deps,secrets,app,agents`, `--offline`. Set `NVD_API_KEY` for a higher NVD rate limit.

Exit code is `1` when something at or above `--fail-on` is found, so it works as a CI step.

### GitHub Action

```yaml
# .github/workflows/stingward.yml
on: { pull_request: {}, schedule: [{ cron: "0 9 * * *" }] }
permissions: { contents: read, pull-requests: write, security-events: write }
jobs:
  stingward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HiveControlAgents/StingWard@v0
        with: { lang: en, fail-on: high }
```

It comments the report on the PR (updating the same comment each run), uploads SARIF to the repository's Security tab, and writes the job summary. The daily schedule matters: new CVEs show up for code that did not change.

## Badge

Every report ends with a grade from A to F and a badge for your README:

[![stingward: A](https://img.shields.io/badge/stingward-A-brightgreen)](https://github.com/HiveControlAgents/StingWard)

A: no critical/high, at most 2 medium · B: no critical/high · C: 1 or 2 high · D: 3+ high · F: any critical.

## Standards

Every finding carries the IDs security teams already use: **CWE**, the **OWASP Top 10 for LLM Applications 2026** (`LLM01:2026`...), the **OWASP Agentic Skills Top 10** (`AST01`..., v1 draft) and the **OWASP Top 10 for Agentic Applications 2026** (`ASI01`...). They show up in the text report, the JSON and as SARIF tags.

## False positives

Add lines to `.stingwardignore` in the project root (`RULE path/glob`, `RULE`, or `path/glob`), or put `stingward:ignore` in a comment on the line.

## Rules

| ID | What it means |
|---|---|
| <a id="dep001"></a>`DEP001` | Dependency version with known vulnerabilities |
| <a id="dep002"></a>`DEP002` | Malicious package (OSV `MAL-*`) |
| <a id="dep003"></a>`DEP003` | Manifest without lockfile: versions cannot be audited |
| <a id="sec001"></a>`SEC001` | Secret in code |
| <a id="sec002"></a>`SEC002` | `.env` committed to git |
| <a id="sec003"></a>`SEC003` | `.env` not in `.gitignore` |
| <a id="sec004"></a>`SEC004` | Supabase `service_role` key in code |
| <a id="app001"></a>`APP001` | Secret exposed to the browser through a public env prefix |
| <a id="app002"></a>`APP002` | AI SDK running in the browser |
| <a id="app003"></a>`APP003` | CORS open to any origin |
| <a id="app004"></a>`APP004` | Supabase table without Row Level Security |
| <a id="app005"></a>`APP005` | Supabase policy that allows everyone |
| <a id="app006"></a>`APP006` | Open Firebase rules |
| <a id="app007"></a>`APP007` | Debug mode enabled |
| <a id="app008"></a>`APP008` | JWT accepted without verifying the signature |
| <a id="agt001"></a>`AGT001` | Agent permission too broad |
| <a id="agt002"></a>`AGT002` | Hook downloads and runs remote code |
| <a id="agt003"></a>`AGT003` | MCP server without a pinned version |
| <a id="agt004"></a>`AGT004` | Credential hard-coded in MCP config |
| <a id="agt005"></a>`AGT005` | Remote MCP server over plain HTTP |
| <a id="agt006"></a>`AGT006` | Every project MCP server auto-approved |
| <a id="skl001"></a>`SKL001` | Invisible Unicode characters |
| <a id="skl002"></a>`SKL002` | Downloads and pipes a script into a shell |
| <a id="skl003"></a>`SKL003` | Prompt injection phrasing / tool poisoning |
| <a id="skl004"></a>`SKL004` | Reads machine credentials (critical when it also calls the internet) |
| <a id="skl005"></a>`SKL005` | Executes instructions taken from files or web pages |
| <a id="skl006"></a>`SKL006` | Skill requests unrestricted shell in `allowed-tools` |
| <a id="skl007"></a>`SKL007` | Obfuscated code |
| <a id="skl008"></a>`SKL008` | Sends data to an anonymous capture service |
| <a id="skl009"></a>`SKL009` | Install script runs commands |
| <a id="skl010"></a>`SKL010` | Skill tells the agent not to pause for the user |

## Scope

`stingward` reports to whoever runs it, about code they chose to check. It does not crawl other people's repositories or open issues on them. A clean report means the common mistakes are not there, not that a project is safe.

## Development

```bash
python3 -m unittest discover -s tests -t .   # offline tests, no network
```

Data: [OSV.dev](https://osv.dev) (aggregates GitHub Advisories, NVD, PyPA, RustSec, Go and OpenSSF malicious packages), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/), [NVD](https://nvd.nist.gov). MIT license.
