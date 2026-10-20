# Rules

[Português](rules.pt-BR.md) · [Back to README](../README.md)

Every finding has a rule ID, a severity and the standard IDs security teams already use. Severity depends on context: the same rule can be lower in tests, docs and examples, and in third-party skills wording such as "never run this" lowers a finding to medium at most, it never hides it.

| Severity | Meaning |
|---|---|
| 🔴 critical | Exploitable as is, or a sign of an attack. Fix before shipping or installing. |
| 🟠 high | A real hole that needs specific conditions. Fix soon. |
| 🟡 medium | Risky setup or missing safeguard. |
| 🔵 low | Worth knowing, often fine. |

Standards: [CWE](https://cwe.mitre.org), [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/llm-top-10/) (`LLM01:2026`...), [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (`AST01`..., v1 draft) and [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/) (`ASI01`...).

| ID | Rule | Up to |
|---|---|---|
| [DEP001](#dep001) | Dependency version with known vulnerabilities | 🔴 |
| [DEP002](#dep002) | Malicious package | 🔴 |
| [DEP003](#dep003) | Manifest without a lockfile | 🔵 |
| [SEC001](#sec001) | Secret in code | 🔴 |
| [SEC002](#sec002) | `.env` committed to git | 🟠 |
| [SEC003](#sec003) | `.env` missing from `.gitignore` | 🟡 |
| [SEC004](#sec004) | Supabase `service_role` key in code | 🔴 |
| [APP001](#app001) | Secret exposed to the browser through a public env prefix | 🔴 |
| [APP002](#app002) | AI SDK running in the browser | 🟠 |
| [APP003](#app003) | CORS open to any origin | 🟠 |
| [APP004](#app004) | Supabase table without Row Level Security | 🟠 |
| [APP005](#app005) | Supabase policy that allows everyone | 🟠 |
| [APP006](#app006) | Open Firebase rules | 🟠 |
| [APP007](#app007) | Debug mode enabled | 🟡 |
| [APP008](#app008) | JWT accepted without verifying the signature | 🟠 |
| [AGT001](#agt001) | Agent permission too broad | 🟠 |
| [AGT002](#agt002) | Hook downloads and runs remote code | 🟠 |
| [AGT003](#agt003) | MCP server without a pinned version | 🟡 |
| [AGT004](#agt004) | Credential hard-coded in MCP config | 🔴 |
| [AGT005](#agt005) | Remote MCP server over plain HTTP | 🟡 |
| [AGT006](#agt006) | Every project MCP server auto-approved | 🟡 |
| [SKL001](#skl001) | Invisible Unicode characters | 🔴 |
| [SKL002](#skl002) | Downloads a script and pipes it into a shell | 🟠 |
| [SKL003](#skl003) | Prompt injection phrasing or tool poisoning | 🟠 |
| [SKL004](#skl004) | Reads machine credentials | 🔴 |
| [SKL005](#skl005) | Executes instructions taken from files or web pages | 🟡 |
| [SKL006](#skl006) | Skill requests unrestricted shell | 🟡 |
| [SKL007](#skl007) | Obfuscated code | 🟠 |
| [SKL008](#skl008) | Sends data to an anonymous capture service | 🟠 |
| [SKL009](#skl009) | Install script runs commands | 🟡 |
| [SKL010](#skl010) | Skill tells the agent not to pause for you | 🟡 |

## Dependencies

<a id="dep001"></a>
### DEP001 · Dependency version with known vulnerabilities

Looks up every package and version from your lockfiles (npm, Yarn, pnpm, Bun, pip `requirements.txt`, Poetry, uv, Pipenv, PDM, Go modules, Cargo, Bundler, Composer) in OSV.dev. Severity comes from the advisory (CVSS or GitHub severity); a CVE in the **CISA KEV** catalog (exploited in the wild) is raised to critical, and an **EPSS** score of 50% or more (likely exploitation in the next 30 days) raises it one level. You get one finding per package, with the single upgrade that fixes all of its known issues.

**Fix:** upgrade to the version shown. If some issues have no fix yet, the finding says so: consider replacing the package.
**Standards:** `CWE-1395`

<a id="dep002"></a>
### DEP002 · Malicious package

OSV `MAL-*` records and GitHub "malware" advisories: packages published to steal data or run code. This is an attack, not a bug.

**Fix:** remove the package, delete `node_modules`/virtualenvs, and rotate every key and password on the machine and in the project.
**Standards:** `CWE-506` · `LLM04:2026` · `AST02`

<a id="dep003"></a>
### DEP003 · Manifest without a lockfile

`package.json`, `pyproject.toml` or `requirements.txt` with version ranges and no lockfile: the versions you deploy cannot be audited and can change on every install.

**Fix:** commit the lockfile (`npm install`, `uv lock`, `poetry lock`, `pip freeze`...).
**Standards:** `CWE-1395`

## Secrets

<a id="sec001"></a>
### SEC001 · Secret in code

API keys (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack, Discord...), private keys, passwords in URLs, webhooks and sensitive assignments. The value is never printed in any report format, only its type and location. Matches in tests, docs and examples are lowered.

**Fix:** move the value to an environment variable or a secret manager, then rotate it: it is already in the history.
**Standards:** `CWE-798` · `LLM02:2026`

<a id="sec002"></a>
### SEC002 · `.env` committed to git

An `.env` file is tracked by git, so every clone and fork has its keys.

**Fix:** `git rm --cached .env`, add it to `.gitignore` and rotate the keys.
**Standards:** `CWE-538`

<a id="sec003"></a>
### SEC003 · `.env` missing from `.gitignore`

Not committed yet, but the next `git add .` takes it along.

**Fix:** add `.env` (and `.env.*`) to `.gitignore`.
**Standards:** `CWE-538`

<a id="sec004"></a>
### SEC004 · Supabase `service_role` key in code

The `service_role` key bypasses Row Level Security: whoever has it can read and change every table.

**Fix:** keep it only on the server, never in the frontend, and rotate it in the Supabase dashboard.
**Standards:** `CWE-798`

## AI-built apps

<a id="app001"></a>
### APP001 · Secret exposed to the browser through a public env prefix

A secret behind `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_` or `NUXT_PUBLIC_` is bundled into the JavaScript every visitor downloads.

**Fix:** drop the prefix, use the key only server-side (API route, server action, edge function) and rotate it.
**Standards:** `CWE-200` · `LLM02:2026`

<a id="app002"></a>
### APP002 · AI SDK running in the browser

`dangerouslyAllowBrowser: true` ships your OpenAI or Anthropic key to the browser. Someone copies it and runs up your bill.

**Fix:** call the AI API from a server route and keep the key there.
**Standards:** `CWE-522` · `LLM02:2026`

<a id="app003"></a>
### APP003 · CORS open to any origin

`Access-Control-Allow-Origin: *`, `origin: "*"`, `allow_origins=["*"]`, `cors()` with no options and similar: any website can call your API from a visitor's browser. High when credentials are also allowed.

**Fix:** allow only your own frontend domains.
**Standards:** `CWE-942`

<a id="app004"></a>
### APP004 · Supabase table without Row Level Security

A table created in a migration without `enable row level security`. With the public anon key anyone can read and change it.

**Fix:** `alter table <name> enable row level security;` and add a policy per operation.
**Standards:** `CWE-862`

<a id="app005"></a>
### APP005 · Supabase policy that allows everyone

A policy with `using (true)` or `with check (true)`. High for writes, medium for reads of sensitive tables, low for other reads.

**Fix:** use a real condition, such as `auth.uid() = user_id`.
**Standards:** `CWE-284`

<a id="app006"></a>
### APP006 · Open Firebase rules

Firestore or Storage rules with `allow read, write: if true` (or the test-mode date check), and Realtime Database rules with `".read": true` or `".write": true`.

**Fix:** require `request.auth != null` and check ownership of each document.
**Standards:** `CWE-284`

<a id="app007"></a>
### APP007 · Debug mode enabled

`DEBUG = True` (Django), `app.run(debug=True)` (Flask) and `uvicorn.run(..., reload=True, host="0.0.0.0")`: stack traces, settings and sometimes a console exposed to visitors.

**Fix:** read it from an environment variable and keep it off in production.
**Standards:** `CWE-489`

<a id="app008"></a>
### APP008 · JWT accepted without verifying the signature

`jwt.decode(..., verify=False)`, `options={"verify_signature": False}` or `algorithms=["none"]`. Anyone can forge a token.

**Fix:** verify the signature with the right key and a fixed algorithm list.
**Standards:** `CWE-347`

## Agents and MCP

<a id="agt001"></a>
### AGT001 · Agent permission too broad

`bypassPermissions`, `--dangerously-skip-permissions`, `Bash(*)`, `Bash(curl:*)` and similar entries in Claude Code, Cursor, Codex or Gemini settings. The agent runs any command without asking.

**Fix:** allow only the specific commands you need, such as `Bash(npm test:*)`.
**Standards:** `CWE-250` · `LLM03:2026` · `ASI03`

<a id="agt002"></a>
### AGT002 · Hook downloads and runs remote code

A hook that pipes `curl` or `wget` into a shell. Whoever controls that URL runs code on your machine every time the hook fires.

**Fix:** pin the script in the repository and review it.
**Standards:** `CWE-494` · `ASI05`

<a id="agt003"></a>
### AGT003 · MCP server without a pinned version

`npx some-mcp` or `uvx some-mcp` with no version: every start may run new code from the registry.

**Fix:** pin an exact version (`some-mcp@1.2.3`).
**Standards:** `CWE-494` · `LLM04:2026` · `ASI04` · `AST07`

<a id="agt004"></a>
### AGT004 · Credential hard-coded in MCP config

A token written directly in `.mcp.json`, `claude_desktop_config.json` or `mcp.json`. These files end up in git and in screenshots.

**Fix:** reference an environment variable (`"${GITHUB_TOKEN}"`) and rotate the key.
**Standards:** `CWE-798` · `LLM02:2026`

<a id="agt005"></a>
### AGT005 · Remote MCP server over plain HTTP

An MCP server URL with `http://` outside localhost: tokens and tool calls travel in clear text.

**Fix:** use `https://`.
**Standards:** `CWE-319`

<a id="agt006"></a>
### AGT006 · Every project MCP server auto-approved

`enableAllProjectMcpServers: true` starts any MCP server a cloned repository declares, without asking.

**Fix:** remove it and approve servers one by one.
**Standards:** `CWE-1188` · `ASI04`

## Skills and prompts

<a id="skl001"></a>
### SKL001 · Invisible Unicode characters

Unicode tag characters (invisible text the model reads), Trojan Source bidi controls and zero-width characters. Stingward decodes and shows the hidden message. Emoji flag sequences and normal right-to-left text are not flagged.

**Fix:** remove them in an editor that shows invisible characters. If the file came from a third party, do not install it.
**Standards:** `CWE-1427` · `LLM01:2026` · `AST01`

<a id="skl002"></a>
### SKL002 · Downloads a script and pipes it into a shell

`curl ... | sh`, `wget -O- ... | bash`, `iex (iwr ...)` and similar, in skills, scripts and instructions.

**Fix:** download, read and pin the script, or install from a package manager with a fixed version.
**Standards:** `CWE-494` · `AST02`

<a id="skl003"></a>
### SKL003 · Prompt injection phrasing or tool poisoning

"Ignore previous instructions", "do not tell the user", fake system tags, and hidden instructions inside MCP tool descriptions.

**Fix:** remove the instruction. If it came from a third party, treat the whole skill as hostile.
**Standards:** `CWE-1427` · `LLM01:2026` · `AST01`

<a id="skl004"></a>
### SKL004 · Reads machine credentials

Reads `~/.ssh`, `~/.aws/credentials`, `.env`, browser profiles or keychains. Critical when the same file also calls the internet: that is the key-theft pattern.

**Fix:** check whether the skill really needs this. Without a clear reason, do not install it.
**Standards:** `CWE-200` · `AST01`

<a id="skl005"></a>
### SKL005 · Executes instructions taken from files or web pages

"Run the commands in this issue", "follow the instructions on the page": whoever writes that content controls the agent.

**Fix:** treat external content as data; ask before running anything that came from it.
**Standards:** `CWE-1427` · `LLM01:2026` · `AST05`

<a id="skl006"></a>
### SKL006 · Skill requests unrestricted shell

`allowed-tools: Bash` (or `Bash(*)`) in `SKILL.md`: while the skill is active it can run any command without asking.

**Fix:** list specific commands, such as `Bash(git status:*)`.
**Standards:** `CWE-250` · `LLM03:2026` · `AST03`

<a id="skl007"></a>
### SKL007 · Obfuscated code

`eval(atob(...))`, `new Function(atob(...))`, `exec(base64.b64decode(...))`, `base64 -d | sh`, and large base64 or hex blobs (images and fonts are recognized and skipped). Legitimate skills have no reason to hide code.

**Fix:** decode it and read what it does. If you cannot, do not install.
**Standards:** `CWE-506` · `AST01`

<a id="skl008"></a>
### SKL008 · Sends data to an anonymous capture service

webhook.site, RequestBin, Pipedream, ngrok, interact.sh, Burp Collaborator, Telegram bots, transfer.sh and similar hosts that receive data anonymously, a common exfiltration channel.

**Fix:** find out what is sent and why. Without a clear reason, do not install.
**Standards:** `CWE-200` · `AST01`

<a id="skl009"></a>
### SKL009 · Install script runs commands

`preinstall`, `install`, `postinstall` or `prepare` scripts in `package.json`: they run on `npm install`, before you use anything.

**Fix:** read the script. Install with `--ignore-scripts` when in doubt.
**Standards:** `CWE-829` · `AST02`

<a id="skl010"></a>
### SKL010 · Skill tells the agent not to pause for you

"Do not pause to check in", "never ask for confirmation": an odd command from a plan, issue or file runs before you see it.

**Fix:** run the skill with restricted permissions and review the plan before executing.
**Standards:** `LLM03:2026` · `AST05`

## Ignoring a finding

Add a line to `.stingwardignore` in the project root (`RULE path/glob`, `RULE` alone, or `path/glob` alone), or put `stingward:ignore` in a comment on the line. Inline ignores only work in your own project, not in third-party skills audited with `stingward skill`.
