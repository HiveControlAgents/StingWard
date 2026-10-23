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
| [DEP004](#dep004) | Version range allows vulnerable versions | 🔴 |
| [DEP005](#dep005) | PHP version with known vulnerabilities | 🔴 |
| [DEP006](#dep006) | Node.js version with known vulnerabilities | 🔴 |
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
| [APP009](#app009) | Model output reaches code, a shell, SQL or HTML | 🔴 |
| [APP010](#app010) | Request input goes into the system prompt | 🟡 |
| [APP011](#app011) | AI endpoint with no login and no rate limit | 🟡 |
| [APP012](#app012) | Loading the model can run code | 🟠 |
| [APP013](#app013) | Agent can run whatever the model writes | 🟠 |
| [APP014](#app014) | Tool argument written by the model reaches a shell, code, SQL, a path or a URL | 🔴 |
| [APP015](#app015) | Function with the `service_role` key trusts the visitor | 🟠 |
| [APP016](#app016) | Database function that runs any SQL | 🔴 |
| [COD001](#cod001) | SQL query built from outside input | 🟠 |
| [COD002](#cod002) | Shell command built from outside input | 🔴 |
| [COD003](#cod003) | Code built from outside input is executed | 🔴 |
| [COD004](#cod004) | Data loaded with pickle or unsafe YAML | 🟠 |
| [COD005](#cod005) | HTML inserted without sanitizing | 🟡 |
| [COD006](#cod006) | TLS certificate check turned off | 🟡 |
| [COD007](#cod007) | File path built from request input | 🟠 |
| [COD008](#cod008) | Server fetches a URL taken from the request | 🟠 |
| [COD009](#cod009) | Redirect to an address taken from the request | 🟡 |
| [COD010](#cod010) | Predictable random number used for a secret | 🔵 |
| [COD011](#cod011) | Password hashed with a fast hash | 🟡 |
| [AGT001](#agt001) | Agent permission too broad | 🟠 |
| [AGT002](#agt002) | Hook or MCP server downloads and runs remote code | 🟠 |
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
| [SKL009](#skl009) | Install script runs commands | 🟠 |
| [SKL010](#skl010) | Skill tells the agent not to pause for you | 🟡 |
| [SKL011](#skl011) | Reverse shell | 🔴 |

## Dependencies

<a id="dep001"></a>
### DEP001 · Dependency version with known vulnerabilities

Looks up every package and version from your lockfiles (npm, Yarn, pnpm, Bun, pip `requirements.txt`, Poetry, uv, Pipenv, PDM, Go modules, Cargo, Bundler, Composer, NuGet `packages.lock.json`) in OSV.dev. Severity comes from the advisory (CVSS or GitHub severity); a CVE in the **CISA KEV** catalog (exploited in the wild) is raised to critical, and an **EPSS** score of 50% or more (likely exploitation in the next 30 days) raises it one level. You get one finding per package, with the single upgrade that fixes all of its known issues.

**Fix:** upgrade to the version shown. If some issues have no fix yet, the finding says so: consider replacing the package.
**Standards:** `CWE-1395`

<a id="dep002"></a>
### DEP002 · Malicious package

OSV `MAL-*` records and GitHub "malware" advisories: packages published to steal data or run code. This is an attack, not a bug. A pinned or locked version is critical. When it is the lowest version of a range without a lockfile (see DEP004), it is critical only when every version the range allows is malicious; when the record lists only some releases, the installed version is probably a later one and the finding is high.

**Fix:** remove the package, delete `node_modules`/virtualenvs, and rotate every key and password on the machine and in the project. When only the lowest version of a range is malicious (high), raise the range's minimum past it and commit a lockfile; clean up and rotate the keys only if the version installed is a malicious one.
**Standards:** `CWE-506` · `LLM04:2026` · `AST02`

<a id="dep003"></a>
### DEP003 · Manifest without a lockfile

`package.json` or `requirements.txt` with version ranges and no lockfile: the versions you deploy cannot be audited and can change on every install.

**Fix:** commit the lockfile (`npm install`, `uv lock`, `poetry lock`, `pip freeze`...).
**Standards:** `CWE-1395`

<a id="dep004"></a>
### DEP004 · Version range allows vulnerable versions

Without a lockfile, a range such as `Pillow>=10` or `"axios": "^1.6.0"` is all that decides the version, and its lowest version still counts: a machine that already has it keeps it, and installers can pick it. Stingward asks OSV.dev about the lowest version of each range (`>=`, `~=` and `==X.*` in Python; `^` and `~` in Poetry; `^`, `~`, `>=`, `1.2.x` and `>=a <b` in npm), in the same batch as the pinned packages, for `requirements*.txt` and `*-requirements.txt` (also the `.txt` files of a `requirements/` folder and the files they include with `-r` or `-c`) and `package.json` without a lockfile beside them and for the dependencies of a `pyproject.toml` without `poetry.lock`, `uv.lock` or `pdm.lock` (`[project]` and its optional dependencies, `[dependency-groups]`, the `dev-dependencies` of `[tool.uv]`, and Poetry's `[tool.poetry.dependencies]`, `dev-dependencies` and groups; git, path and URL dependencies are left out). A package pinned elsewhere in the project is left to DEP001. The installed version is often newer, so the finding is medium at most (low when the worst issue is below high), unless the range's upper bound leaves out the fix: then every version it allows is affected and the severity is the full DEP001 one.

**Fix:** raise the minimum to the version shown, for example replace `Pillow>=10` with `Pillow>=12.3.0`. If no version in the range has the fix, widen the range.
**Standards:** `CWE-1395`

<a id="dep005"></a>
### DEP005 · PHP version with known vulnerabilities

Reads the PHP version the project runs on and looks it up in OSV.dev, where PHP's own advisories are listed: the `php` image (also `library/php`, a known Docker Hub mirror and `bitnami/php-fpm`) on a `FROM` line of a `Dockerfile` or `Containerfile`, with the `ARG` values declared before it filled in, or on an `image:` line of `docker-compose.yml` or `compose.yaml`; `.php-version`; `php` in `.tool-versions` (asdf); and `php` in the `[tools]` table of `mise.toml`. Tags without a version (`php:latest`, `php:8-cli`), release candidates and version constraints such as `"php": "^8.2"` in `composer.json` are left out. An exact version such as `php:8.3.30-apache` is reported like DEP001, with the full severity. A tag that follows a branch, such as `php:8.3-apache` or `8.3` in `.php-version`, runs the newest 8.3 of the day the image was built or PHP was updated, so it lists what the branch's releases fixed in the last 90 days, one level lower; an issue that no release of the branch fixes, as in a branch that is no longer supported, is reported with the full severity. In tests and examples it is low.

**Fix:** use the version shown, for example change `php:8.3.30-apache` to `php:8.3.36-apache`, rebuild the image and deploy again. For a tag that follows a branch, rebuild with `docker build --pull --no-cache` or pin the version. Without Docker, update PHP where the app runs and restart PHP-FPM or Apache.
**Standards:** `CWE-1395`

<a id="dep006"></a>
### DEP006 · Node.js version with known vulnerabilities

Reads the Node.js version the app runs on and looks it up in OSV.dev, where Node.js's own advisories are listed, the same way as DEP005: the `node` image (also `library/node`, a known Docker Hub mirror and `bitnami/node`) on an `image:` line of `docker-compose.yml` or `compose.yaml`, or on the `FROM` line of the stage that runs in a `Dockerfile` or `Containerfile`. That is the last stage, or the earlier stage it starts from (`FROM base`); a stage that only builds the site, as in `FROM node:20 AS build` followed by `FROM nginx`, leaves no Node.js in the image and is left out. A major is a branch (`node:24-alpine`), and an LTS name stands for its major (`node:iron` is 20). When the project runs a server on Node.js (a `package.json` that depends on Express, Fastify, Koa, Hono, NestJS, Next.js, Nuxt, Remix, Socket.IO and similar, or whose `start` script runs `node`), the version files count too: `.nvmrc` and `.node-version` (`v24.10.0`, `24`, `lts/iron`), `nodejs` in `.tool-versions`, `node` in the `[tools]` table of `mise.toml`, and the `nodejs-20` module in the `modules` of a Replit `.replit` file. Without a server, those files usually only say which Node.js builds a static site. Tags that move between branches (`node:lts`, `node:current`, `node:latest`), release candidates, `engines` in `package.json` and `setup-node` in CI are left out. Exact versions and branches are reported as in DEP005. In tests and examples it is low.

**Fix:** use the version shown, for example change `node:24.10.0-alpine` to `node:24.22.1-alpine`, rebuild the image and deploy again. For a branch with no fix, such as Node.js 20 after its support ended, move to the branch shown (`node:22-alpine`, or `nodejs-22` in the `modules` of `.replit`), test the app and deploy again. On Replit, deploy again and check `node --version`.
**Standards:** `CWE-1395`

## Secrets

<a id="sec001"></a>
### SEC001 · Secret in code

API keys (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack, Discord, Replicate, Pinecone, Shopify, Notion, Linear, Resend, Clerk...), Google OAuth client secrets (`GOCSPX-`, high: an installed app ships its own), private keys (also in `id_rsa`, `.pem`, `.key` and `.p8` files), passwords in URLs, webhooks and sensitive assignments. The value is never printed in any report format, only its type and location. Matches in tests, docs and examples are lowered.

**Fix:** move the value to an environment variable or a secret manager, then rotate it: it is already in the history.
**Standards:** `CWE-798` · `LLM02:2026`

<a id="sec002"></a>
### SEC002 · `.env` committed to git

An `.env` file is tracked by git, so every clone and fork has its keys. The `.env.vault` of dotenv-vault holds only encrypted environments and is made to be committed: it counts only when it also holds a plain secret. The `.env.keys` that opens it still counts.

**Fix:** `git rm --cached .env`, add it to `.gitignore` and rotate the keys.
**Standards:** `CWE-538`

<a id="sec003"></a>
### SEC003 · `.env` missing from `.gitignore`

Not committed yet, but the next `git add .` takes it along. A `.env.vault` (dotenv-vault, encrypted) is left out: it is meant to be committed.

**Fix:** add `.env` (and `.env.*`) to `.gitignore`.
**Standards:** `CWE-538`

<a id="sec004"></a>
### SEC004 · Supabase `service_role` key in code

The `service_role` key bypasses Row Level Security: whoever has it can read and change every table. The default key of a local Supabase (the one `supabase start` creates on every machine: issuer `supabase-demo`, signed with the CLI's default secret) is low, with a "local default key" note, and does not make a committed `.env` high. Any other `service_role` key is critical.

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

<a id="app009"></a>
### APP009 · Model output reaches code, a shell, SQL or HTML

The answer of an LLM call (OpenAI, Anthropic, Gemini, LangChain, the AI SDK...) reaches `eval`/`exec`, a shell command, a template, a SQL query (also through `supabase.rpc('exec_sql', ...)`), or `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `unsafe_allow_html`. A prompt injection in anything the model read turns into code on your server or scripts in your users' browsers. Critical when the answer is executed, high for SQL, medium for HTML. `JSON.parse`, `json.loads` and DOMPurify break the chain. The arguments the model writes for a tool are covered by [APP014](#app014).

**Fix:** treat model output like user input: ask for JSON and validate it, map it to a fixed list of actions, pass shell arguments as a list, run SQL with a read-only user, and clean HTML with DOMPurify.
**Standards:** `CWE-1426` · `LLM10:2026`

<a id="app010"></a>
### APP010 · Request input goes into the system prompt

A request value written in the middle of the instructions: `{"role": "system", "content": f"You support {body['company']}..."}`, `` system: `... ${body.name}` ``, `SystemMessage(...)`, `system_instruction=`. Whoever sends it can rewrite your rules. User text in a user message is fine, and so is passing a whole prompt the client chose (a playground): only a value mixed into instructions written in the code is reported.

**Fix:** keep the system prompt fixed and send the user's text as a user message. If a setting must change the prompt, pick the wording from a fixed list.
**Standards:** `CWE-1427` · `LLM01:2026`

<a id="app011"></a>
### APP011 · AI endpoint with no login and no rate limit

A server route that calls a model (Next.js `app/api/**/route.ts`, a server action, an Express or Hono handler, a Supabase Edge Function, a FastAPI or Flask route), with an SDK or with `fetch` to the provider's API (OpenAI, Anthropic, Gemini, the Lovable AI Gateway, OpenRouter...), with no sign of login and no rate limit in the file, in `middleware.ts`, in a global `app.use(...)` or in router dependencies. Anyone can call it in a loop on your account. Not reported in skills, tests and examples.

**Fix:** require a signed-in user, rate limit per user or IP (`@upstash/ratelimit`, `express-rate-limit`, `slowapi`), set `max_tokens`, and add a spending limit in the provider's dashboard.
**Standards:** `CWE-306` · `CWE-770` · `LLM06:2026`

<a id="app012"></a>
### APP012 · Loading the model can run code

`from_pretrained(..., trust_remote_code=True)` runs Python from the model's repository; `FAISS.load_local(..., allow_dangerous_deserialization=True)` and `torch.load` without `weights_only=True` unpickle the file. High when the file comes from the request, medium when the unsafe option is written out, low for a plain `torch.load` (safe by default since PyTorch 2.6).

**Fix:** pin `revision=` to a commit you reviewed, pass `weights_only=True` or use safetensors, and only load indexes you created.
**Standards:** `CWE-502` · `CWE-829` · `LLM04:2026`

<a id="app013"></a>
### APP013 · Agent can run whatever the model writes

LangChain `PythonREPLTool`, `ShellTool` and `load_tools(["python_repl"])`, `allow_dangerous_code=True`, AutoGen `use_docker: False`, Open Interpreter `auto_run = True` and similar: one hidden instruction in a document, page or message becomes code running on your machine. Medium for SQL agents (`create_sql_agent`, `SQLDatabaseChain`), which run the model's SQL on your database, and for `allow_dangerous_requests=True`. Tool classes count only when they come from the agent library.

**Fix:** remove the tool, or run it in a sandbox (a container with no secrets and no network) and confirm each run. Give SQL agents a read-only database user.
**Standards:** `CWE-94` · `LLM03:2026` · `ASI05`

<a id="app014"></a>
### APP014 · Tool argument written by the model reaches a shell, code, SQL, a path or a URL

An MCP server or agent tool passes one of its arguments to a dangerous call. The AI model fills in those arguments, not you or your code, and anything it read before the call (a web page, a file, an issue, an email) can hide instructions that change what it writes. Read as tool arguments: the parameters of FastMCP `@mcp.tool()`/`@server.tool()` functions and of `mcp.add_tool(f)`, the `arguments` of a low-level `@server.call_tool()` handler, `server.tool(...)`, `server.registerTool(...)` and `setRequestHandler(CallToolRequestSchema, ...)` handlers in TypeScript, LangChain `@tool` and `BaseTool._run`, AI SDK `tool({ execute })`, and `tool_call.function.arguments` or `block.input` read from an OpenAI or Anthropic response. A value passed to a helper in the same file, to a function the tool imports from another file of the project (two levels deep), or through a `{"name": function}` table, is followed.

Severity follows the sink. Critical when the argument is mixed into a shell command or code written in the code (`os.system("git log " + ref)`, `` exec(`ls ${dir}`) ``, `["sh", "-c", f"..."]`). High when the tool runs the whole command or code it receives, for SQL built with the argument, for pickle or unsafe YAML, and for a path joined to a folder of the code (`os.path.join(BASE, name)`, where `../` leaves it). Medium for any other path, for a URL the server fetches and for HTML. In skills the finding keeps its full severity; in tests and examples it drops to low like the other code findings.

Not reported: parameters typed as numbers, booleans, `Literal`, a local `Enum` or `Field(pattern=...)`, Zod `z.number()`/`z.enum()`, parameters the framework injects (`ctx: Context`), argument lists with no shell whose program is written in the code, an argument passed first to a check such as `validate_name(arg)` or `check_path(arg)` (in TypeScript, path checks such as `validatePath(p)`), `shlex.quote`, query parameters, `basename`, `resolve()` plus an `is_relative_to`/`startsWith` check, a fixed file name inside a folder the model picks, a fixed host, an allow list of hosts, and code that runs in the browser. A tool that runs a whole SQL query it receives is a SQL tool by design and is not reported. A JSON Schema with only `"type": "string"` does not count as validation.

The CWE and the OWASP Top 10 for Agentic Applications entry depend on the sink: CWE-78 and ASI05 for shell commands, CWE-94 and ASI05 for code and templates, CWE-502 and ASI05 for pickle and YAML, CWE-89 and ASI02 for SQL, CWE-22 and ASI02 for paths, CWE-918 and ASI02 for URLs, CWE-79 for HTML.

**Fix:** treat every tool argument as untrusted input: run programs with an argument list and no shell, pass SQL values as parameters, keep paths inside one folder (resolve them and check the prefix), allow only the hosts the tool needs, and type arguments as narrowly as you can (numbers, enums, patterns). If the tool must run commands, ask the user to confirm each one.
**Standards:** `LLM03:2026`

<a id="app015"></a>
### APP015 · Function with the `service_role` key trusts the visitor

A Supabase Edge Function (`supabase/functions/*/index.ts`, the shape Lovable builds) or another server route creates a client with the `service_role` key, which skips RLS, and lets a value from the request pick the record: a filter such as `.eq('user_id', userId)`, an `update`, `delete`, `upsert` or `rpc`, a Storage path, or an `auth.admin` call such as `deleteUser(body.userId)`. Nothing in the file checks who is calling, so anyone changes the id and reads, changes or deletes someone else's data. `verify_jwt = true` does not help: the anon key in the site is already a valid token. Not reported when the file reads the user from the token (`auth.getUser`, `getClaims`, `getServerSession`, `auth()`...), checks a webhook signature (`constructEvent`, `stripe-signature`, `svix`...) or a server secret (`CRON_SECRET`, `x-api-key`), when the client uses the anon key and the caller's `Authorization` header, for inserts and for queries with fixed values. Not reported in skills.

**Fix:** read the user from the token first (`const { data: { user } } = await supabase.auth.getUser(token)`, with the token from the `Authorization` header), reject the request when there is none and use `user.id` instead of the id the request sent. Or create the client with the anon key and the `Authorization` header, so RLS applies.
**Standards:** `CWE-639` · `CWE-862`

<a id="app016"></a>
### APP016 · Database function that runs any SQL

A migration creates a `security definer` function in the `public` schema that runs SQL built from one of its text parameters: `execute query`, `execute 'select ... (' || query || ')'` or `execute format('... %s', p_where)`. It runs with the owner's rights and skips RLS, and in Supabase anyone with the anon key calls it through `supabase.rpc()`, so the caller runs any SQL on the database. Critical. Not reported for `security invoker` functions, `format()` with only `%I` and `%L`, parameters that are not text, functions outside `public`, and functions whose `execute` is revoked from both `anon` and `authenticated`.

**Fix:** drop the function. If you really need it, write one function per query that takes parameters, use `security invoker`, or run `revoke execute on function name(text) from public, anon, authenticated;`.
**Standards:** `CWE-89` · `CWE-250`

## Code

Python files are read with `ast` and JavaScript/TypeScript (also the `<script>` of `.vue`, `.svelte` and `.astro`) with tight patterns, following where each value came from inside the function: the request (Flask, FastAPI, Django, Express, Next.js, Hono...), a function argument, or another server. A call to your own helper (`get_file_by_id(id)`) is not followed, because it returns something else, and neither is a parameter the framework already turned into a number, boolean or UUID (`item_id: int`, `<int:id>`). Minified bundles and third-party libraries copied into the project (a `/*! name vX.Y` or `@license` header, `vendor/`, `third_party/`, `static/js/lib/`) are skipped in a project, but read in `stingward skill`, where they are the code that runs; tests, examples and fixtures drop to low.

<a id="cod001"></a>
### COD001 · SQL query built from outside input

An f-string, `+`, `%` or `.format()` with SQL that goes to `execute`, `text()`, `read_sql`, `pool.query`, `knex.raw`, `$queryRawUnsafe`, Django's `.extra(where=..., select=..., tables=...)` and similar. High with request data, medium with a function argument placed where a value goes (`= '{name}'`, `LIKE`, `IN (...)`). Medium when request data, model output or a tool argument picks a column or table name (`ORDER BY {order}`, `FROM {table}`, `LIMIT {limit}`); a name checked against a fixed list or taken from a dict in the code is not reported. Table names from constants, `?`/`%s`/`$1` parameters, ORM builders and tagged templates (`` sql`...` ``, `` $queryRaw`...` ``) are not reported.

**Fix:** pass values as parameters: `cursor.execute("... WHERE id = %s", (id,))`, `$1` in Postgres, `?` in SQLite, `` sql`...` `` or `` $queryRaw`...` `` in Prisma. A column or table name cannot be a parameter: pick it from a fixed list (`SORTS[key]`, `if order not in ALLOWED: abort(400)`).
**Standards:** `CWE-89`

<a id="cod002"></a>
### COD002 · Shell command built from outside input

`os.system`, `subprocess.run(..., shell=True)`, `["sh", "-c", ...]`, `exec`/`execSync` from `child_process`, `spawn(cmd, { shell: true })`, `spawn("sh", ["-c", cmd])`, execa with `shell: true` and similar with request data in the command (critical), or a function argument mixed into the command text in a web app (medium). An argument list with no shell (`subprocess.run(["ping", host])`, `execFile`, `spawn("ls", [dir])`) and command-line tools (click, typer) are not reported.

**Fix:** run the program with an argument list and no shell, and accept only values from a known list.
**Standards:** `CWE-78`

<a id="cod003"></a>
### COD003 · Code built from outside input is executed

`eval`, `exec`, `new Function`, `vm.runIn*Context`, `setTimeout` with a string, or `render_template_string` built from request data. Anyone can run code on your server. `ast.literal_eval`, `JSON.parse` and constant code are not reported.

**Fix:** do not run text as code. Parse the data you expect (`json.loads`, `JSON.parse`, `ast.literal_eval`) or map allowed values to functions.
**Standards:** `CWE-94` · `CWE-95`

<a id="cod004"></a>
### COD004 · Data loaded with pickle or unsafe YAML

`pickle`, `dill`, `joblib`, `marshal` and `yaml.load` with the full or unsafe loader. High for request data, medium for another server's response or an explicit unsafe loader, low for `yaml.load` of a local file with no `Loader`. `yaml.safe_load`, `SafeLoader` and ruamel's `YAML()` are not reported, and neither is pickle of a local file.

**Fix:** use `yaml.safe_load` or JSON for outside data; only unpickle files you wrote yourself, in a place nobody else can write to.
**Standards:** `CWE-502`

<a id="cod005"></a>
### COD005 · HTML inserted without sanitizing

`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `set:html`, `Markup()`, `res.send`/`res.write`/`res.end` in Express, `c.html` in Hono, or an HTML string returned by a Flask route or a FastAPI route with `response_class=HTMLResponse`, with data from the URL or the request (medium). In JavaScript, HTML built from other variables is low. `DOMPurify.sanitize`, `escapeHtml`, `textContent`, plain JSX, constant HTML, `res.json` and text with no HTML tag are not reported.

**Fix:** show it as text (`textContent`, or the variable straight in JSX) or clean it first with `DOMPurify.sanitize` (sanitize-html or bleach on the server).
**Standards:** `CWE-79`

<a id="cod006"></a>
### COD006 · TLS certificate check turned off

`verify=False` in requests/httpx, `session.verify = False`, `ssl._create_unverified_context`, `CERT_NONE`, `rejectUnauthorized: false`, and `NODE_TLS_REJECT_UNAUTHORIZED=0` in code, `.env` files, Dockerfiles or YAML. Anyone on the network path can pose as the server.

**Fix:** remove the switch. For a private CA, point to its certificate (`verify="/path/ca.pem"` in Python, `ca:` in Node).
**Standards:** `CWE-295`

<a id="cod007"></a>
### COD007 · File path built from request input

`open`, `send_file`, `FileResponse`, `Path(...).read_text`, `fs.readFile`, `res.sendFile` and similar with a request value in the path. `secure_filename`, `basename`, a `resolve()` plus `is_relative_to`/`startsWith` check, `sendFile(..., { root })`, the server-chosen path of an upload (`req.file.path`), a route segment that cannot hold `/` (`/files/{id}`) and admin-only routes are not reported.

**Fix:** keep only the file name (`os.path.basename`, `secure_filename`, `path.basename`), or resolve the path and check that it stays inside the folder you expect.
**Standards:** `CWE-22`

<a id="cod008"></a>
### COD008 · Server fetches a URL taken from the request

`requests.get`, `httpx`, `urlopen`, `fetch`, `axios` and similar on the server when the request decides where the URL points (the whole URL or its start). A fixed host with a request value in the path, a check of the host (`urlparse(...).hostname`, an allow list) and code that runs in the browser are not reported. High, or medium when the host comes from the request's own `Host` or `X-Forwarded-Host` header (`f"https://{request.headers['Host']}/api"`): another person's browser cannot set it, and the proxy in front usually checks it, but whoever calls the server directly can.

**Fix:** allow only the domains you need, block private and local addresses, and do not follow redirects without checking them.
**Standards:** `CWE-918`

<a id="cod009"></a>
### COD009 · Redirect to an address taken from the request

`redirect(request.args["next"])`, `res.redirect(req.query.returnTo)`, `NextResponse.redirect`, `location.href =` with a URL parameter, and similar. A path that starts with a fixed `/...`, `url_for` and a check of the host are not reported. A start made only of slashes (`"/" + next`, `` `/${next}` ``, `"//" + host`) is reported: with `next = "/evil.com"` the browser goes to `//evil.com`, another site. So is a host from the request right after a fixed scheme (`"https://" + request.args["host"]`, `` `https://${req.body.host}/home` ``), but not one from the `Host` or `X-Forwarded-Host` header: that is the site's own host, which nobody else's browser picks.

**Fix:** redirect only to relative paths that start with a single `/` or to domains from a known list.
**Standards:** `CWE-601`

<a id="cod010"></a>
### COD010 · Predictable random number used for a secret

`Math.random()` or Python's `random` assigned to (or returned by) something named like a secret: `reset_token`, `apiKey`, `password`, `otp`, `verification_code`, also at module level and when the value is built in a callback (`[...Array(32)].map(() => ...Math.random()...)`). A session id (`session_id`, `sessionId`, `sid`) counts when it goes into a cookie. Names like `token_count` or `delay`, a session id that never reaches a cookie, and tests are not reported.

**Fix:** use `crypto.randomUUID()` or `crypto.getRandomValues` in JavaScript, and the `secrets` module in Python (`secrets.token_urlsafe`).
**Standards:** `CWE-338`

<a id="cod011"></a>
### COD011 · Password hashed with a fast hash

MD5, SHA-1 or SHA-2 (`hashlib.sha256(password...)`, `createHash("sha256").update(password)`, CryptoJS) applied to a variable named like a password. If the database leaks, the passwords fall to brute force. Hashes of files or request bodies are not reported.

**Fix:** use a function made for passwords: bcrypt, scrypt or Argon2 (argon2-cffi and bcrypt in Python, bcrypt in Node), or leave login to an auth provider.
**Standards:** `CWE-916`

## Agents and MCP

<a id="agt001"></a>
### AGT001 · Agent permission too broad

`bypassPermissions`, `--dangerously-skip-permissions`, `Bash(*)`, `Bash(curl:*)` and similar entries in Claude Code, Cursor, Codex or Gemini settings. The agent runs any command without asking.

**Fix:** allow only the specific commands you need, such as `Bash(npm test:*)`.
**Standards:** `CWE-250` · `LLM03:2026` · `ASI03`

<a id="agt002"></a>
### AGT002 · Hook or MCP server downloads and runs remote code

A hook command, or the command that launches an MCP server (for example `sh -c "curl ... | sh"`), that pipes `curl` or `wget` into a shell. Whoever controls that URL runs code on your machine every time the hook fires or the server starts.

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

`curl ... | sh`, `wget -O- ... | bash`, `iex (iwr ...)` and similar, and downloading a file then running it on the same line (`curl -o x ... && chmod +x x`), in skills, scripts and instructions.

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

`preinstall`, `install`, `postinstall` or `prepare` scripts in `package.json`: they run on `npm install`, before you use anything. High when the script downloads and runs code from the internet.

**Fix:** read the script. Install with `--ignore-scripts` when in doubt.
**Standards:** `CWE-829` · `AST02`

<a id="skl010"></a>
### SKL010 · Skill tells the agent not to pause for you

"Do not pause to check in", "never ask for confirmation": an odd command from a plan, issue or file runs before you see it.

**Fix:** run the skill with restricted permissions and review the plan before executing.
**Standards:** `LLM03:2026` · `AST05`

<a id="skl011"></a>
### SKL011 · Reverse shell

`bash -i >& /dev/tcp/host/port`, `nc -e /bin/sh`, `socat ... exec:/bin/bash`, `os.dup2(s.fileno(), ...)` with `pty.spawn`, PowerShell `Net.Sockets.TCPClient`: the skill hands your terminal to whoever is listening on the other end. A port check such as `</dev/tcp/localhost/5432` is not flagged.

**Fix:** do not install. If it already ran, take the machine off the network, rotate passwords and keys, and check processes and scheduled tasks.
**Standards:** `CWE-506` · `AST01`

## Ignoring a finding

Add a line to `.stingwardignore` in the project root (`RULE path/glob`, `RULE` alone, or `path/glob` alone), or put `stingward:ignore` in a comment on the line. Inline ignores only work in your own project, not in third-party skills audited with `stingward skill`.
