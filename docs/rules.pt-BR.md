# Regras

[English](rules.md) · [Voltar ao README](../README.pt-BR.md)

Todo achado tem um código de regra, uma severidade e os códigos de padrão que times de segurança já usam. A severidade depende do contexto: a mesma regra pode cair em testes, documentação e exemplos, e numa skill de terceiros um texto como "nunca rode isto" baixa o achado no máximo para médio, nunca o esconde.

| Severidade | O que quer dizer |
|---|---|
| 🔴 crítica | Explorável do jeito que está, ou sinal de ataque. Corrija antes de publicar ou instalar. |
| 🟠 alta | Brecha real que depende de alguma condição. Corrija logo. |
| 🟡 média | Configuração arriscada ou proteção que falta. |
| 🔵 baixa | Vale saber, muitas vezes está tudo bem. |

Padrões: [CWE](https://cwe.mitre.org), [OWASP Top 10 para Aplicações com LLM 2026](https://genai.owasp.org/llm-top-10/) (`LLM01:2026`...), [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (`AST01`..., rascunho v1) e [OWASP Top 10 para Aplicações Agênticas 2026](https://genai.owasp.org/) (`ASI01`...).

| Código | Regra | Até |
|---|---|---|
| [DEP001](#dep001) | Versão de dependência com falhas conhecidas | 🔴 |
| [DEP002](#dep002) | Pacote malicioso | 🔴 |
| [DEP003](#dep003) | Manifesto sem lockfile | 🔵 |
| [DEP004](#dep004) | Faixa de versão aceita versões com falhas | 🔴 |
| [DEP005](#dep005) | Versão do PHP com falhas conhecidas | 🔴 |
| [SEC001](#sec001) | Segredo no código | 🔴 |
| [SEC002](#sec002) | `.env` no git | 🟠 |
| [SEC003](#sec003) | `.env` fora do `.gitignore` | 🟡 |
| [SEC004](#sec004) | Chave `service_role` do Supabase no código | 🔴 |
| [APP001](#app001) | Segredo exposto ao navegador por prefixo público | 🔴 |
| [APP002](#app002) | SDK de IA rodando no navegador | 🟠 |
| [APP003](#app003) | CORS aberto para qualquer origem | 🟠 |
| [APP004](#app004) | Tabela do Supabase sem Row Level Security | 🟠 |
| [APP005](#app005) | Política do Supabase que libera para todos | 🟠 |
| [APP006](#app006) | Regras do Firebase abertas | 🟠 |
| [APP007](#app007) | Modo debug ligado | 🟡 |
| [APP008](#app008) | JWT aceito sem verificar a assinatura | 🟠 |
| [APP009](#app009) | Saída do modelo chega a código, shell, SQL ou HTML | 🔴 |
| [APP010](#app010) | Dado da requisição entra no prompt de sistema | 🟡 |
| [APP011](#app011) | Rota de IA sem login e sem limite de uso | 🟡 |
| [APP012](#app012) | Carregar o modelo pode executar código | 🟠 |
| [APP013](#app013) | Agente pode executar o que o modelo escrever | 🟠 |
| [APP014](#app014) | Argumento que o modelo escreve na ferramenta chega a shell, código, SQL, caminho ou URL | 🔴 |
| [COD001](#cod001) | Consulta SQL montada com dado de fora | 🟠 |
| [COD002](#cod002) | Comando de shell montado com dado de fora | 🔴 |
| [COD003](#cod003) | Código montado com dado de fora é executado | 🔴 |
| [COD004](#cod004) | Dados carregados com pickle ou YAML inseguro | 🟠 |
| [COD005](#cod005) | HTML inserido sem limpar | 🟡 |
| [COD006](#cod006) | Verificação do certificado TLS desligada | 🟡 |
| [COD007](#cod007) | Caminho de arquivo montado com dados da requisição | 🟠 |
| [COD008](#cod008) | Servidor busca uma URL que veio da requisição | 🟠 |
| [COD009](#cod009) | Redirecionamento para um endereço que veio da requisição | 🟡 |
| [COD010](#cod010) | Número aleatório previsível usado num segredo | 🔵 |
| [COD011](#cod011) | Senha guardada com hash rápido | 🟡 |
| [AGT001](#agt001) | Permissão de agente ampla demais | 🟠 |
| [AGT002](#agt002) | Hook ou servidor MCP que baixa e executa código | 🟠 |
| [AGT003](#agt003) | Servidor MCP sem versão fixa | 🟡 |
| [AGT004](#agt004) | Credencial escrita na configuração do MCP | 🔴 |
| [AGT005](#agt005) | Servidor MCP remoto sem HTTPS | 🟡 |
| [AGT006](#agt006) | Todos os servidores MCP do projeto aprovados automaticamente | 🟡 |
| [SKL001](#skl001) | Caracteres Unicode invisíveis | 🔴 |
| [SKL002](#skl002) | Baixa um script e passa direto para o shell | 🟠 |
| [SKL003](#skl003) | Injeção de prompt ou envenenamento de ferramenta | 🟠 |
| [SKL004](#skl004) | Lê credenciais da máquina | 🔴 |
| [SKL005](#skl005) | Executa instruções vindas de arquivos ou páginas | 🟡 |
| [SKL006](#skl006) | Skill pede shell sem restrição | 🟡 |
| [SKL007](#skl007) | Código ofuscado | 🟠 |
| [SKL008](#skl008) | Envia dados para serviço de captura anônimo | 🟠 |
| [SKL009](#skl009) | Script de instalação executa comandos | 🟠 |
| [SKL010](#skl010) | Skill manda o agente não parar para falar com você | 🟡 |
| [SKL011](#skl011) | Reverse shell | 🔴 |

## Dependências

<a id="dep001"></a>
### DEP001 · Versão de dependência com falhas conhecidas

Consulta no OSV.dev cada pacote e versão dos seus lockfiles (npm, Yarn, pnpm, Bun, `requirements.txt` do pip, Poetry, uv, Pipenv, PDM, módulos Go, Cargo, Bundler, Composer, `packages.lock.json` do NuGet). A severidade vem do alerta (CVSS ou severidade do GitHub); uma CVE no catálogo **KEV da CISA** (explorada agora) sobe para crítica, e um **EPSS** de 50% ou mais (exploração provável nos próximos 30 dias) sobe um nível. Sai um achado por pacote, com a atualização única que resolve todas as falhas conhecidas.

**Como corrigir:** atualize para a versão indicada. Se alguma falha ainda não tem correção, o achado avisa: pense em trocar de pacote.
**Padrões:** `CWE-1395`

<a id="dep002"></a>
### DEP002 · Pacote malicioso

Registros `MAL-*` do OSV e alertas de "malware" do GitHub: pacotes publicados para roubar dados ou executar código. É ataque, não bug. Versão fixada ou travada no lockfile é crítica. Quando é a menor versão de uma faixa sem lockfile (veja o DEP004), só é crítica se toda versão aceita pela faixa é maliciosa; quando o registro cita só algumas versões, a instalada provavelmente é uma posterior e o achado é alto.

**Como corrigir:** remova o pacote, apague `node_modules`/virtualenvs e troque todas as chaves e senhas da máquina e do projeto. Quando só a menor versão de uma faixa é maliciosa (alto), suba a versão mínima da faixa para depois dela e faça commit do lockfile; limpe a máquina e troque as chaves só se a versão instalada for uma das maliciosas.
**Padrões:** `CWE-506` · `LLM04:2026` · `AST02`

<a id="dep003"></a>
### DEP003 · Manifesto sem lockfile

`package.json` ou `requirements.txt` com faixas de versão e sem lockfile: não dá para auditar as versões que vão para produção, e elas mudam a cada instalação.

**Como corrigir:** gere e envie o lockfile (`npm install`, `uv lock`, `poetry lock`, `pip freeze`...).
**Padrões:** `CWE-1395`

<a id="dep004"></a>
### DEP004 · Faixa de versão aceita versões com falhas

Sem lockfile, uma faixa como `Pillow>=10` ou `"axios": "^1.6.0"` é tudo o que decide a versão, e a menor versão dela continua valendo: quem já tem essa versão instalada fica com ela, e o instalador pode escolhê-la. O Stingward consulta no OSV.dev a menor versão de cada faixa (`>=`, `~=` e `==X.*` no Python; `^` e `~` no Poetry; `^`, `~`, `>=`, `1.2.x` e `>=a <b` no npm), no mesmo lote dos pacotes fixados, em `requirements*.txt` e `*-requirements.txt` (também os `.txt` de uma pasta `requirements/` e os arquivos que eles incluem com `-r` ou `-c`) e `package.json` sem lockfile ao lado e nas dependências de um `pyproject.toml` sem `poetry.lock`, `uv.lock` ou `pdm.lock` (`[project]` e as dependências opcionais, `[dependency-groups]`, o `dev-dependencies` do `[tool.uv]` e, no Poetry, `[tool.poetry.dependencies]`, `dev-dependencies` e os grupos; dependência de git, path ou URL fica de fora). Pacote fixado em outro arquivo do projeto fica com o DEP001. A versão instalada costuma ser mais nova, então o achado vai no máximo a médio (baixo quando a pior falha fica abaixo de alta), a não ser que o teto da faixa deixe a correção de fora: aí toda versão aceita tem a falha e a severidade é a mesma do DEP001.

**Como corrigir:** suba a versão mínima para a indicada, por exemplo troque `Pillow>=10` por `Pillow>=12.3.0`. Se nenhuma versão da faixa tem a correção, amplie a faixa.
**Padrões:** `CWE-1395`

<a id="dep005"></a>
### DEP005 · Versão do PHP com falhas conhecidas

Lê a versão do PHP em que o projeto roda e a consulta no OSV.dev, onde estão os avisos do próprio PHP: a imagem `php` (também `library/php`, um espelho conhecido do Docker Hub e `bitnami/php-fpm`) numa linha `FROM` de `Dockerfile` ou `Containerfile`, com os valores dos `ARG` declarados antes dela, ou numa linha `image:` de `docker-compose.yml` ou `compose.yaml`; `.php-version`; o `php` do `.tool-versions` (asdf); e o `php` da tabela `[tools]` do `mise.toml`. Tag sem versão (`php:latest`, `php:8-cli`), versão de teste (RC) e restrição de versão como `"php": "^8.2"` no `composer.json` ficam de fora. Uma versão exata como `php:8.3.30-apache` sai como no DEP001, com a severidade cheia. Uma tag que acompanha a série, como `php:8.3-apache` ou `8.3` no `.php-version`, roda a 8.3 mais nova do dia em que a imagem foi montada ou o PHP foi atualizado, então o achado lista o que as versões da série corrigiram nos últimos 90 dias, um nível abaixo; a falha que nenhuma versão da série corrige, como numa série sem suporte, sai com a severidade cheia. Em testes e exemplos fica baixa.

**Como corrigir:** use a versão indicada, por exemplo troque `php:8.3.30-apache` por `php:8.3.36-apache`, monte a imagem de novo e publique. Numa tag que acompanha a série, monte de novo com `docker build --pull --no-cache` ou fixe a versão. Sem Docker, atualize o PHP onde o app roda e reinicie o PHP-FPM ou o Apache.
**Padrões:** `CWE-1395`

## Segredos

<a id="sec001"></a>
### SEC001 · Segredo no código

Chaves de API (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack, Discord, Replicate, Pinecone, Shopify, Notion, Linear, Resend, Clerk...), segredos de cliente OAuth do Google (`GOCSPX-`, alto: um app instalado leva o seu junto), chaves privadas (também em arquivos `id_rsa`, `.pem`, `.key` e `.p8`), senha em URL, webhooks e atribuições sensíveis. O valor nunca aparece em nenhum formato de relatório, só o tipo e o lugar. Em testes, documentação e exemplos a severidade cai.

**Como corrigir:** mova o valor para variável de ambiente ou cofre de segredos e troque a chave: ela já está no histórico.
**Padrões:** `CWE-798` · `LLM02:2026`

<a id="sec002"></a>
### SEC002 · `.env` no git

O `.env` está versionado, então todo clone e fork leva as chaves junto. O `.env.vault` do dotenv-vault só guarda os ambientes cifrados e é feito para ir ao git: só conta se também tiver um segredo em texto puro. O `.env.keys`, que abre o cofre, continua contando.

**Como corrigir:** `git rm --cached .env`, coloque no `.gitignore` e troque as chaves.
**Padrões:** `CWE-538`

<a id="sec003"></a>
### SEC003 · `.env` fora do `.gitignore`

Ainda não foi para o git, mas o próximo `git add .` leva junto. O `.env.vault` (dotenv-vault, cifrado) fica de fora: ele é feito para ir ao git.

**Como corrigir:** adicione `.env` (e `.env.*`) ao `.gitignore`.
**Padrões:** `CWE-538`

<a id="sec004"></a>
### SEC004 · Chave `service_role` do Supabase no código

A chave `service_role` passa por cima do Row Level Security: quem tem a chave lê e altera qualquer tabela. A chave padrão do Supabase local (a que o `supabase start` cria em toda máquina: emissor `supabase-demo`, assinada com o segredo padrão do CLI) é baixa, com a nota "chave padrão do ambiente local", e não deixa alto um `.env` no git. Qualquer outra chave `service_role` é crítica.

**Como corrigir:** use só no servidor, nunca no front-end, e gere outra no painel do Supabase.
**Padrões:** `CWE-798`

## Apps feitos com IA

<a id="app001"></a>
### APP001 · Segredo exposto ao navegador por prefixo público

Segredo atrás de `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_` ou `NUXT_PUBLIC_` vai dentro do JavaScript que todo visitante baixa.

**Como corrigir:** tire o prefixo, use a chave só no servidor (rota de API, server action, edge function) e troque a chave.
**Padrões:** `CWE-200` · `LLM02:2026`

<a id="app002"></a>
### APP002 · SDK de IA rodando no navegador

`dangerouslyAllowBrowser: true` manda sua chave da OpenAI ou Anthropic para o navegador. Alguém copia e a conta vem para você.

**Como corrigir:** chame a API de IA de uma rota no servidor e deixe a chave lá.
**Padrões:** `CWE-522` · `LLM02:2026`

<a id="app003"></a>
### APP003 · CORS aberto para qualquer origem

`Access-Control-Allow-Origin: *`, `origin: "*"`, `allow_origins=["*"]`, `cors()` sem opções e parecidos: qualquer site chama sua API pelo navegador do visitante. Alta quando também libera credenciais.

**Como corrigir:** libere só os domínios do seu front-end.
**Padrões:** `CWE-942`

<a id="app004"></a>
### APP004 · Tabela do Supabase sem Row Level Security

Tabela criada numa migration sem `enable row level security`. Com a chave anon, que é pública, qualquer pessoa lê e altera a tabela.

**Como corrigir:** `alter table <nome> enable row level security;` e crie uma política por operação.
**Padrões:** `CWE-862`

<a id="app005"></a>
### APP005 · Política do Supabase que libera para todos

Política com `using (true)` ou `with check (true)`. Alta para escrita, média para leitura de tabela sensível, baixa para outras leituras.

**Como corrigir:** use uma condição de verdade, como `auth.uid() = user_id`.
**Padrões:** `CWE-284`

<a id="app006"></a>
### APP006 · Regras do Firebase abertas

Regras do Firestore ou Storage com `allow read, write: if true` (ou a data do modo de teste), e do Realtime Database com `".read": true` ou `".write": true`.

**Como corrigir:** exija `request.auth != null` e confira o dono de cada documento.
**Padrões:** `CWE-284`

<a id="app007"></a>
### APP007 · Modo debug ligado

`DEBUG = True` (Django), `app.run(debug=True)` (Flask) e `uvicorn.run(..., reload=True, host="0.0.0.0")`: stack trace, configurações e às vezes um console abertos para visitantes.

**Como corrigir:** leia de uma variável de ambiente e deixe desligado em produção.
**Padrões:** `CWE-489`

<a id="app008"></a>
### APP008 · JWT aceito sem verificar a assinatura

`jwt.decode(..., verify=False)`, `options={"verify_signature": False}` ou `algorithms=["none"]`. Qualquer pessoa forja um token.

**Como corrigir:** verifique a assinatura com a chave certa e uma lista fixa de algoritmos.
**Padrões:** `CWE-347`

<a id="app009"></a>
### APP009 · Saída do modelo chega a código, shell, SQL ou HTML

A resposta de uma chamada de LLM (OpenAI, Anthropic, Gemini, LangChain, AI SDK...) chega a `eval`/`exec`, um comando de shell, um template, uma consulta SQL, ou `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `unsafe_allow_html`. Uma injeção de prompt em qualquer coisa que o modelo leu vira código no seu servidor ou script no navegador de quem usa o app. Crítico quando a resposta é executada, alto para SQL, médio para HTML. `JSON.parse`, `json.loads` e DOMPurify cortam a cadeia. Os argumentos que o modelo escreve numa ferramenta ficam com a [APP014](#app014).

**Como corrigir:** trate a saída do modelo como entrada de usuário: peça JSON e valide, mapeie para uma lista fixa de ações, passe os argumentos do shell em lista, rode o SQL com um usuário só de leitura e limpe o HTML com DOMPurify.
**Padrões:** `CWE-1426` · `LLM10:2026`

<a id="app010"></a>
### APP010 · Dado da requisição entra no prompt de sistema

Um valor da requisição escrito no meio das instruções: `{"role": "system", "content": f"Você atende {body['empresa']}..."}`, `` system: `... ${body.name}` ``, `SystemMessage(...)`, `system_instruction=`. Quem manda esse valor pode reescrever as suas regras. Texto do usuário numa mensagem de usuário está certo, e repassar inteiro um prompt que o cliente escolheu (um playground) também: só entra o valor misturado com instruções escritas no código.

**Como corrigir:** deixe o prompt de sistema fixo e mande o texto do usuário como mensagem de usuário. Se uma opção precisa mudar o prompt, escolha o trecho numa lista fixa.
**Padrões:** `CWE-1427` · `LLM01:2026`

<a id="app011"></a>
### APP011 · Rota de IA sem login e sem limite de uso

Uma rota do servidor que chama um modelo (`app/api/**/route.ts` do Next.js, server action, handler do Express ou Hono, rota do FastAPI ou Flask) sem sinal de login nem limite de pedidos no arquivo, no `middleware.ts`, num `app.use(...)` global ou nas dependências do router. Qualquer pessoa chama em loop na sua conta. Não entra em skills, testes e exemplos.

**Como corrigir:** exija usuário logado, limite pedidos por usuário ou IP (`@upstash/ratelimit`, `express-rate-limit`, `slowapi`), defina `max_tokens` e ponha um limite de gasto no painel do provedor.
**Padrões:** `CWE-306` · `CWE-770` · `LLM06:2026`

<a id="app012"></a>
### APP012 · Carregar o modelo pode executar código

`from_pretrained(..., trust_remote_code=True)` roda Python do repositório do modelo; `FAISS.load_local(..., allow_dangerous_deserialization=True)` e `torch.load` sem `weights_only=True` abrem o arquivo com pickle. Alto quando o arquivo vem da requisição, médio quando a opção insegura está escrita, baixo para um `torch.load` simples (seguro por padrão desde o PyTorch 2.6).

**Como corrigir:** fixe `revision=` num commit revisado, passe `weights_only=True` ou use safetensors, e carregue só índices criados por você.
**Padrões:** `CWE-502` · `CWE-829` · `LLM04:2026`

<a id="app013"></a>
### APP013 · Agente pode executar o que o modelo escrever

`PythonREPLTool`, `ShellTool` e `load_tools(["python_repl"])` do LangChain, `allow_dangerous_code=True`, `use_docker: False` do AutoGen, `auto_run = True` do Open Interpreter e parecidos: uma instrução escondida num documento, página ou mensagem vira código rodando na sua máquina. Médio para agentes de SQL (`create_sql_agent`, `SQLDatabaseChain`), que rodam no seu banco o SQL do modelo, e para `allow_dangerous_requests=True`. Classes de ferramenta só contam quando vêm da biblioteca de agentes.

**Como corrigir:** tire a ferramenta, ou rode numa sandbox (container sem segredos e sem rede) e confirme cada execução. Dê aos agentes de SQL um usuário de banco só de leitura.
**Padrões:** `CWE-94` · `LLM03:2026` · `ASI05`

<a id="app014"></a>
### APP014 · Argumento que o modelo escreve na ferramenta chega a shell, código, SQL, caminho ou URL

Um servidor MCP ou uma ferramenta de agente passa um dos seus argumentos para uma chamada perigosa. Quem preenche esses argumentos é o modelo de IA, não você nem o seu código, e qualquer coisa que ele leu antes da chamada (uma página, um arquivo, uma issue, um e-mail) pode esconder instruções que mudam o que ele escreve. Contam como argumento de ferramenta: os parâmetros das funções com `@mcp.tool()`/`@server.tool()` do FastMCP e de `mcp.add_tool(f)`, o `arguments` de um handler `@server.call_tool()` de baixo nível, os handlers de `server.tool(...)`, `server.registerTool(...)` e `setRequestHandler(CallToolRequestSchema, ...)` em TypeScript, `@tool` e `BaseTool._run` do LangChain, `tool({ execute })` do AI SDK, e `tool_call.function.arguments` ou `block.input` lidos da resposta da OpenAI ou da Anthropic. O valor passado a um helper do mesmo arquivo, a uma função que a ferramenta importa de outro arquivo do projeto (até dois níveis), ou por uma tabela `{"nome": funcao}`, é seguido.

A severidade segue o sink. Crítico quando o argumento entra no meio de um comando de shell ou de um código escrito no código (`os.system("git log " + ref)`, `` exec(`ls ${dir}`) ``, `["sh", "-c", f"..."]`). Alto quando a ferramenta roda o comando ou o código inteiro que recebe, para SQL montado com o argumento, para pickle ou YAML inseguro e para um caminho que junta o argumento a uma pasta do código (`os.path.join(BASE, nome)`, de onde `../` sai). Médio para qualquer outro caminho, para um endereço que o servidor busca e para HTML. Em skills o achado mantém a severidade cheia; em testes e exemplos cai para baixa, como os outros achados de código.

Não entram: parâmetros tipados como número, booleano, `Literal`, `Enum` do arquivo ou `Field(pattern=...)`, `z.number()`/`z.enum()` do Zod, parâmetros que o framework injeta (`ctx: Context`), lista de argumentos sem shell com o programa escrito no código, argumento que passa antes por uma checagem como `validate_name(arg)` ou `check_path(arg)` (em TypeScript, checagens de caminho como `validatePath(p)`), `shlex.quote`, parâmetros de consulta, `basename`, `resolve()` com checagem de `is_relative_to`/`startsWith`, nome de arquivo fixo dentro de uma pasta que o modelo escolhe, host fixo, lista de hosts permitidos e código que roda no navegador. Uma ferramenta que roda a consulta SQL inteira que recebe é uma ferramenta de SQL por escolha e não entra. Um JSON Schema só com `"type": "string"` não conta como validação.

O CWE e o item do OWASP Top 10 for Agentic Applications dependem do sink: CWE-78 e ASI05 para comandos de shell, CWE-94 e ASI05 para código e templates, CWE-502 e ASI05 para pickle e YAML, CWE-89 e ASI02 para SQL, CWE-22 e ASI02 para caminhos, CWE-918 e ASI02 para URLs, CWE-79 para HTML.

**Como corrigir:** trate todo argumento de ferramenta como entrada não confiável: rode programas com lista de argumentos e sem shell, passe valores de SQL como parâmetro, mantenha caminhos dentro de uma pasta (resolva e confira o prefixo), aceite só os hosts de que a ferramenta precisa e tipe os argumentos do jeito mais estreito possível (número, enum, padrão). Se a ferramenta precisa rodar comandos, peça confirmação a quem usa antes de cada um.
**Padrões:** `LLM03:2026`

## Código

Arquivos Python são lidos com `ast` e JavaScript/TypeScript (também o `<script>` de `.vue`, `.svelte` e `.astro`) com padrões justos, seguindo de onde veio cada valor dentro da função: a requisição (Flask, FastAPI, Django, Express, Next.js, Hono...), um argumento da função ou outro servidor. A chamada a um helper seu (`get_file_by_id(id)`) não é seguida, porque devolve outra coisa, nem um parâmetro que o framework já converteu em número, booleano ou UUID (`item_id: int`, `<int:id>`). Bundles minificados e bibliotecas de terceiros copiadas para o projeto (cabeçalho `/*! nome vX.Y` ou `@license`, `vendor/`, `third_party/`, `static/js/lib/`) ficam de fora num projeto, mas são lidos no `stingward skill`, onde são o código que roda; testes, exemplos e fixtures caem para baixa.

<a id="cod001"></a>
### COD001 · Consulta SQL montada com dado de fora

f-string, `+`, `%` ou `.format()` com SQL que vai para `execute`, `text()`, `read_sql`, `pool.query`, `knex.raw`, `$queryRawUnsafe`, o `.extra(where=..., select=..., tables=...)` do Django e parecidos. Alto com dado da requisição, médio com argumento de função no lugar de um valor (`= '{nome}'`, `LIKE`, `IN (...)`). Médio quando o dado da requisição, a resposta do modelo ou o argumento de uma ferramenta escolhe o nome de uma coluna ou tabela (`ORDER BY {ordem}`, `FROM {tabela}`, `LIMIT {limite}`); nome conferido numa lista fixa ou tirado de um dicionário do código não entra. Nome de tabela vindo de constante, parâmetros `?`/`%s`/`$1`, construtores de ORM e templates com tag (`` sql`...` ``, `` $queryRaw`...` ``) não entram.

**Como corrigir:** passe os valores como parâmetros: `cursor.execute("... WHERE id = %s", (id,))`, `$1` no Postgres, `?` no SQLite, `` sql`...` `` ou `` $queryRaw`...` `` no Prisma. Nome de coluna ou tabela não pode ser parâmetro: escolha numa lista fixa (`ORDENS[chave]`, `if ordem not in PERMITIDAS: abort(400)`).
**Padrões:** `CWE-89`

<a id="cod002"></a>
### COD002 · Comando de shell montado com dado de fora

`os.system`, `subprocess.run(..., shell=True)`, `["sh", "-c", ...]`, `exec`/`execSync` do `child_process`, `spawn(cmd, { shell: true })`, `spawn("sh", ["-c", cmd])`, execa com `shell: true` e parecidos com dado da requisição no comando (crítico), ou argumento de função misturado no texto do comando num app web (médio). Lista de argumentos sem shell (`subprocess.run(["ping", host])`, `execFile`, `spawn("ls", [dir])`) e ferramentas de linha de comando (click, typer) não entram.

**Como corrigir:** rode o programa com uma lista de argumentos e sem shell, e aceite só valores de uma lista conhecida.
**Padrões:** `CWE-78`

<a id="cod003"></a>
### COD003 · Código montado com dado de fora é executado

`eval`, `exec`, `new Function`, `vm.runIn*Context`, `setTimeout` com texto ou `render_template_string` montados com dado da requisição. Qualquer pessoa roda código no seu servidor. `ast.literal_eval`, `JSON.parse` e código constante não entram.

**Como corrigir:** não execute texto. Leia o dado que você espera (`json.loads`, `JSON.parse`, `ast.literal_eval`) ou mapeie valores permitidos para funções.
**Padrões:** `CWE-94` · `CWE-95`

<a id="cod004"></a>
### COD004 · Dados carregados com pickle ou YAML inseguro

`pickle`, `dill`, `joblib`, `marshal` e `yaml.load` com o carregador completo ou inseguro. Alto para dado da requisição, médio para resposta de outro servidor ou carregador inseguro escrito, baixo para `yaml.load` de arquivo local sem `Loader`. `yaml.safe_load`, `SafeLoader` e o `YAML()` do ruamel não entram, nem pickle de arquivo local.

**Como corrigir:** use `yaml.safe_load` ou JSON para dados de fora; só use pickle em arquivos que você mesmo gravou, num lugar em que mais ninguém escreve.
**Padrões:** `CWE-502`

<a id="cod005"></a>
### COD005 · HTML inserido sem limpar

`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `set:html`, `Markup()`, `res.send`/`res.write`/`res.end` do Express, `c.html` do Hono, ou HTML devolvido como texto por uma rota Flask ou por uma rota FastAPI com `response_class=HTMLResponse`, com dado da URL ou da requisição (médio). No JavaScript, HTML montado com outras variáveis é baixo. `DOMPurify.sanitize`, `escapeHtml`, `textContent`, JSX comum, HTML constante, `res.json` e texto sem tag HTML não entram.

**Como corrigir:** mostre como texto (`textContent`, ou a variável direto no JSX) ou limpe antes com `DOMPurify.sanitize` (sanitize-html ou bleach no servidor).
**Padrões:** `CWE-79`

<a id="cod006"></a>
### COD006 · Verificação do certificado TLS desligada

`verify=False` no requests/httpx, `session.verify = False`, `ssl._create_unverified_context`, `CERT_NONE`, `rejectUnauthorized: false` e `NODE_TLS_REJECT_UNAUTHORIZED=0` no código, em `.env`, Dockerfile ou YAML. Qualquer um no caminho da rede se passa pelo servidor.

**Como corrigir:** tire a opção. Para uma CA própria, aponte para o certificado dela (`verify="/caminho/ca.pem"` no Python, `ca:` no Node).
**Padrões:** `CWE-295`

<a id="cod007"></a>
### COD007 · Caminho de arquivo montado com dados da requisição

`open`, `send_file`, `FileResponse`, `Path(...).read_text`, `fs.readFile`, `res.sendFile` e parecidos com um valor da requisição no caminho. `secure_filename`, `basename`, `resolve()` com checagem de `is_relative_to`/`startsWith`, `sendFile(..., { root })`, o caminho que o servidor escolheu para um upload (`req.file.path`), um pedaço da rota que não aceita `/` (`/files/{id}`) e rotas só de administrador não entram.

**Como corrigir:** use só o nome do arquivo (`os.path.basename`, `secure_filename`, `path.basename`) ou resolva o caminho e confira que ele continua dentro da pasta esperada.
**Padrões:** `CWE-22`

<a id="cod008"></a>
### COD008 · Servidor busca uma URL que veio da requisição

`requests.get`, `httpx`, `urlopen`, `fetch`, `axios` e parecidos no servidor quando a requisição decide para onde a URL aponta (a URL inteira ou o começo dela). Host fixo com um valor da requisição no caminho, checagem do host (`urlparse(...).hostname`, lista de permitidos) e código que roda no navegador não entram. Alto, ou médio quando o host vem do próprio cabeçalho `Host` ou `X-Forwarded-Host` da requisição (`f"https://{request.headers['Host']}/api"`): o navegador de outra pessoa não escolhe esse valor e o proxy na frente costuma conferir, mas quem chama o servidor direto consegue trocar.

**Como corrigir:** aceite só os domínios de que você precisa, bloqueie endereços privados e locais e não siga redirecionamentos sem conferir.
**Padrões:** `CWE-918`

<a id="cod009"></a>
### COD009 · Redirecionamento para um endereço que veio da requisição

`redirect(request.args["next"])`, `res.redirect(req.query.returnTo)`, `NextResponse.redirect`, `location.href =` com um parâmetro da URL e parecidos. Caminho que começa com um `/...` fixo, `url_for` e checagem do host não entram. Começo feito só de barras (`"/" + next`, `` `/${next}` ``, `"//" + host`) entra: com `next = "/evil.com"`, o navegador vai para `//evil.com`, outro site. Também entra o host vindo da requisição logo depois de um esquema fixo (`"https://" + request.args["host"]`, `` `https://${req.body.host}/home` ``), mas não o do cabeçalho `Host` ou `X-Forwarded-Host`: esse é o host do próprio site, que o navegador de outra pessoa não escolhe.

**Como corrigir:** redirecione só para caminhos relativos que começam com uma única `/` ou para domínios de uma lista conhecida.
**Padrões:** `CWE-601`

<a id="cod010"></a>
### COD010 · Número aleatório previsível usado num segredo

`Math.random()` ou o `random` do Python atribuído a (ou devolvido por) algo com nome de segredo: `reset_token`, `apiKey`, `password`, `otp`, `verification_code`, também no nível do módulo e quando o valor é montado num callback (`[...Array(32)].map(() => ...Math.random()...)`). Um id de sessão (`session_id`, `sessionId`, `sid`) conta quando vai para um cookie. Nomes como `token_count` ou `delay`, id de sessão que nunca chega a um cookie e testes não entram.

**Como corrigir:** use `crypto.randomUUID()` ou `crypto.getRandomValues` no JavaScript e o módulo `secrets` no Python (`secrets.token_urlsafe`).
**Padrões:** `CWE-338`

<a id="cod011"></a>
### COD011 · Senha guardada com hash rápido

MD5, SHA-1 ou SHA-2 (`hashlib.sha256(password...)`, `createHash("sha256").update(password)`, CryptoJS) aplicado a uma variável com nome de senha. Se o banco vazar, as senhas caem na força bruta. Hash de arquivo ou do corpo da requisição não entra.

**Como corrigir:** use uma função feita para senhas: bcrypt, scrypt ou Argon2 (argon2-cffi e bcrypt no Python, bcrypt no Node), ou deixe o login com um provedor de autenticação.
**Padrões:** `CWE-916`

## Agentes e MCP

<a id="agt001"></a>
### AGT001 · Permissão de agente ampla demais

`bypassPermissions`, `--dangerously-skip-permissions`, `Bash(*)`, `Bash(curl:*)` e parecidos nas configurações do Claude Code, Cursor, Codex ou Gemini. O agente roda qualquer comando sem perguntar.

**Como corrigir:** libere só os comandos que precisa, como `Bash(npm test:*)`.
**Padrões:** `CWE-250` · `LLM03:2026` · `ASI03`

<a id="agt002"></a>
### AGT002 · Hook ou servidor MCP que baixa e executa código

Um comando de hook, ou o comando que inicia um servidor MCP (por exemplo `sh -c "curl ... | sh"`), que passa `curl` ou `wget` direto para o shell. Quem controla aquela URL roda código na sua máquina toda vez que o hook dispara ou o servidor inicia.

**Como corrigir:** guarde o script no repositório e revise.
**Padrões:** `CWE-494` · `ASI05`

<a id="agt003"></a>
### AGT003 · Servidor MCP sem versão fixa

`npx algum-mcp` ou `uvx algum-mcp` sem versão: cada início pode rodar código novo do registro.

**Como corrigir:** fixe a versão exata (`algum-mcp@1.2.3`).
**Padrões:** `CWE-494` · `LLM04:2026` · `ASI04` · `AST07`

<a id="agt004"></a>
### AGT004 · Credencial escrita na configuração do MCP

Token escrito direto no `.mcp.json`, `claude_desktop_config.json` ou `mcp.json`. Esses arquivos vão para o git e para prints de tela.

**Como corrigir:** use uma variável de ambiente (`"${GITHUB_TOKEN}"`) e troque a chave.
**Padrões:** `CWE-798` · `LLM02:2026`

<a id="agt005"></a>
### AGT005 · Servidor MCP remoto sem HTTPS

URL de servidor MCP com `http://` fora do localhost: tokens e chamadas de ferramenta trafegam abertos.

**Como corrigir:** use `https://`.
**Padrões:** `CWE-319`

<a id="agt006"></a>
### AGT006 · Todos os servidores MCP do projeto aprovados automaticamente

`enableAllProjectMcpServers: true` inicia qualquer servidor MCP que um repositório clonado declarar, sem perguntar.

**Como corrigir:** remova e aprove os servidores um a um.
**Padrões:** `CWE-1188` · `ASI04`

## Skills e prompts

<a id="skl001"></a>
### SKL001 · Caracteres Unicode invisíveis

Caracteres de tag Unicode (texto invisível que o modelo lê), controles bidirecionais do Trojan Source e caracteres de largura zero. O Stingward decodifica e mostra a mensagem escondida. Bandeiras em emoji e texto normal da direita para a esquerda não contam.

**Como corrigir:** remova num editor que mostra caracteres invisíveis. Se o arquivo veio de terceiros, não instale.
**Padrões:** `CWE-1427` · `LLM01:2026` · `AST01`

<a id="skl002"></a>
### SKL002 · Baixa um script e passa direto para o shell

`curl ... | sh`, `wget -O- ... | bash`, `iex (iwr ...)` e parecidos, e baixar um arquivo e rodar na mesma linha (`curl -o x ... && chmod +x x`), em skills, scripts e instruções.

**Como corrigir:** baixe, leia e fixe o script, ou instale por um gerenciador de pacotes com versão fixa.
**Padrões:** `CWE-494` · `AST02`

<a id="skl003"></a>
### SKL003 · Injeção de prompt ou envenenamento de ferramenta

"Ignore as instruções anteriores", "não conte ao usuário", tags de sistema falsas e instruções escondidas na descrição de ferramentas MCP.

**Como corrigir:** remova a instrução. Se veio de terceiros, trate a skill inteira como hostil.
**Padrões:** `CWE-1427` · `LLM01:2026` · `AST01`

<a id="skl004"></a>
### SKL004 · Lê credenciais da máquina

Lê `~/.ssh`, `~/.aws/credentials`, `.env`, perfis do navegador ou o chaveiro do sistema. Crítica quando o mesmo arquivo também chama a internet: é o padrão de roubo de chave.

**Como corrigir:** veja se a skill precisa mesmo disso. Sem motivo claro, não instale.
**Padrões:** `CWE-200` · `AST01`

<a id="skl005"></a>
### SKL005 · Executa instruções vindas de arquivos ou páginas

"Rode os comandos desta issue", "siga as instruções da página": quem escreve esse conteúdo controla o agente.

**Como corrigir:** trate conteúdo de fora como dado; peça confirmação antes de rodar qualquer coisa que veio dele.
**Padrões:** `CWE-1427` · `LLM01:2026` · `AST05`

<a id="skl006"></a>
### SKL006 · Skill pede shell sem restrição

`allowed-tools: Bash` (ou `Bash(*)`) no `SKILL.md`: enquanto a skill está ativa, ela roda qualquer comando sem perguntar.

**Como corrigir:** liste comandos específicos, como `Bash(git status:*)`.
**Padrões:** `CWE-250` · `LLM03:2026` · `AST03`

<a id="skl007"></a>
### SKL007 · Código ofuscado

`eval(atob(...))`, `new Function(atob(...))`, `exec(base64.b64decode(...))`, `base64 -d | sh` e blocos grandes em base64 ou hexadecimal (imagens e fontes são reconhecidas e puladas). Skill legítima não tem motivo para esconder código.

**Como corrigir:** decodifique e leia o que ele faz. Se não der, não instale.
**Padrões:** `CWE-506` · `AST01`

<a id="skl008"></a>
### SKL008 · Envia dados para serviço de captura anônimo

webhook.site, RequestBin, Pipedream, ngrok, interact.sh, Burp Collaborator, bots do Telegram, transfer.sh e parecidos, que recebem dados sem identificação: canal comum de vazamento.

**Como corrigir:** descubra o que é enviado e por quê. Sem motivo claro, não instale.
**Padrões:** `CWE-200` · `AST01`

<a id="skl009"></a>
### SKL009 · Script de instalação executa comandos

Scripts `preinstall`, `install`, `postinstall` ou `prepare` no `package.json`: rodam no `npm install`, antes de você usar qualquer coisa. Alto quando o script baixa e roda código da internet.

**Como corrigir:** leia o script. Na dúvida, instale com `--ignore-scripts`.
**Padrões:** `CWE-829` · `AST02`

<a id="skl010"></a>
### SKL010 · Skill manda o agente não parar para falar com você

"Não pare para confirmar", "nunca peça confirmação": um comando estranho vindo de um plano, issue ou arquivo roda antes de você ver.

**Como corrigir:** rode a skill com permissões restritas e revise o plano antes de executar.
**Padrões:** `LLM03:2026` · `AST05`

<a id="skl011"></a>
### SKL011 · Reverse shell

`bash -i >& /dev/tcp/host/porta`, `nc -e /bin/sh`, `socat ... exec:/bin/bash`, `os.dup2(s.fileno(), ...)` com `pty.spawn`, `Net.Sockets.TCPClient` no PowerShell: a skill entrega o seu terminal para quem estiver escutando do outro lado. Teste de porta como `</dev/tcp/localhost/5432` não é marcado.

**Como corrigir:** não instale. Se já rodou, tire a máquina da rede, troque senhas e chaves e confira processos e tarefas agendadas.
**Padrões:** `CWE-506` · `AST01`

## Ignorar um achado

Coloque uma linha no `.stingwardignore` na raiz do projeto (`REGRA caminho/glob`, só `REGRA`, ou só `caminho/glob`), ou escreva `stingward:ignore` num comentário na linha. O ignore na linha só vale no seu próprio projeto, não em skills de terceiros auditadas com `stingward skill`.
