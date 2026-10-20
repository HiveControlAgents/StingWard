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
| [AGT001](#agt001) | Permissão de agente ampla demais | 🟠 |
| [AGT002](#agt002) | Hook que baixa e executa código | 🟠 |
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
| [SKL009](#skl009) | Script de instalação executa comandos | 🟡 |
| [SKL010](#skl010) | Skill manda o agente não parar para falar com você | 🟡 |

## Dependências

<a id="dep001"></a>
### DEP001 · Versão de dependência com falhas conhecidas

Consulta no OSV.dev cada pacote e versão dos seus lockfiles (npm, Yarn, pnpm, Bun, `requirements.txt` do pip, Poetry, uv, Pipenv, PDM, módulos Go, Cargo, Bundler, Composer). A severidade vem do alerta (CVSS ou severidade do GitHub); uma CVE no catálogo **KEV da CISA** (explorada agora) sobe para crítica, e um **EPSS** de 50% ou mais (exploração provável nos próximos 30 dias) sobe um nível. Sai um achado por pacote, com a atualização única que resolve todas as falhas conhecidas.

**Como corrigir:** atualize para a versão indicada. Se alguma falha ainda não tem correção, o achado avisa: pense em trocar de pacote.
**Padrões:** `CWE-1395`

<a id="dep002"></a>
### DEP002 · Pacote malicioso

Registros `MAL-*` do OSV e alertas de "malware" do GitHub: pacotes publicados para roubar dados ou executar código. É ataque, não bug.

**Como corrigir:** remova o pacote, apague `node_modules`/virtualenvs e troque todas as chaves e senhas da máquina e do projeto.
**Padrões:** `CWE-506` · `LLM04:2026` · `AST02`

<a id="dep003"></a>
### DEP003 · Manifesto sem lockfile

`package.json`, `pyproject.toml` ou `requirements.txt` com faixas de versão e sem lockfile: não dá para auditar as versões que vão para produção, e elas mudam a cada instalação.

**Como corrigir:** gere e envie o lockfile (`npm install`, `uv lock`, `poetry lock`, `pip freeze`...).
**Padrões:** `CWE-1395`

## Segredos

<a id="sec001"></a>
### SEC001 · Segredo no código

Chaves de API (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack, Discord...), chaves privadas, senha em URL, webhooks e atribuições sensíveis. O valor nunca aparece em nenhum formato de relatório, só o tipo e o lugar. Em testes, documentação e exemplos a severidade cai.

**Como corrigir:** mova o valor para variável de ambiente ou cofre de segredos e troque a chave: ela já está no histórico.
**Padrões:** `CWE-798` · `LLM02:2026`

<a id="sec002"></a>
### SEC002 · `.env` no git

O `.env` está versionado, então todo clone e fork leva as chaves junto.

**Como corrigir:** `git rm --cached .env`, coloque no `.gitignore` e troque as chaves.
**Padrões:** `CWE-538`

<a id="sec003"></a>
### SEC003 · `.env` fora do `.gitignore`

Ainda não foi para o git, mas o próximo `git add .` leva junto.

**Como corrigir:** adicione `.env` (e `.env.*`) ao `.gitignore`.
**Padrões:** `CWE-538`

<a id="sec004"></a>
### SEC004 · Chave `service_role` do Supabase no código

A chave `service_role` passa por cima do Row Level Security: quem tem a chave lê e altera qualquer tabela.

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

## Agentes e MCP

<a id="agt001"></a>
### AGT001 · Permissão de agente ampla demais

`bypassPermissions`, `--dangerously-skip-permissions`, `Bash(*)`, `Bash(curl:*)` e parecidos nas configurações do Claude Code, Cursor, Codex ou Gemini. O agente roda qualquer comando sem perguntar.

**Como corrigir:** libere só os comandos que precisa, como `Bash(npm test:*)`.
**Padrões:** `CWE-250` · `LLM03:2026` · `ASI03`

<a id="agt002"></a>
### AGT002 · Hook que baixa e executa código

Hook que passa `curl` ou `wget` direto para o shell. Quem controla aquela URL roda código na sua máquina toda vez que o hook dispara.

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

`curl ... | sh`, `wget -O- ... | bash`, `iex (iwr ...)` e parecidos, em skills, scripts e instruções.

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

Scripts `preinstall`, `install`, `postinstall` ou `prepare` no `package.json`: rodam no `npm install`, antes de você usar qualquer coisa.

**Como corrigir:** leia o script. Na dúvida, instale com `--ignore-scripts`.
**Padrões:** `CWE-829` · `AST02`

<a id="skl010"></a>
### SKL010 · Skill manda o agente não parar para falar com você

"Não pare para confirmar", "nunca peça confirmação": um comando estranho vindo de um plano, issue ou arquivo roda antes de você ver.

**Como corrigir:** rode a skill com permissões restritas e revise o plano antes de executar.
**Padrões:** `LLM03:2026` · `AST05`

## Ignorar um achado

Coloque uma linha no `.stingwardignore` na raiz do projeto (`REGRA caminho/glob`, só `REGRA`, ou só `caminho/glob`), ou escreva `stingward:ignore` num comentário na linha. O ignore na linha só vale no seu próprio projeto, não em skills de terceiros auditadas com `stingward skill`.
