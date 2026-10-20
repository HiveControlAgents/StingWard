"""Catálogo de regras com os textos em português e inglês.

Cada texto pode usar campos de Finding.params com {nome}. Os textos falam com quem
está construindo o projeto, não com especialista em segurança: o que é, por que importa
e o que fazer.
"""
from __future__ import annotations

RULES = {
    # ------------------------------------------------------------------ dependências
    "DEP001": {
        "group": "deps",
        "pt": ("{pkg} {version}: {headline}",
               "{why}{exploit}",
               "{fix}"),
        "en": ("{pkg} {version}: {headline}",
               "{why}{exploit}",
               "{fix}"),
    },
    "DEP002": {
        "group": "deps",
        "pt": ("{pkg} {version} é um pacote malicioso ({vuln_id})",
               "O pacote foi publicado para roubar dados ou executar código. Não é um bug: é ataque.",
               "{fix}"),
        "en": ("{pkg} {version} is a malicious package ({vuln_id})",
               "This package was published to steal data or run code. It is not a bug, it is an attack.",
               "{fix}"),
    },
    "DEP003": {
        "group": "deps",
        "pt": ("{manifest} sem lockfile: {count} dependência(s) com versão aberta",
               "Sem lockfile não dá para saber qual versão está instalada, nem para auditar. Cada instalação pode puxar uma versão diferente.",
               "Gere e faça commit do lockfile (npm install, poetry lock, uv lock) ou fixe as versões com ==."),
        "en": ("{manifest} has no lockfile: {count} dependency(ies) with open versions",
               "Without a lockfile nobody knows which version gets installed, so it cannot be audited.",
               "Generate and commit a lockfile (npm install, poetry lock, uv lock) or pin versions with ==."),
    },
    "DEP004": {
        "group": "deps",
        "pt": ("{pkg} {spec}: {headline}",
               "{why}{exploit}",
               "{fix}"),
        "en": ("{pkg} {spec}: {headline}",
               "{why}{exploit}",
               "{fix}"),
    },
    # ------------------------------------------------------------------ segredos
    "SEC001": {
        "group": "secrets",
        "pt": ("Segredo no código: {kind}",
               "Quem tiver acesso ao repositório (ou ao histórico do git) pode usar essa credencial.",
               "Troque (revogue) a chave no painel do serviço, mova para variável de ambiente e apague do histórico se o repositório for público."),
        "en": ("Secret in code: {kind}",
               "Anyone with access to the repository, or its git history, can use this credential.",
               "Revoke the key in the provider's dashboard, move it to an environment variable, and purge it from history if the repo is public."),
    },
    "SEC002": {
        "group": "secrets",
        "pt": ("Arquivo {name} está no git",
               "Arquivos .env guardam as chaves do projeto. No git, elas vão junto para todo clone e fork.",
               "Rode git rm --cached {name}, adicione {name} ao .gitignore e troque as chaves que estavam nele."),
        "en": ("{name} is committed to git",
               ".env files hold the project's keys. Once in git they travel with every clone and fork.",
               "Run git rm --cached {name}, add {name} to .gitignore, and rotate the keys it contained."),
    },
    "SEC003": {
        "group": "secrets",
        "pt": ("Arquivo {name} fora do .gitignore",
               "O arquivo ainda não foi commitado, mas o próximo git add . leva as chaves junto.",
               "Adicione {name} ao .gitignore."),
        "en": ("{name} is not in .gitignore",
               "It has not been committed yet, but the next git add . will take the keys along.",
               "Add {name} to .gitignore."),
    },
    "SEC004": {
        "group": "secrets",
        "pt": ("Chave service_role do Supabase no código{note}",
               "Essa chave ignora todas as regras de acesso (RLS). Com ela, qualquer pessoa lê e apaga o banco inteiro.{local}",
               "Gere uma chave nova no painel do Supabase (Settings > API), use a service_role só no servidor e a anon no front-end."),
        "en": ("Supabase service_role key in code{note}",
               "This key bypasses every access rule (RLS). With it anyone can read and delete the whole database.{local}",
               "Rotate it in the Supabase dashboard (Settings > API), keep service_role server-side only and use the anon key in the frontend."),
    },
    # ------------------------------------------------------------------ apps feitos com IA
    "APP001": {
        "group": "app",
        "pt": ("Segredo exposto no navegador: {var}",
               "Variáveis com prefixo {prefix} vão para o JavaScript que o navegador baixa. Qualquer visitante vê o valor.",
               "Tire o prefixo {prefix}, use a variável só no servidor (API route, server action, edge function) e troque a chave."),
        "en": ("Secret exposed to the browser: {var}",
               "Variables prefixed with {prefix} are bundled into the JavaScript every visitor downloads.",
               "Drop the {prefix} prefix, use it server-side only (API route, server action, edge function) and rotate the key."),
    },
    "APP002": {
        "group": "app",
        "pt": ("SDK de IA rodando no navegador (dangerouslyAllowBrowser)",
               "A chave da OpenAI/Anthropic vai junto para o navegador. Alguém copia e usa sua conta até estourar a fatura.",
               "Chame a API de IA por uma rota no servidor e deixe a chave só lá."),
        "en": ("AI SDK running in the browser (dangerouslyAllowBrowser)",
               "Your OpenAI/Anthropic key ships to the browser. Someone copies it and runs up your bill.",
               "Call the AI API from a server route and keep the key there."),
    },
    "APP003": {
        "group": "app",
        "pt": ("CORS aberto para qualquer site{cred}",
               "Qualquer página da internet pode chamar sua API pelo navegador de quem visitar.{cred_why}",
               "Liste só os domínios do seu front-end em origin/allow_origins."),
        "en": ("CORS open to any website{cred}",
               "Any page on the internet can call your API from a visitor's browser.{cred_why}",
               "Allow only your frontend domains in origin/allow_origins."),
    },
    "APP004": {
        "group": "app",
        "pt": ("Tabela {table} sem RLS no Supabase",
               "Sem Row Level Security, qualquer pessoa com a chave anon (que é pública) lê e altera essa tabela.",
               "Adicione: alter table {table} enable row level security; e crie políticas para cada operação."),
        "en": ("Table {table} has no RLS in Supabase",
               "Without Row Level Security anyone with the anon key (which is public) can read and change this table.",
               "Add: alter table {table} enable row level security; and create policies for each operation."),
    },
    "APP005": {
        "group": "app",
        "pt": ("Política do Supabase liberada para todos: {policy}",
               "A política usa true como condição, então vale para qualquer pessoa, logada ou não.",
               "Troque true por uma condição como auth.uid() = user_id."),
        "en": ("Supabase policy open to everyone: {policy}",
               "The policy uses true as its condition, so it applies to anyone, signed in or not.",
               "Replace true with a condition such as auth.uid() = user_id."),
    },
    "APP006": {
        "group": "app",
        "pt": ("Regras do Firebase abertas",
               "Com essa regra qualquer pessoa lê e grava no banco ou no storage. O modo de teste do Firebase também expira e quebra o app.",
               "Escreva regras que exijam request.auth e confiram o dono do documento."),
        "en": ("Firebase rules are open",
               "With this rule anyone can read and write your database or storage.",
               "Write rules that require request.auth and check document ownership."),
    },
    "APP007": {
        "group": "app",
        "pt": ("Modo debug ligado ({framework})",
               "Em produção, a página de erro do debug mostra código, variáveis e às vezes um console que executa comandos.",
               "Leia o valor de uma variável de ambiente e deixe desligado em produção."),
        "en": ("Debug mode enabled ({framework})",
               "In production the debug error page leaks code, variables and sometimes an interactive console.",
               "Read it from an environment variable and keep it off in production."),
    },
    "APP008": {
        "group": "app",
        "pt": ("Token JWT aceito sem verificar assinatura",
               "Qualquer pessoa pode montar um token dizendo que é admin e o servidor aceita.",
               "Verifique a assinatura e fixe o algoritmo (ex.: algorithms=[\"HS256\"])."),
        "en": ("JWT accepted without signature verification",
               "Anyone can forge a token claiming to be admin and the server will accept it.",
               "Verify the signature and pin the algorithm (e.g. algorithms=[\"HS256\"])."),
    },
    "APP009": {
        "group": "app",
        "pt": ("Texto escrito pelo modelo chega {sink}",
               "A resposta do modelo pode ser guiada por qualquer coisa que ele leu (uma página, um arquivo, a mensagem de alguém). "
               "Usar isso direto transforma uma injeção de prompt em {impact}.",
               "Trate a saída do modelo como entrada de usuário: {fix}"),
        "en": ("Text written by the model reaches {sink}",
               "The model's answer can be steered by anything it read (a web page, a file, someone's message). Using it as is turns "
               "a prompt injection into {impact}.",
               "Treat model output like user input: {fix}"),
    },
    "APP010": {
        "group": "app",
        "pt": ("Dado da requisição entra no prompt de sistema",
               "O prompt de sistema é onde ficam as suas regras. Quem manda esse valor pode reescrevê-las: tirar os limites, vazar o "
               "prompt ou mudar o que o modelo faz.",
               "Deixe o prompt de sistema fixo. Mande o texto do usuário como mensagem de usuário e, se uma opção precisa mudar o "
               "prompt, escolha o trecho numa lista fixa."),
        "en": ("Request input goes into the system prompt",
               "The system prompt is where your rules live. Whoever sends that value can rewrite them: drop your limits, leak the "
               "prompt or change what the model does.",
               "Keep the system prompt fixed. Send the user's text as a user message, and if a setting must change the prompt, pick "
               "the wording from a fixed list."),
    },
    "APP011": {
        "group": "app",
        "pt": ("Rota de IA sem login e sem limite de uso",
               "Quem achar essa URL chama o modelo na sua conta em loop: a fatura dispara e o seu app vira proxy de IA de graça para "
               "outras pessoas.",
               "Exija usuário logado, limite pedidos por usuário ou IP (@upstash/ratelimit, express-rate-limit, slowapi), defina "
               "max_tokens / maxOutputTokens e ponha um limite de gasto no painel do provedor."),
        "en": ("AI endpoint with no login and no rate limit",
               "Anyone who finds this URL can call the model on your account in a loop: the bill spikes and your app becomes a free "
               "AI proxy for others.",
               "Require a signed-in user, rate limit per user or IP (@upstash/ratelimit, express-rate-limit, slowapi), set "
               "max_tokens / maxOutputTokens, and add a spending limit in the provider's dashboard."),
    },
    "APP012": {
        "group": "app",
        "pt": ("Carregar o modelo pode executar código ({what})", "{why}", "{fix}"),
        "en": ("Loading the model can run code ({what})", "{why}", "{fix}"),
    },
    "APP013": {
        "group": "app",
        "pt": ("Agente pode executar o que o modelo escrever ({what})", "{why}", "{fix}"),
        "en": ("Agent can run whatever the model writes ({what})", "{why}", "{fix}"),
    },
    "APP014": {
        "group": "app",
        "pt": ("Argumento que o modelo escreve na ferramenta chega {sink}",
               "Quem preenche os argumentos desta ferramenta é o modelo de IA, não você nem o seu código. Qualquer coisa que ele "
               "leu antes de chamá-la (uma página, um arquivo, uma issue, um e-mail) pode esconder instruções que mudam o que ele "
               "escreve aqui. {detail}",
               "{fix}"),
        "en": ("Tool argument written by the model reaches {sink}",
               "The AI model fills in this tool's arguments, not you or your code. Anything it read before calling the tool (a web "
               "page, a file, an issue, an email) can hide instructions that change what it writes here. {detail}",
               "{fix}"),
    },
    # ------------------------------------------------------------------ falhas no código
    "COD001": {
        "group": "code",
        "pt": ("Consulta SQL montada com {source}",
               "O valor entra no meio do texto do SQL. Quem manda algo como ' OR '1'='1 consegue ler, mudar ou apagar dados do banco.",
               "Passe os valores como parâmetros e deixe o driver juntar: cursor.execute(\"... WHERE id = %s\", (id,)), $1 no "
               "Postgres, ? no SQLite, sql`...` ou $queryRaw`...` no Prisma. Nome de coluna ou de tabela não pode ser "
               "parâmetro: escolha o nome numa lista fixa (SORTS[chave], if order not in ALLOWED: abort(400))."),
        "en": ("SQL query built from {source}",
               "The value goes straight into the SQL text. Someone who sends ' OR '1'='1 can read, change or delete data.",
               "Pass values as parameters and let the driver combine them: cursor.execute(\"... WHERE id = %s\", (id,)), $1 in "
               "Postgres, ? in SQLite, sql`...` or $queryRaw`...` in Prisma. A column or table name cannot be a parameter: "
               "pick it from a fixed list (SORTS[key], if order not in ALLOWED: abort(400))."),
    },
    "COD002": {
        "group": "code",
        "pt": ("Comando de shell montado com {source}",
               "Quem controla esse valor pode colocar ; ou && e rodar qualquer comando no seu servidor.",
               "Rode o programa com uma lista de argumentos e sem shell (subprocess.run([\"cmd\", valor]), execFile no Node) e "
               "aceite só valores de uma lista conhecida."),
        "en": ("Shell command built from {source}",
               "Whoever controls that value can add ; or && and run any command on your server.",
               "Run the program with an argument list and no shell (subprocess.run([\"cmd\", value]), execFile in Node) and accept "
               "only values from a known list."),
    },
    "COD003": {
        "group": "code",
        "pt": ("Código montado com {source} é executado ({sink})",
               "eval, exec, new Function e templates montados na hora rodam o texto que recebem. Com {source}, qualquer pessoa roda "
               "código no seu servidor.",
               "Não execute texto. Leia o dado que você espera (json.loads, JSON.parse, ast.literal_eval) ou mapeie valores "
               "permitidos para funções."),
        "en": ("Code built from {source} is executed ({sink})",
               "eval, exec, new Function and templates built on the fly run whatever text they get. With {source}, anyone can run "
               "code on your server.",
               "Do not run text as code. Parse the data you expect (json.loads, JSON.parse, ast.literal_eval) or map allowed values "
               "to functions."),
    },
    "COD004": {
        "group": "code",
        "pt": ("Dados carregados com {what}, que pode executar código",
               "pickle e YAML com o carregador completo recriam qualquer objeto, o que basta para rodar comandos quando o conteúdo "
               "vem de outra pessoa.",
               "Use yaml.safe_load ou JSON para dados de fora; só use pickle em arquivos que você mesmo gravou, num lugar em que mais "
               "ninguém escreve."),
        "en": ("Data loaded with {what}, which can run code",
               "pickle and YAML with the full loader rebuild any object, which is enough to run commands when someone else wrote "
               "the content.",
               "Use yaml.safe_load or JSON for outside data; only unpickle files you wrote yourself, in a place nobody else can write to."),
    },
    "COD005": {
        "group": "code",
        "pt": ("HTML inserido sem limpar ({sink})",
               "Se o texto tiver algo que uma pessoa escreveu, um <script> ou onerror= roda no navegador de quem visita e pode tomar "
               "a sessão dela.",
               "Mostre como texto (textContent, ou a variável direto no JSX) ou limpe antes com DOMPurify.sanitize (sanitize-html ou "
               "bleach no servidor)."),
        "en": ("HTML inserted without sanitizing ({sink})",
               "If the text contains something a person wrote, a <script> or onerror= runs in your visitors' browsers and can take "
               "over their session.",
               "Show it as text (textContent, or the variable straight in JSX) or clean it first with DOMPurify.sanitize "
               "(sanitize-html or bleach on the server)."),
    },
    "COD006": {
        "group": "code",
        "pt": ("Verificação do certificado TLS desligada ({what})",
               "Sem conferir o certificado, qualquer um no caminho da rede (Wi-Fi público, proxy, provedor) se passa pelo servidor e "
               "lê ou altera o tráfego, tokens incluídos.",
               "Tire a opção. Para uma CA própria, aponte para o certificado dela (verify=\"/caminho/ca.pem\" no Python, ca: no "
               "Node) em vez de desligar a verificação."),
        "en": ("TLS certificate check turned off ({what})",
               "Without checking the certificate, anyone on the network path (public Wi-Fi, a proxy, the ISP) can pose as the server "
               "and read or change the traffic, tokens included.",
               "Remove the switch. For a private CA, point to its certificate (verify=\"/path/ca.pem\" in Python, ca: in Node) "
               "instead of turning the check off."),
    },
    "COD007": {
        "group": "code",
        "pt": ("Caminho de arquivo montado com dados da requisição ({sink})",
               "Um valor como ../../.env deixa alguém ler ou sobrescrever qualquer arquivo que o servidor alcança.",
               "Use só o nome do arquivo (os.path.basename, secure_filename, path.basename) ou resolva o caminho e confira que ele "
               "continua dentro da pasta esperada."),
        "en": ("File path built from request input ({sink})",
               "A value like ../../.env lets someone read or overwrite any file the server can reach.",
               "Keep only the file name (os.path.basename, secure_filename, path.basename), or resolve the path and check that it "
               "stays inside the folder you expect."),
    },
    "COD008": {
        "group": "code",
        "pt": ("Servidor busca uma URL que veio da requisição ({sink})",
               "Alguém pode fazer o seu servidor chamar endereços internos, como o serviço de metadados da nuvem (169.254.169.254), "
               "e devolver a resposta com as credenciais.",
               "Aceite só os domínios de que você precisa, bloqueie endereços privados e locais e não siga redirecionamentos sem conferir."),
        "en": ("Server fetches a URL taken from the request ({sink})",
               "Someone can make your server call internal addresses, such as the cloud metadata service (169.254.169.254), and get "
               "back the answer with credentials.",
               "Allow only the domains you need, block private and local addresses, and do not follow redirects without checking them."),
    },
    "COD009": {
        "group": "code",
        "pt": ("Redirecionamento para um endereço que veio da requisição ({sink})",
               "Um link do seu site pode levar as pessoas para uma página falsa igual à sua, e um endereço javascript: pode rodar código.",
               "Redirecione só para caminhos relativos que começam com uma única / ou para domínios de uma lista conhecida."),
        "en": ("Redirect to an address taken from the request ({sink})",
               "A link to your site can send people to a fake page that looks like yours, and a javascript: address can run code.",
               "Redirect only to relative paths that start with a single / or to domains from a known list."),
    },
    "COD010": {
        "group": "code",
        "pt": ("Número aleatório previsível usado em {name}",
               "Math.random e o módulo random do Python não foram feitos para segredos: dá para adivinhar os próximos valores.",
               "Use crypto.randomUUID() ou crypto.getRandomValues no JavaScript e o módulo secrets no Python (secrets.token_urlsafe)."),
        "en": ("Predictable random number used for {name}",
               "Math.random and Python's random module are not made for secrets: their next values can be guessed.",
               "Use crypto.randomUUID() or crypto.getRandomValues in JavaScript, and the secrets module in Python (secrets.token_urlsafe)."),
    },
    "COD011": {
        "group": "code",
        "pt": ("Senha guardada com hash {algo}",
               "{algo} é rápido de propósito: se o banco vazar, dá para testar bilhões de senhas por segundo até achar as originais.",
               "Use uma função feita para senhas: bcrypt, scrypt ou Argon2 (argon2-cffi e bcrypt no Python, bcrypt no Node), ou "
               "deixe o login com um provedor de autenticação."),
        "en": ("Password hashed with {algo}",
               "{algo} is fast on purpose: if the database leaks, attackers can test billions of guesses per second until they find "
               "the passwords.",
               "Use a function made for passwords: bcrypt, scrypt or Argon2 (argon2-cffi and bcrypt in Python, bcrypt in Node), or "
               "leave login to an auth provider."),
    },
    # ------------------------------------------------------------------ agentes, skills, MCP
    "AGT001": {
        "group": "agents",
        "pt": ("Permissão ampla demais para o agente: {what}",
               "O agente pode rodar qualquer comando sem perguntar. Uma instrução escondida num arquivo, issue ou página web vira comando na sua máquina.",
               "Libere só comandos específicos (ex.: Bash(npm test:*)) e deixe o resto pedindo confirmação."),
        "en": ("Agent permission too broad: {what}",
               "The agent can run any command without asking. A hidden instruction in a file, issue or web page becomes a command on your machine.",
               "Allow only specific commands (e.g. Bash(npm test:*)) and keep confirmation for the rest."),
    },
    "AGT002": {
        "group": "agents",
        "pt": ("Hook ou servidor MCP baixa e executa código da internet",
               "Um comando de hook ou o comando que inicia um servidor MCP passa curl/wget para o shell. Toda vez que o "
               "hook dispara, ou o servidor inicia, roda o que estiver naquele endereço hoje, sem revisão.",
               "Baixe o script uma vez, revise, guarde no repositório e chame o arquivo local."),
        "en": ("Hook or MCP server downloads and runs code from the internet",
               "A hook command, or the command that launches an MCP server, pipes curl/wget into a shell. Every time the "
               "hook fires, or the server starts, it runs whatever is at that URL today, unreviewed.",
               "Download the script once, review it, commit it, and call the local file."),
    },
    "AGT003": {
        "group": "agents",
        "pt": ("Servidor MCP sem versão fixa: {server} ({spec})",
               "Cada vez que o agente inicia, baixa a versão mais nova. Se o pacote for sequestrado, o código novo roda com seu acesso.",
               "Fixe a versão (ex.: {fixed_hint}) e atualize de propósito."),
        "en": ("MCP server without a pinned version: {server} ({spec})",
               "Every time the agent starts it downloads the newest release. If the package is hijacked, the new code runs with your access.",
               "Pin a version (e.g. {fixed_hint}) and upgrade on purpose."),
    },
    "AGT004": {
        "group": "agents",
        "pt": ("Credencial escrita na configuração do MCP: {server}",
               "Arquivos de configuração do MCP costumam ir para o git e para prints de tela.",
               "Use referência a variável de ambiente (ex.: \"${{GITHUB_TOKEN}}\") e troque a chave."),
        "en": ("Credential hard-coded in MCP config: {server}",
               "MCP config files tend to end up in git and in screenshots.",
               "Reference an environment variable instead (e.g. \"${{GITHUB_TOKEN}}\") and rotate the key."),
    },
    "AGT005": {
        "group": "agents",
        "pt": ("Servidor MCP remoto sem HTTPS: {server}",
               "O tráfego entre o agente e o servidor, incluindo tokens, vai sem criptografia.",
               "Use a URL https:// do servidor."),
        "en": ("Remote MCP server without HTTPS: {server}",
               "Traffic between the agent and the server, tokens included, is unencrypted.",
               "Use the server's https:// URL."),
    },
    "AGT006": {
        "group": "agents",
        "pt": ("Configuração aprova sozinha qualquer servidor MCP do projeto",
               "Com enableAllProjectMcpServers, abrir um repositório clonado já liga os servidores MCP que ele declarar.",
               "Desligue a opção e aprove servidores um por um."),
        "en": ("Config auto-approves every project MCP server",
               "With enableAllProjectMcpServers, opening a cloned repo starts whatever MCP servers it declares.",
               "Turn it off and approve servers one by one."),
    },
    # ------------------------------------------------------------------ conteúdo de skills e prompts
    "SKL001": {
        "group": "skills",
        "pt": ("Caracteres invisíveis no texto ({kind})",
               "{why}",
               "Abra o arquivo num editor que mostre caracteres invisíveis e remova. Se veio de terceiros, não instale."),
        "en": ("Invisible characters in text ({kind})",
               "{why}",
               "Open the file in an editor that shows invisible characters and remove them. If it came from a third party, do not install it."),
    },
    "SKL002": {
        "group": "skills",
        "pt": ("Baixa e executa script da internet ({snippet})",
               "O agente vai rodar o que estiver nesse endereço, que pode mudar depois da sua revisão.",
               "Troque por um script local revisado ou por um pacote com versão fixa."),
        "en": ("Downloads and runs a script from the internet ({snippet})",
               "The agent will run whatever is at that URL, which can change after you review it.",
               "Replace it with a reviewed local script or a version-pinned package."),
    },
    "SKL003": {
        "group": "skills",
        "pt": ("Instrução que tenta passar por cima do usuário: \"{snippet}\"",
               "Frases assim são a marca de prompt injection: mandam o agente ignorar regras ou esconder o que faz.",
               "Não instale. Se o arquivo é seu, remova a frase."),
        "en": ("Instruction that tries to override the user: \"{snippet}\"",
               "Phrases like this are the signature of prompt injection: they tell the agent to ignore rules or hide what it does.",
               "Do not install. If the file is yours, remove the phrase."),
    },
    "SKL004": {
        "group": "skills",
        "pt": ("Lê credenciais da máquina{send} ({what})",
               "{why}",
               "Confira se a skill realmente precisa disso. Uma skill que lê ~/.ssh ou .env e chama a internet pode estar roubando chaves."),
        "en": ("Reads machine credentials{send} ({what})",
               "{why}",
               "Check whether the skill really needs this. A skill that reads ~/.ssh or .env and calls the internet may be stealing keys."),
    },
    "SKL005": {
        "group": "skills",
        "pt": ("Executa instruções vindas de arquivos ou páginas: \"{snippet}\"",
               "Quem conseguir escrever nesse arquivo ou página (um PR, uma issue, um site) passa a dar ordens ao agente.",
               "Trate o conteúdo lido como dado, não como ordem: peça confirmação antes de executar comandos que vierem dele."),
        "en": ("Executes instructions coming from files or pages: \"{snippet}\"",
               "Whoever can write to that file or page (a PR, an issue, a website) can command the agent.",
               "Treat fetched content as data, not orders: ask for confirmation before running commands taken from it."),
    },
    "SKL006": {
        "group": "skills",
        "pt": ("Skill pede shell sem restrição (allowed-tools: {tools})",
               "A skill pode rodar qualquer comando sem perguntar enquanto estiver ativa.",
               "Restrinja a comandos específicos, como Bash(git status:*)."),
        "en": ("Skill requests unrestricted shell (allowed-tools: {tools})",
               "While active, the skill can run any command without asking.",
               "Restrict it to specific commands, such as Bash(git status:*)."),
    },
    "SKL007": {
        "group": "skills",
        "pt": ("Código ofuscado ({what})",
               "Esconder o que o código faz é comum em malware. Skill legítima não precisa disso.",
               "Decodifique e leia antes de instalar. Se não der para entender, não instale."),
        "en": ("Obfuscated code ({what})",
               "Hiding what code does is common in malware. A legitimate skill does not need it.",
               "Decode and read it before installing. If you cannot tell what it does, do not install it."),
    },
    "SKL008": {
        "group": "skills",
        "pt": ("Envia dados para serviço de captura ({host})",
               "{host} é usado para receber dados de forma anônima, comum em exfiltração.",
               "Descubra o que está sendo enviado. Se não houver motivo claro, não instale."),
        "en": ("Sends data to a capture service ({host})",
               "{host} is used to receive data anonymously, a common exfiltration channel.",
               "Find out what is sent. Without a clear reason, do not install."),
    },
    "SKL009": {
        "group": "skills",
        "pt": ("Script de instalação roda comandos ({script})",
               "Scripts {script} rodam sozinhos no npm install, antes de você usar o pacote.",
               "Leia o script. Se possível instale com --ignore-scripts."),
        "en": ("Install script runs commands ({script})",
               "{script} scripts run automatically on npm install, before you use the package.",
               "Read the script. If possible install with --ignore-scripts."),
    },
    "SKL010": {
        "group": "skills",
        "pt": ("Skill manda o agente seguir sem parar para você confirmar: \"{snippet}\"",
               "Sem pausas, um comando estranho vindo de um plano, issue ou arquivo roda antes de você ver.",
               "Use a skill com permissões restritas (sem Bash livre) e revise o plano antes de mandar executar."),
        "en": ("Skill tells the agent to keep going without checking with you: \"{snippet}\"",
               "With no pauses, an odd command coming from a plan, issue or file runs before you see it.",
               "Run it with restricted permissions (no unrestricted Bash) and review the plan before executing."),
    },
    "SKL011": {
        "group": "skills",
        "pt": ("Abre acesso remoto à máquina (reverse shell: {snippet})",
               "Um reverse shell entrega o terminal do seu computador para quem estiver do outro lado. Uma skill não tem motivo para isso.",
               "Não instale. Se já rodou, tire a máquina da rede, troque senhas e chaves e confira processos e tarefas agendadas."),
        "en": ("Opens remote access to the machine (reverse shell: {snippet})",
               "A reverse shell hands your computer's terminal to whoever is on the other end. A skill has no reason to do this.",
               "Do not install. If it already ran, take the machine off the network, rotate passwords and keys, and check processes and scheduled tasks."),
    },
}


# Na APP014 o CWE e o ASI dependem de onde o argumento chega (params["kind"]): (antes, depois) dos padrões da regra.
KIND_STANDARDS = {
    "APP014": {
        "shell": (["CWE-78"], ["ASI05"]),
        "code": (["CWE-94"], ["ASI05"]),
        "template": (["CWE-94"], ["ASI05"]),
        "deserialize": (["CWE-502"], ["ASI05"]),
        "sql": (["CWE-89"], ["ASI02"]),
        "path": (["CWE-22"], ["ASI02"]),
        "url": (["CWE-918"], ["ASI02"]),
        "html": (["CWE-79"], []),
    },
}


def standards(rule: str, params: dict | None = None):
    """Padrões do achado: os da regra, mais os que dependem do tipo de sink."""
    base = STANDARDS.get(rule, [])
    extra = KIND_STANDARDS.get(rule, {}).get((params or {}).get("kind"))
    return extra[0] + base + extra[1] if extra else list(base)


def texts(rule: str, lang: str, params: dict):
    """Devolve (título, por quê, como corrigir) já preenchidos."""
    lang = lang if lang in ("pt", "en") else "en"
    return tuple(fill(t, lang, params) for t in RULES[rule][lang])


def fill(template: str, lang: str, params: dict) -> str:
    """Preenche {nome} com os parâmetros do achado; campo que falta vira texto vazio."""
    safe = _Defaults(params)
    # Parâmetros que dependem do idioma vêm como nome_pt / nome_en.
    for k, v in params.items():
        if k.endswith("_" + lang):
            safe[k[:-3]] = v
    return template.format_map(safe)


class _Defaults(dict):
    def __missing__(self, key):
        return ""


# Classificação reconhecida pelo mercado: CWE, OWASP Top 10 para LLM 2026 (LLMxx:2026),
# OWASP Agentic Skills Top 10 (ASTxx, rascunho v1) e OWASP Agentic Applications 2026 (ASIxx).
STANDARDS = {
    "DEP001": ["CWE-1395"],
    "DEP002": ["CWE-506", "LLM04:2026", "AST02"],
    "DEP003": ["CWE-1395"],
    "DEP004": ["CWE-1395"],
    "SEC001": ["CWE-798", "LLM02:2026"],
    "SEC002": ["CWE-538"],
    "SEC003": ["CWE-538"],
    "SEC004": ["CWE-798"],
    "APP001": ["CWE-200", "LLM02:2026"],
    "APP002": ["CWE-522", "LLM02:2026"],
    "APP003": ["CWE-942"],
    "APP004": ["CWE-862"],
    "APP005": ["CWE-284"],
    "APP006": ["CWE-284"],
    "APP007": ["CWE-489"],
    "APP008": ["CWE-347"],
    "APP009": ["CWE-1426", "LLM10:2026"],
    "APP010": ["CWE-1427", "LLM01:2026"],
    "APP011": ["CWE-306", "CWE-770", "LLM06:2026"],
    "APP012": ["CWE-502", "CWE-829", "LLM04:2026"],
    "APP013": ["CWE-94", "LLM03:2026", "ASI05"],
    "APP014": ["LLM03:2026"],
    "COD001": ["CWE-89"],
    "COD002": ["CWE-78"],
    "COD003": ["CWE-94", "CWE-95"],
    "COD004": ["CWE-502"],
    "COD005": ["CWE-79"],
    "COD006": ["CWE-295"],
    "COD007": ["CWE-22"],
    "COD008": ["CWE-918"],
    "COD009": ["CWE-601"],
    "COD010": ["CWE-338"],
    "COD011": ["CWE-916"],
    "AGT001": ["CWE-250", "LLM03:2026", "ASI03"],
    "AGT002": ["CWE-494", "ASI05"],
    "AGT003": ["CWE-494", "LLM04:2026", "ASI04", "AST07"],
    "AGT004": ["CWE-798", "LLM02:2026"],
    "AGT005": ["CWE-319"],
    "AGT006": ["CWE-1188", "ASI04"],
    "SKL001": ["CWE-1427", "LLM01:2026", "AST01"],
    "SKL002": ["CWE-494", "AST02"],
    "SKL003": ["CWE-1427", "LLM01:2026", "AST01"],
    "SKL004": ["CWE-200", "AST01"],
    "SKL005": ["CWE-1427", "LLM01:2026", "AST05"],
    "SKL006": ["CWE-250", "LLM03:2026", "AST03"],
    "SKL007": ["CWE-506", "AST01"],
    "SKL008": ["CWE-200", "AST01"],
    "SKL009": ["CWE-829", "AST02"],
    "SKL010": ["LLM03:2026", "AST05"],
    "SKL011": ["CWE-506", "AST01"],
}
