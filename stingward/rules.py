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
               "Remova o pacote agora, apague node_modules/venv e troque todas as chaves e senhas da máquina e do projeto."),
        "en": ("{pkg} {version} is a malicious package ({vuln_id})",
               "This package was published to steal data or run code. It is not a bug, it is an attack.",
               "Remove it now, delete node_modules/venv, and rotate every key and password on this machine and project."),
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
        "pt": ("Chave service_role do Supabase no código",
               "Essa chave ignora todas as regras de acesso (RLS). Com ela, qualquer pessoa lê e apaga o banco inteiro.",
               "Gere uma chave nova no painel do Supabase (Settings > API), use a service_role só no servidor e a anon no front-end."),
        "en": ("Supabase service_role key in code",
               "This key bypasses every access rule (RLS). With it anyone can read and delete the whole database.",
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
        "pt": ("Hook baixa e executa código da internet",
               "Toda vez que o hook dispara, roda o que estiver naquele endereço hoje, sem revisão.",
               "Baixe o script uma vez, revise, guarde no repositório e chame o arquivo local."),
        "en": ("Hook downloads and runs code from the internet",
               "Every time the hook fires it runs whatever is at that URL today, unreviewed.",
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
