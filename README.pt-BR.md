# Stingward

**Verificação de segurança para projetos feitos com IA, e para skills e servidores MCP antes de instalar.**

Muita gente publica apps, skills do Claude Code e servidores MCP escritos com IA. Pouca gente sabe o que é uma CVE, por que `NEXT_PUBLIC_OPENAI_API_KEY` é um problema, ou que uma skill pode esconder instruções que só o modelo lê. O `stingward` encontra essas stingwards e explica, em português simples, como fechar cada uma.

[English](README.md)

## O que ele verifica

- **Dependências:** CVEs conhecidas e **pacotes maliciosos** nos lockfiles de npm, PyPI, Go, crates.io, RubyGems e Packagist, priorizados pela lista **KEV da CISA** (falhas exploradas agora) e pelo **EPSS** (chance de exploração). Um achado por pacote, com a atualização única que resolve tudo.
- **Segredos:** chaves de API (OpenAI, Anthropic, GitHub, AWS, Stripe, Slack...), chaves privadas, `service_role` do Supabase, webhooks, senha em URL, `.env` no git ou fora do `.gitignore`. O motor de segredos vem do CEOVul.
- **Apps feitos com IA:** segredo atrás de `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`, `dangerouslyAllowBrowser`, CORS aberto, tabela do Supabase sem RLS ou com `using (true)`, regras do Firebase abertas, modo debug, JWT sem verificar assinatura.
- **Agentes e MCP:** `bypassPermissions`, `Bash(*)`, hook com `curl | sh`, `enableAllProjectMcpServers`, MCP sem versão fixa, token escrito no `.mcp.json`, MCP remoto sem HTTPS, pacote MCP vulnerável (ex.: `mcp-remote`, CVE-2025-6514).
- **Skills e prompts:** caracteres invisíveis (tags Unicode, Trojan Source, largura zero), "ignore as instruções anteriores" e "não conte ao usuário", leitura de `~/.ssh` / `~/.aws` com chamada à internet, `curl | bash`, código ofuscado, serviços de captura (webhook.site, ngrok...), scripts de instalação, `allowed-tools: Bash`, "não pare para confirmar" e instrução escondida na descrição de ferramentas MCP.

Só nome e versão dos pacotes saem da sua máquina. O código nunca sai. Sem cadastro, sem telemetria, sem dependências: Python 3.9+ puro.

## Como usar

**No Claude Code:**

```
/plugin marketplace add HiveControlAgents/StingWard
/plugin install stingward@stingward
```

Depois é só perguntar: *"meu projeto está seguro?"* ou *"posso instalar esta skill: github.com/x/y?"*.

**Na linha de comando:**

```bash
pipx install stingward          # ou: uvx stingward · npx stingward (precisa de Python 3.9+)

stingward                         # audita o projeto da pasta atual
stingward skill ./alguma-skill    # audita uma skill, plugin ou servidor MCP antes de instalar
stingward skill dono/repo         # ... direto do GitHub
stingward agents                  # audita ~/.claude, Claude Desktop, Cursor, Codex e Gemini desta máquina
```

**No GitHub:** copie [examples/stingward.yml](examples/stingward.yml) para `.github/workflows/`. A Action comenta o relatório no PR, publica SARIF na aba Security e roda todo dia, porque CVE nova aparece mesmo sem commit novo.

Cada achado vem com os códigos que times de segurança já usam: CWE, OWASP Top 10 para LLM 2026 (`LLM01:2026`...), OWASP Agentic Skills Top 10 (`AST01`..., rascunho v1) e OWASP Agentic Applications 2026 (`ASI01`...).

O relatório termina com uma nota de A a F (A: só itens baixos ou nada · B: médios, nenhum alto · C: 1 ou 2 altos · D: 3+ altos · F: algum crítico) e um selo para o README. Código de saída: `0` limpo, `1` achou algo na severidade de `--fail-on` ou acima, `2` erro de uso, `3` o OSV.dev não respondeu e as dependências não foram checadas. Para alarme falso, use `.stingwardignore` (`REGRA caminho/glob`) ou um comentário `stingward:ignore` na linha.

## Limite

O aviso vai para quem roda a ferramenta, sobre o código que essa pessoa escolheu verificar. O `stingward` não varre repositórios de terceiros nem abre issues neles. Relatório limpo quer dizer que os erros mais comuns não estão lá, não que o projeto é seguro.
