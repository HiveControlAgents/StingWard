<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/banner-pt-dark.png">
    <img alt="Stingward: verificação de segurança para apps feitos com IA, skills do Claude Code e servidores MCP" src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/banner-pt-light.png" width="820">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/HiveControlAgents/StingWard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/HiveControlAgents/StingWard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/stingward/"><img alt="PyPI" src="https://img.shields.io/pypi/v/stingward?color=f5b83d&label=pypi"></a>
  <a href="https://www.npmjs.com/package/stingward"><img alt="npm" src="https://img.shields.io/npm/v/stingward?color=f5b83d"></a>
  <a href="https://pypi.org/project/stingward/"><img alt="Python 3.9+" src="https://img.shields.io/pypi/pyversions/stingward"></a>
  <img alt="Zero dependências" src="https://img.shields.io/badge/depend%C3%AAncias-0-brightgreen">
  <a href="https://github.com/HiveControlAgents/StingWard/blob/main/LICENSE"><img alt="Licença Apache 2.0" src="https://img.shields.io/badge/licen%C3%A7a-Apache%202.0-blue"></a>
  <a href="#qualidade"><img alt="stingward: A" src="https://img.shields.io/badge/stingward-A-brightgreen"></a>
</p>

<p align="center">
  <a href="https://github.com/HiveControlAgents/StingWard/blob/main/README.md">English</a> · <b>Português</b> · <a href="https://github.com/HiveControlAgents/StingWard/blob/main/README.es.md">Español</a>
</p>

Muita gente publica apps, skills do Claude Code e servidores MCP escritos com IA. Pouca gente sabe o que é uma CVE, por que `NEXT_PUBLIC_OPENAI_API_KEY` é um problema, ou que uma skill pode esconder instruções que só o modelo lê. **O Stingward encontra essas brechas e explica, em português simples, como fechar cada uma.**

<p align="center">
  <img alt="stingward skill ./pdf-helper: Não instale ainda. Instrução escondida em Unicode, script que lê as credenciais da AWS e envia para o webhook.site, shell sem restrição. Nota F." src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/demo-skill-pt.gif" width="820">
</p>

<p align="center"><sub>Uma skill que parece um ajudante de PDF. O Stingward decodifica a instrução invisível e acha o roubo de chaves antes de você instalar.</sub></p>

## Começo rápido

| Onde | Como |
|---|---|
| **Claude Code** | `/plugin marketplace add HiveControlAgents/StingWard` e depois `/plugin install stingward@stingward`. Aí é só perguntar *"meu projeto está seguro?"* ou *"posso instalar github.com/x/y?"* |
| **Terminal** | `pipx install stingward` (ou `uvx stingward`, ou `npx stingward` com Python 3.9+ instalado) e rode `stingward` no seu projeto |
| **GitHub** | Adicione a [Action](#github-action): ela comenta em cada PR, preenche a aba Security e verifica de novo todo dia |

```bash
stingward                         # audita o projeto da pasta atual
stingward skill ./alguma-skill    # audita uma skill, plugin ou servidor MCP antes de instalar
stingward skill dono/repo         # ...direto do GitHub (aceita também URLs .../tree/branch/subpasta)
stingward agents                  # audita a configuração do Claude Code, Claude Desktop, Cursor, Codex e Gemini desta máquina
```

Sem cadastro, sem telemetria, sem dependências: Python 3.9+ puro, no Linux, macOS e Windows.

## O que ele encontra

| Área | Exemplos |
|---|---|
| **Dependências** | CVEs conhecidas e **pacotes maliciosos** nos lockfiles de npm, Yarn, pnpm, Bun, pip, Poetry, uv, Pipenv, PDM, Go, Cargo, Bundler, Composer e NuGet. Priorizados pelo **KEV da CISA** (falhas exploradas agora) e pelo **EPSS** (chance de exploração), com a atualização única que resolve tudo o que se conhece. Sem lockfile, a menor versão que cada faixa aceita (`Pillow>=10`, `^1.6.0`) também é verificada. |
| **Segredos** | Chaves de API (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack...), chaves privadas, `service_role` do Supabase, webhooks, senha em URL, `.env` no git ou fora do `.gitignore`. O valor nunca aparece no relatório. |
| **Apps feitos com IA** | Segredo atrás de `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`, `dangerouslyAllowBrowser`, CORS aberto, tabela do Supabase sem RLS ou com `using (true)`, regras do Firebase abertas, modo debug, JWT sem verificar assinatura. No código que chama um modelo: a resposta dele chegando a `eval`, shell, SQL ou HTML, dado da requisição dentro do prompt de sistema, rota de IA sem login e sem limite de uso, `trust_remote_code` e `torch.load` inseguro, agente com ferramenta de Python REPL ou shell. Em servidores MCP e ferramentas de agente: argumento que o modelo escreve chegando a shell, `eval`, SQL, caminho de arquivo ou URL que o servidor busca. |
| **Código** | Injeção de SQL, de comando e de código, `pickle` e YAML inseguro, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`), verificação de TLS desligada, path traversal, SSRF, redirecionamento aberto, `Math.random` em token e hash rápido em senha. Python é lido com `ast` e JavaScript/TypeScript com padrões justos que seguem o dado da requisição dentro de cada função. |
| **Agentes e MCP** | `bypassPermissions`, `Bash(*)`, hook com `curl \| sh`, `enableAllProjectMcpServers`, MCP sem versão fixa, token no `.mcp.json`, MCP remoto sem HTTPS, pacote MCP vulnerável como o `mcp-remote` (CVE-2025-6514). |
| **Skills e prompts** | Caracteres invisíveis (tags Unicode, Trojan Source, largura zero), "ignore as instruções anteriores", "não conte ao usuário", leitura de `~/.ssh` ou `~/.aws` com chamada à internet, `curl \| bash`, reverse shell, código ofuscado, serviços de captura (webhook.site, ngrok...), scripts de instalação, `allowed-tools: Bash`, instrução escondida na descrição de ferramentas MCP. |

As 50 regras, com severidade, exemplos e correção: [docs/rules.pt-BR.md](https://github.com/HiveControlAgents/StingWard/blob/main/docs/rules.pt-BR.md).

<p align="center">
  <img alt="stingward ./my-saas: chave da OpenAI exposta por NEXT_PUBLIC_, resposta do modelo executada como comando de shell, next 14.1.0 com a CVE-2025-29927 (EPSS de 99%), SQL e caminho de arquivo montados com dados da requisição, servidor que busca qualquer URL, tabela do Supabase sem RLS, requests cuja menor versão aceita tem falhas conhecidas. Nota F." src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/demo-app-pt.gif" width="820">
</p>

<p align="center"><sub>Um app típico feito com IA, em Next.js e Supabase. Rode as duas demonstrações num clone deste repositório: <code>python scripts/demo/fixtures.py demo</code>, depois <code>stingward skill demo/pdf-helper</code> e <code>stingward demo/my-saas</code>.</sub></p>

## Como funciona

1. **Lista os arquivos**, pulando pastas de dependências e de build como `node_modules` e `dist`. Na auditoria de uma skill de terceiros ele lê o build, porque é isso que de fato roda.
2. **Lê os lockfiles** e pergunta ao [OSV.dev](https://osv.dev) sobre todos os pacotes e versões de uma vez. CVEs do [KEV da CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) viram críticas; o [EPSS](https://www.first.org/epss/) e o [NVD](https://nvd.nist.gov) completam a chance de exploração e as notas que faltam.
3. **Roda as verificações** de segredos, erros de app, configuração de agentes e conteúdo de skills, levando em conta o contexto: pastas de teste, documentação e exemplos pesam menos, e numa skill de terceiros um texto tranquilizador pode baixar o achado para médio, mas nunca escondê-lo.
4. **Escreve o relatório** em português ou inglês: veredito, o que corrigir primeiro, achados do pior para o melhor com onde, por quê e como corrigir (o mesmo problema em vários arquivos aparece uma vez, com todos os lugares), nota de A a F e um selo. `--html ARQ` grava também um relatório num arquivo só, para entregar ou imprimir em PDF: resumo, plano de correção com o esforço estimado, achados com o trecho de código (segredos mascarados) e escopo e método.

Só nome e versão dos pacotes saem da sua máquina (para `api.osv.dev`, `www.cisa.gov`, `api.first.org` e `services.nvd.nist.gov`). O código nunca sai. As respostas ficam em cache por algumas horas em `~/.cache/stingward`.

O Stingward lê conteúdo hostil por natureza, então trata esse conteúdo com cuidado: o git nunca descobre um repositório dentro dos arquivos auditados, os inicializadores nunca importam código da pasta auditada, e segredos, códigos de terminal e markdown são neutralizados em todos os formatos de relatório. Veja o [SECURITY.md](https://github.com/HiveControlAgents/StingWard/blob/main/SECURITY.md).

## GitHub Action

```yaml
# .github/workflows/stingward.yml
name: stingward
on:
  pull_request:
  push: { branches: [main] }
  schedule: [{ cron: "0 9 * * *" }]   # CVE nova aparece mesmo sem commit novo
permissions: { contents: read, pull-requests: write, security-events: write }
jobs:
  stingward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HiveControlAgents/StingWard@v0
        with: { lang: pt, fail-on: high }
```

Ela comenta o relatório no PR (e atualiza o mesmo comentário a cada execução), envia SARIF para a aba **Security** do repositório, escreve o resumo do job e expõe a nota em `steps.<id>.outputs.grade`.

| Entrada | Padrão | |
|---|---|---|
| `path` | `.` | Pasta a auditar |
| `fail-on` | `high` | Falha o job nesta severidade ou acima: `critical`, `high`, `medium`, `low`, `never` |
| `lang` | `en` | Idioma do relatório: `en` ou `pt` |
| `comment` | `true` | Comenta nos pull requests (precisa de `pull-requests: write`) |
| `sarif` | `true` | Envia SARIF para o code scanning (precisa de `security-events: write` e, em repositório privado, de `actions: read`) |
| `category` | `stingward` | Categoria do SARIF no code scanning. Use uma diferente em cada execução quando o mesmo workflow audita várias pastas |

## Referência da linha de comando

| Opção | |
|---|---|
| `--lang en\|pt` | Idioma do relatório (padrão: `STINGWARD_LANG`, depois o idioma do sistema) |
| `--format text\|json\|markdown\|sarif\|html` | O que vai para a saída padrão |
| `--json ARQ`, `--markdown ARQ`, `--sarif ARQ`, `--html ARQ` | Grava também esses arquivos, na mesma execução |
| `--fail-on critical\|high\|medium\|low\|never` | Código de saída 1 nesta severidade ou acima (padrão `high`) |
| `--only deps,secrets,app,code,agents` | Roda só algumas verificações |
| `--offline` | Não consulta as bases online (as dependências não são verificadas) |
| `--no-color` | Texto sem cores |
| `--review-template ARQ` | Grava o arquivo da revisão humana: um item por achado, mantendo o que já foi revisado |
| `--review ARQ` | Aplica a revisão humana: um status e um comentário para cada achado |
| `--client NOME`, `--notes ARQ` | "Preparado para" na capa e o parecer do analista (parágrafos, listas com `-`, `**negrito**`, `` `código` ``) |

| Código de saída | O que quer dizer |
|---|---|
| `0` | Nada na severidade de `--fail-on` ou acima |
| `1` | Achou algo na severidade de `--fail-on` ou acima |
| `2` | Erro de uso: opção errada, pasta que não existe, skill que não deu para baixar ou arquivo de saída que não deu para gravar |
| `3` | O OSV.dev não respondeu e as dependências não foram verificadas, ou respondeu só em parte e a verificação ficou incompleta. Um portão de CI não deve passar calado; use `--offline` para pular de propósito. |
| `4` | Nenhum arquivo foi lido, então não havia o que avaliar: pasta vazia, caminho errado ou, no CI, o código não foi baixado antes (checkout). Um portão de CI não deve passar calado; `--fail-on never` aceita. |

Ambiente: `STINGWARD_LANG` define o idioma padrão, `NVD_API_KEY` aumenta o limite de consultas ao NVD e `STINGWARD_CACHE` muda a pasta de cache.

**Nota:** A quer dizer só itens baixos ou nada · B médios, nenhum alto · C um ou dois altos · D três ou mais altos · F algum crítico. Todo relatório termina com um selo para o seu README:

```markdown
[![stingward: A](https://img.shields.io/badge/stingward-A-brightgreen)](https://github.com/HiveControlAgents/StingWard)
```

**Revisão humana:** numa auditoria que você entrega para alguém, grave o arquivo de revisão com `stingward . --review-template revisao.json`. Cada item aponta para um achado pela `fingerprint` (que também sai no JSON e no SARIF), que não muda quando outras partes do arquivo são editadas. Ela é feita com a linha marcada e o segredo já mascarado, então nada derivado de um segredo vai para o arquivo de revisão. Isso é de propósito e quer dizer que uma chave trocada por outra na mesma linha mantém o status: quando uma chave for trocada, confira essa linha de novo antes de reaproveitar a revisão. Ponha em `status` `confirmed`, `false_positive`, `accepted_risk` ou `fixed`, escreva o `comment` e rode `stingward . --review revisao.json --client "Nome do cliente" --notes parecer.md --html relatorio.html`. Alarmes falsos vão para um apêndice; eles e o que foi corrigido durante a auditoria saem da nota, da lista do que corrigir primeiro e do `--fail-on`. Riscos aceitos continuam na nota, mas saem da lista do que corrigir primeiro. Os relatórios em texto e Markdown também seguem a revisão. Comentários e parecer são escapados e passam pelo mesmo mascaramento de segredos dos trechos de código. Numa revisão feita por IA, ponha `"review_kind": "ai"` no arquivo de revisão: os relatórios passam a dizer revisão por IA em vez de revisão humana, `accepted_risk` é recusado (só o cliente aceita um risco) e `fixed` só é aceito para um achado que sumiu de uma varredura que podia vê-lo: sem `.stingwardignore`, comentário `stingward:ignore` ou os limites de tamanho e de arquivos escondendo.

**Alarme falso:** coloque uma linha no `.stingwardignore` na raiz do projeto (`REGRA caminho/glob`, `REGRA` ou `caminho/glob`), ou escreva `stingward:ignore` num comentário na linha. Se uma regra estiver errada, [avise](https://github.com/HiveControlAgents/StingWard/issues/new?template=false-positive.yml) com um exemplo mínimo.

**Padrões:** os achados trazem os códigos **CWE**, **OWASP Top 10 para LLM 2026** (`LLM01:2026`...), **OWASP Agentic Skills Top 10** (`AST01`..., rascunho v1) e **OWASP Top 10 para Aplicações Agênticas 2026** (`ASI01`...), no texto, no JSON e nas tags do SARIF.

## Qualidade

- **Mais de 400 testes automáticos**, e ainda testes online que consultam de verdade o OSV, o KEV, o EPSS e o NVD em seis ecossistemas. A cobertura de linhas passa de 90%.
- **Cada push roda 24 jobs de CI**: testes no Linux, macOS e Windows com Python 3.9 a 3.14, os pacotes do PyPI e do npm montados e instalados do zero nos três sistemas, o plugin do Claude Code validado e a Action rodando em projetos de exemplo.
- **O Stingward audita a si mesmo** no CI e não pode ter achado alto ou crítico; a nota dele é o selo A lá em cima.
- **Alarme falso é medido** em coleções populares de skills e servidores MCP públicos: nenhum achado crítico ou alto que não seja real, e poucos médios por repositório. Cada alarme falso corrigido vira teste de regressão.
- **Revisão de segurança do próprio Stingward**, por exemplo para garantir que uma pasta de skill montada como repositório git não executa comandos, e que um segredo nunca chega ao relatório. Cada problema encontrado é corrigido com um teste que falha no código antigo.

```bash
python -m unittest discover -s tests -t .                       # offline, poucos segundos
STINGWARD_ONLINE=1 python -m unittest discover -s tests -t .    # consulta também as bases de verdade
```

## Perguntas frequentes

**Relatório limpo quer dizer que meu projeto está seguro?** Não. Quer dizer que os erros mais comuns não estão lá. O Stingward é uma primeira linha rápida, não um teste de invasão.

**Meu código sai da minha máquina?** Não. Só nome e versão dos pacotes são enviados, para consultar as falhas.

**Qual a diferença para o `npm audit`, o Dependabot ou um scanner de segredos?** Cada um cobre uma parte. O Stingward junta dependências, segredos e os erros típicos de apps feitos com IA, agentes, skills e servidores MCP num relatório só, escrito para quem construiu o projeto, e audita uma skill antes de você instalar.

**Por que o `npx stingward` precisa de Python?** O motor é um único pacote em Python puro, sem dependências; o pacote do npm só dá a partida, para quem usa JavaScript rodar sem `pip`. No Windows, o `npx` não acha os atalhos `.bat` do pyenv-win: instale o Python pelo python.org ou use `pip install stingward`.

**Dá para verificar um repositório privado ou uma skill no meu disco?** Dá. Aponte para uma pasta, ou para `dono/repo` com as suas credenciais do git de sempre.

## Limite

O aviso vai para quem roda a ferramenta, sobre o código que essa pessoa escolheu verificar. O Stingward não varre repositórios de terceiros nem abre issues neles.

## Contribuir

Relatos de bug, alarmes falsos e regras novas são bem-vindos. Leia o [CONTRIBUTING.pt-BR.md](https://github.com/HiveControlAgents/StingWard/blob/main/CONTRIBUTING.pt-BR.md) para preparar o ambiente, e relate problemas de segurança do próprio Stingward em particular, como explica o [SECURITY.md](https://github.com/HiveControlAgents/StingWard/blob/main/SECURITY.md).

Dados de vulnerabilidades: [OSV.dev](https://osv.dev) (que reúne GitHub Advisories, NVD, PyPA, RustSec, Go e os pacotes maliciosos da OpenSSF), [KEV da CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS da FIRST](https://www.first.org/epss/) e [NVD](https://nvd.nist.gov).

[Apache 2.0](https://github.com/HiveControlAgents/StingWard/blob/main/LICENSE) © Isaque Moutta
