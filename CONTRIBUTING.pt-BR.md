# Como contribuir com o Stingward

[English](CONTRIBUTING.md)

Obrigado pela ajuda. As contribuições mais úteis são **alarmes falsos e problemas não detectados com um exemplo mínimo**, regras novas para erros que você vê em projetos feitos com IA, e ajustes nas explicações para que continuem claras para quem não é especialista em segurança.

## Preparar o ambiente

O Stingward é Python 3.9+ puro, sem dependências, então não há nada para instalar:

```bash
git clone https://github.com/HiveControlAgents/StingWard.git
cd StingWard
python -m stingward --offline .                                 # roda nele mesmo
python -m unittest discover -s tests -t .                       # testes offline, poucos segundos
STINGWARD_ONLINE=1 python -m unittest discover -s tests -t .    # consulta também OSV, KEV, EPSS e NVD
```

Para rodar as demonstrações do README: `python scripts/demo/fixtures.py demo`, depois `python -m stingward skill demo/pdf-helper` e `python -m stingward demo/my-saas`.

Para montar o site: `python site/build.py _site` e abra o `_site/index.html`. Com `--online`, o relatório do app inclui as dependências consultadas no OSV.dev, como no site publicado.

## Onde fica cada coisa

| Caminho | O que é |
|---|---|
| `stingward/cli.py` | Linha de comando, códigos de saída, download de skill do GitHub |
| `stingward/scan.py` | Lista de arquivos, execução das verificações, `.stingwardignore`, severidade conforme o contexto |
| `stingward/checks/` | `deps.py`, `secrets.py`, `app.py`, `code.py` (falhas no código Python e JavaScript, e no código que chama um modelo), `agents.py` (agentes, MCP e skills) |
| `stingward/rules.py` | Título, motivo e correção de cada regra, em português e inglês, e os códigos de padrão |
| `stingward/report.py` | Saída em texto, Markdown, JSON e SARIF, nota e selo |
| `stingward/lockfiles.py`, `vulndb.py`, `net.py` | Leitura de lockfiles, clientes de OSV/KEV/EPSS/NVD, HTTP com cache e novas tentativas |
| `stingward/gitsafe.py` | O único jeito de o Stingward chamar o git (veja abaixo) |
| `skills/stingward/` | A skill do Claude Code que vem no plugin |
| `action.yml` | A GitHub Action |
| `npm/` | O inicializador do npm (`scripts/build-npm.sh` copia o pacote Python para dentro) |
| `docs/` | Referência das regras e imagens do README |
| `site/` | O site: `build.py` preenche o `page.html` com o `text.json` e com relatórios reais do Stingward, e o `.github/workflows/pages.yml` publica |

## Criar ou mudar uma regra

1. Escreva os textos em `stingward/rules.py`, em português e inglês, para quem fez o app com IA: o que é, por que importa, o que fazer. Coloque os códigos de padrão em `STANDARDS`.
2. Implemente no arquivo certo em `stingward/checks/`.
3. Escreva testes do que ela precisa pegar **e** dos parecidos que ela não pode marcar. Todo alarme falso corrigido vira teste de regressão em `tests/test_fp_regressions.py`.
4. Documente em `docs/rules.md` e `docs/rules.pt-BR.md` e coloque nas tabelas de regras. O `tests/test_docs.py` falha se faltar uma regra na documentação ou se os padrões não baterem.

## Regras para o código

- **O conteúdo auditado é hostil.** Nunca execute, nunca importe nada da pasta auditada e chame o git só pelo `stingward/gitsafe.py`, que impede o git de descobrir um repositório dentro dos arquivos auditados.
- **Nunca imprima um segredo**, nem um pedaço dele. Trechos passam por `secrets.mask()`.
- **Só a biblioteca padrão**, compatível com Python 3.9, funcionando no Linux, macOS e Windows.
- **Um achado numa skill de terceiros pode baixar, nunca sumir**, para que um atacante não esconda o ataque com palavras.
- Siga o estilo ao redor: funções curtas e comentários só onde o motivo não é óbvio.

## Pull requests

Mantenha o PR focado, inclua testes e confira se o CI passou nos três sistemas. Descreva o antes e o depois em palavras simples. Ao contribuir, você concorda que seu trabalho sai sob a [licença Apache 2.0](LICENSE).

## Versões (mantenedores)

Suba a versão em `pyproject.toml`, `stingward/__init__.py`, `npm/package.json` e `.claude-plugin/plugin.json`, escreva a entrada no `CHANGELOG.md` e envie para a `main`. Quando o CI passa, o workflow de release publica no PyPI e no npm com publicação confiável, cria a tag `vX.Y.Z`, move a `v0` e cria o release no GitHub. O `tests/test_docs.py` confere se as versões batem.

## Convivência e segurança

Seja gentil; veja o [Código de Conduta](CODE_OF_CONDUCT.md). Relate vulnerabilidades do próprio Stingward em particular, como explica o [SECURITY.md](SECURITY.md).
