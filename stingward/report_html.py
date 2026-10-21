"""Relatório em HTML para entregar a quem pediu a auditoria: um arquivo só, sem rede, que imprime bem em PDF (A4).

Tudo o que vem do projeto auditado (nome de arquivo, trecho de código, nome de pacote, resumo de aviso) pode ser do
atacante. Passa por _h(), que deixa visíveis os caracteres invisíveis e de controle e escapa o HTML; os trechos de
código passam antes pelo mesmo mascaramento de segredos do resto do relatório. A política de conteúdo (CSP) do
arquivo bloqueia script, imagem, fonte, formulário e conexão: só o CSS embutido vale.
"""
from __future__ import annotations

import datetime
import html as _html
import itertools
import os
import re
import unicodedata
from collections import Counter

from . import __version__, gitsafe, report
from . import _redact as redact
from .checks import secrets
from .model import SEV_RANK, SEVERITIES
from .rules import RULES, standards

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
GROUPS = ["deps", "secrets", "app", "code", "agents", "skills"]
CHECK_ORDER = ["deps", "secrets", "app", "code", "agents"]
MAX_PLACES = 100      # lugares listados por item
MAX_EVIDENCE = 3      # trechos de código por item
MAX_VULNS = 8         # falhas listadas por pacote
MAX_LINE = 2000       # linha maior que isso (código minificado) não é mostrada
SHOW = 220            # caracteres mostrados por linha de trecho

# Textos com (singular, plural) passam por _n().
H = {
    "pt": {
        "doc": "Relatório de auditoria de segurança", "brand_sub": "Auditoria de segurança",
        "kind": {"project": "Auditoria de segurança do projeto", "skill": "Auditoria de skill, plugin ou servidor MCP",
                 "agents": "Auditoria da configuração de agentes"},
        "agents_name": "Agentes desta máquina",
        "date": "Data", "target": "Alvo", "commit": "Commit", "type": "Tipo", "tool": "Ferramenta", "found": "Achados",
        "checks": "Verificações",
        "type_of": {"project": "Projeto", "skill": "Skill, plugin ou servidor MCP", "agents": "Configuração de agentes"},
        "none_found": "nenhum",
        "grade": "Nota",
        "verdict": {
            "project": {"bad": "Há problemas graves. Corrija os itens críticos e altos antes de lançar ou de colocar mais usuários no app.",
                        "mid": "Nada crítico ou alto. Os itens médios merecem atenção, porque podem virar problema de verdade.",
                        "ok": "Nada grave encontrado. É um bom sinal, não uma garantia: veja o escopo e os limites no fim."},
            "agents": {"bad": "Há problemas graves nesta configuração. Corrija os itens críticos e altos antes de continuar usando os agentes.",
                       "mid": "Nada crítico ou alto. Os itens médios merecem atenção, porque podem virar problema de verdade.",
                       "ok": "Nada grave encontrado. É um bom sinal, não uma garantia: veja o escopo e os limites no fim."},
        },
        "warn_offline": "Modo offline: as dependências não foram checadas contra as bases de falhas conhecidas.",
        "warn_osv": "O OSV.dev não respondeu: as dependências não foram checadas contra as bases de falhas conhecidas.",
        "warn_osv_partial": "A checagem de dependências ficou incompleta: {detail}. Rode de novo mais tarde para completá-la.",
        "warn_kev": "A lista CISA KEV não respondeu: uma falha que atacantes já exploram pode aparecer com severidade abaixo da real.",
        "warn_big": ("{n} arquivo de código ou texto acima de {mb} MB não foi lido e ficou fora desta auditoria. A lista está em {scope}.",
                     "{n} arquivos de código ou texto acima de {mb} MB não foram lidos e ficaram fora desta auditoria. A lista está em {scope}."),
        "warn_many": "A pasta tem mais de {n} arquivos: a leitura parou aí, e o resto ficou fora desta auditoria.",
        "warn_only": "Só parte das verificações rodou: {checks}.",
        "toc": "Conteúdo",
        "s_summary": "Resumo executivo", "s_plan": "Plano de correção", "s_findings": "Achados em detalhe", "s_scope": "Escopo e método",
        "grade_means": "O que a nota quer dizer",
        "grade_intro": "A nota vai de A a F e depende só dos achados mais graves.",
        "scale": {"A": "Só itens baixos, ou nenhum.", "B": "Itens médios, nenhum alto ou crítico.", "C": "Um ou dois itens altos, nenhum crítico.",
                  "D": "Três ou mais itens altos, nenhum crítico.", "F": "Pelo menos um item crítico."},
        "sev": {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Info"},
        "sev_help": {"critical": "Dá para explorar agora, com dano sério.", "high": "Grave, corrija logo.",
                     "medium": "Risco real, mas depende de outras condições.", "low": "Higiene: vale arrumar.", "info": "Só para saber."},
        "grouped": "{n} achados, agrupados em {problems}: o mesmo problema em vários lugares aparece uma vez, com todos os lugares.",
        "problems": ("{n} problema", "{n} problemas"),
        "first": "Corrija primeiro", "first_where": "Onde:",
        "first_none": "Nada crítico ou alto, então nada urgente. Siga o plano de correção na ordem.",
        "clean": "Nada encontrado. Isso não prova que está seguro, mas os erros mais comuns não estão aqui.",
        "more_places": ("e mais {n} lugar", "e mais {n} lugares"),
        "plan_intro": "Siga de cima para baixo. O esforço é uma estimativa para quem conhece o código.",
        "effort_h": "Esforço",
        "effort": {"quick": "Rápido", "hours": "Horas", "days": "Dias"},
        "effort_legend": "Rápido: menos de uma hora. Horas: cabe num dia. Dias: mais de um dia, em geral porque é preciso testar de novo ou reescrever uma parte.",
        "col_n": "#", "col_problem": "Problema", "col_where": "Onde",
        "band": {"critical": "Crítico: corrija agora", "high": "Alto: nesta semana", "medium": "Médio: neste mês",
                 "low": "Baixo: quando puder", "info": "Informativo"},
        "plan_empty": "Nada a corrigir.",
        "group": {"deps": "Dependências", "secrets": "Segredos", "app": "Aplicação", "code": "Código", "agents": "Agentes e MCP", "skills": "Skills e prompts"},
        "where": "Onde", "evidence": "Evidência", "why": "Por que importa", "fix": "Como corrigir", "standards": "Padrões",
        "refs": "Referências", "rule": "Regra",
        "line": "linha {n}", "whole_file": "o arquivo inteiro",
        "ev_note": "Trechos lidos dos arquivos no momento da auditoria. Segredos aparecem mascarados.",
        "ev_missing": "Não foi possível ler este trecho.",
        "ev_long": "linha longa ({n} caracteres), não exibida",
        "ev_more": ("Trecho do outro lugar omitido.", "Trechos dos outros {n} lugares omitidos."),
        "hidden": ("{n} caractere invisível", "{n} caracteres invisíveis"),
        "vulns": "Falhas conhecidas nesta versão", "vulns_floor": "Falhas conhecidas na menor versão aceita", "v_id": "ID", "v_sev": "Severidade", "v_summary": "Resumo", "v_fixed": "Corrigida em",
        "v_more": ("e mais {n} falha", "e mais {n} falhas"), "v_none": "sem correção",
        "no_findings": "Nenhum achado.",
        "scope_what": "O que foi verificado",
        "unread_big": ("{n} arquivo de código ou texto passou do limite de {mb} MB e não foi lido:",
                       "{n} arquivos de código ou texto passaram do limite de {mb} MB e não foram lidos:"),
        "unread_more": ("e mais {n} arquivo", "e mais {n} arquivos"),
        "files": ("{n} arquivo lido", "{n} arquivos lidos"),
        "pkgs": ("{n} pacote encontrado em lockfiles e configurações de MCP", "{n} pacotes encontrados em lockfiles e configurações de MCP"),
        "pkgs_skipped": "Dependências não verificadas", "rules": "{n} regras",
        "check_name": {"deps": "dependências", "secrets": "segredos", "app": "erros comuns de apps feitos com IA", "code": "falhas no código (injeção, XSS, SSRF e outras)", "agents": "agentes, MCP e skills"},
        "ignore": ("O projeto tem {n} regra no .stingwardignore, que esconde alguns achados de propósito. Confira se ela ainda faz sentido.",
                   "O projeto tem {n} regras no .stingwardignore, que escondem alguns achados de propósito. Confira se elas ainda fazem sentido."),
        "sources_h": "Bases consultadas", "src_col": "Base", "src_role": "Para quê", "src_status": "Situação",
        "src": {"osv": ("OSV.dev", "falhas conhecidas e pacotes maliciosos"),
                "kev": ("CISA KEV", "falhas que atacantes estão explorando agora"),
                "epss": ("EPSS (FIRST)", "chance de exploração nos próximos 30 dias"),
                "nvd": ("NVD", "nota de severidade quando o aviso não traz")},
        "st_ok": "consultado", "st_partial": "consultado em parte: {detail}", "st_kev": "consultado, catálogo {v}", "st_fail": "não respondeu", "st_offline": "pulado (modo offline)",
        "st_off": "não rodou (verificação de dependências desligada)", "st_nopkg": "não foi preciso: nenhum pacote encontrado",
        "st_nocve": "não foi preciso: nenhuma CVE encontrada", "st_noscore": "não foi preciso: todos os avisos tinham nota",
        "st_empty": "consultado, sem resposta útil", "st_na": "não foi preciso",
        "privacy": "Só nomes e versões de pacotes saíram da máquina, para essas bases. O código não saiu.",
        "method_h": "Como foi feito",
        "method": ["Listamos os arquivos do alvo, sem as pastas de dependências e de build, como node_modules e dist. Numa skill de terceiros o build é lido, porque é ele que roda.",
                   "Lemos os lockfiles e perguntamos ao OSV.dev sobre cada pacote e versão. Falhas que estão na lista KEV da CISA viram críticas; EPSS e NVD completam a chance de exploração e as notas que faltam.",
                   "Rodamos {n} regras para segredos, erros comuns de apps feitos com IA, falhas no código do próprio projeto, configurações de agentes e MCP e conteúdo de skills. Pastas de teste, documentação e exemplos pesam menos.",
                   "Damos a nota de A a F pelos achados mais graves."],
        "limits_h": "Limites",
        "limits": ["É uma primeira linha de defesa, automática e rápida: lê o código e a configuração atrás de erros e falhas conhecidas. Não é um teste de invasão: ninguém tentou entrar no app rodando.",
                   "Ficam de fora o app em funcionamento, o fluxo de login, as regras de negócio, as configurações do servidor e da nuvem e tudo o que não está nestes arquivos.",
                   "Um relatório limpo quer dizer que os erros comuns que a ferramenta conhece não apareceram nesta data. Não quer dizer que o app é seguro.",
                   "Falhas novas são publicadas todo dia: uma dependência boa hoje pode ter falha amanhã. Rode a verificação de novo com frequência, por exemplo a cada pull request.",
                   "Um achado pode ser alarme falso. Cada um mostra onde está, para você confirmar antes de mexer no código."],
        "footer": "Gerado pelo Stingward {v}, software livre (Apache 2.0).",
        # revisão humana (--review, --client, --notes)
        "client": "Preparado para", "review_meta": "Revisão humana", "reviewer_none": "uma pessoa",
        "status": report.T["pt"]["status"],
        "s_appendix": "Apêndice: alarmes falsos",
        "notes_h": "Parecer do analista",
        "grade_rule": "Depois da revisão humana, alarmes falsos e o que foi corrigido durante a auditoria não contam.",
        "review_line": "Revisão humana: {counts}.",
        "first_none_accepted": "Nada crítico ou alto para corrigir agora: o que sobrou nessas severidades é risco aceito, com o motivo junto do achado.",
        "clean_reviewed": "Depois da revisão, nenhum achado continua valendo: eram alarmes falsos ou foram corrigidos durante a auditoria. Isso não prova que está seguro.",
        "band_done": "Sem ação planejada: risco aceito ou já corrigido",
        "status_h": "Situação",
        "review_h": "Revisão",
        "appendix_intro": "Quem revisou conferiu estes achados no código e concluiu que não são problema neste projeto. Eles não contam para a nota, para o plano nem para o que corrigir primeiro. Ficam aqui para você ver o que foi descartado e por quê.",
        "human_h": "Revisão humana",
        "human_intro": "Depois da varredura automática, {who} conferiu os achados à mão, no código e na configuração, e marcou cada um como confirmado, alarme falso, risco aceito ou corrigido. O comentário de quem revisou aparece junto de cada achado.",
        "human_rules_h": "Como a revisão muda a nota",
        "human_rules": ["Contam para a nota os achados confirmados, os riscos aceitos e os que ainda não foram revisados.",
                        "Alarmes falsos não contam: saem da nota, do plano e da lista do que corrigir primeiro e ficam no apêndice, com o motivo.",
                        "O que foi corrigido e conferido durante a auditoria não conta para a nota nem entra no que corrigir primeiro, mas continua no relatório, marcado como corrigido.",
                        "Riscos aceitos continuam contando para a nota, porque o risco existe, mas saem da lista do que corrigir primeiro: a decisão de conviver com eles fica registrada junto do achado."],
        "method_review": "Uma pessoa conferiu os achados à mão e marcou o resultado de cada um: confirmado, alarme falso, risco aceito ou corrigido.",
        "method_grade_review": "Damos a nota de A a F pelos achados mais graves que continuam valendo depois da revisão.",
        "limits_review": ["É uma varredura automática do código e da configuração, conferida por uma pessoa. Não é um teste de invasão: ninguém tentou entrar no app rodando.",
                          "Ficam de fora o app em funcionamento, as regras de negócio, as configurações do servidor e da nuvem e tudo o que não está nestes arquivos, a não ser o que o parecer do analista disser que foi conferido à parte.",
                          "Um relatório limpo quer dizer que os erros comuns que a ferramenta conhece não apareceram nesta data. Não quer dizer que o app é seguro.",
                          "Falhas novas são publicadas todo dia: uma dependência boa hoje pode ter falha amanhã. Rode a verificação de novo com frequência, por exemplo a cada pull request.",
                          "A revisão humana diminui os alarmes falsos, mas não elimina o erro: é o julgamento de uma pessoa com o que estava disponível nesta data. Se algo não bater com o que você sabe do app, fale com quem revisou."],
    },
    "en": {
        "doc": "Security audit report", "brand_sub": "Security audit",
        "kind": {"project": "Project security audit", "skill": "Skill, plugin or MCP server audit", "agents": "Agent setup audit"},
        "agents_name": "Agents on this machine",
        "date": "Date", "target": "Target", "commit": "Commit", "type": "Type", "tool": "Tool", "found": "Findings",
        "checks": "Checks",
        "type_of": {"project": "Project", "skill": "Skill, plugin or MCP server", "agents": "Agent setup"},
        "none_found": "none",
        "grade": "Grade",
        "verdict": {
            "project": {"bad": "Serious problems found. Fix the critical and high items before you launch or bring in more users.",
                        "mid": "Nothing critical or high. The medium items deserve attention: they can turn into real problems.",
                        "ok": "Nothing serious found. That is a good sign, not a guarantee: see scope and limitations at the end."},
            "agents": {"bad": "Serious problems in this setup. Fix the critical and high items before you keep using these agents.",
                       "mid": "Nothing critical or high. The medium items deserve attention: they can turn into real problems.",
                       "ok": "Nothing serious found. That is a good sign, not a guarantee: see scope and limitations at the end."},
        },
        "warn_offline": "Offline mode: dependencies were not checked against the vulnerability databases.",
        "warn_osv": "OSV.dev did not respond: dependencies were not checked against the vulnerability databases.",
        "warn_osv_partial": "The dependency check is incomplete: {detail}. Run it again later to complete it.",
        "warn_kev": "The CISA KEV list did not respond: a vulnerability attackers already exploit may show a lower severity than it should.",
        "warn_big": ("{n} code or text file over {mb} MB was not read and is not covered by this audit. The list is under {scope}.",
                     "{n} code or text files over {mb} MB were not read and are not covered by this audit. The list is under {scope}."),
        "warn_many": "The folder has more than {n} files: reading stopped there, and the rest is not covered by this audit.",
        "warn_only": "Only some checks ran: {checks}.",
        "toc": "Contents",
        "s_summary": "Executive summary", "s_plan": "Remediation plan", "s_findings": "Findings in detail", "s_scope": "Scope and method",
        "grade_means": "What the grade means",
        "grade_intro": "The grade goes from A to F and depends only on the most serious findings.",
        "scale": {"A": "Only low items, or none.", "B": "Medium items, nothing high or critical.", "C": "One or two high items, nothing critical.",
                  "D": "Three or more high items, nothing critical.", "F": "At least one critical item."},
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "sev_help": {"critical": "Exploitable now, with serious damage.", "high": "Serious, fix soon.",
                     "medium": "Real risk that depends on other conditions.", "low": "Hygiene, worth tidying.", "info": "For your information."},
        "grouped": "{n} findings, grouped into {problems}: the same problem in several places is listed once, with every place.",
        "problems": ("{n} problem", "{n} problems"),
        "first": "Fix these first", "first_where": "Where:",
        "first_none": "Nothing critical or high, so nothing urgent. Work through the remediation plan in order.",
        "clean": "Nothing found. That does not prove it is safe, but the most common mistakes are not here.",
        "more_places": ("and {n} more place", "and {n} more places"),
        "plan_intro": "Work from top to bottom. Effort is a rough estimate for someone who knows the code.",
        "effort_h": "Effort",
        "effort": {"quick": "Quick", "hours": "Hours", "days": "Days"},
        "effort_legend": "Quick: under an hour. Hours: fits in a day. Days: more than a day, usually because something has to be retested or rewritten.",
        "col_n": "#", "col_problem": "Problem", "col_where": "Where",
        "band": {"critical": "Critical: fix now", "high": "High: this week", "medium": "Medium: this month",
                 "low": "Low: when you can", "info": "For your information"},
        "plan_empty": "Nothing to fix.",
        "group": {"deps": "Dependencies", "secrets": "Secrets", "app": "Application", "code": "Code", "agents": "Agents and MCP", "skills": "Skills and prompts"},
        "where": "Where", "evidence": "Evidence", "why": "Why it matters", "fix": "How to fix", "standards": "Standards",
        "refs": "References", "rule": "Rule",
        "line": "line {n}", "whole_file": "the whole file",
        "ev_note": "Excerpts read from the files at audit time. Secrets are masked.",
        "ev_missing": "Could not read this excerpt.",
        "ev_long": "long line ({n} characters), not shown",
        "ev_more": ("Excerpt for the other place left out.", "Excerpts for the other {n} places left out."),
        "hidden": ("{n} invisible character", "{n} invisible characters"),
        "vulns": "Known vulnerabilities in this version", "vulns_floor": "Known vulnerabilities in the lowest version allowed", "v_id": "ID", "v_sev": "Severity", "v_summary": "Summary", "v_fixed": "Fixed in",
        "v_more": ("and {n} more", "and {n} more"), "v_none": "no fix yet",
        "no_findings": "No findings.",
        "scope_what": "What was checked",
        "unread_big": ("{n} code or text file was over the {mb} MB limit and was not read:",
                       "{n} code or text files were over the {mb} MB limit and were not read:"),
        "unread_more": ("and {n} more file", "and {n} more files"),
        "files": ("{n} file read", "{n} files read"),
        "pkgs": ("{n} package found in lockfiles and MCP configs", "{n} packages found in lockfiles and MCP configs"),
        "pkgs_skipped": "Dependencies not checked", "rules": "{n} rules",
        "check_name": {"deps": "dependencies", "secrets": "secrets", "app": "common AI-built app mistakes", "code": "code flaws (injection, XSS, SSRF and more)", "agents": "agents, MCP and skills"},
        "ignore": ("The project has {n} rule in .stingwardignore that hides some findings on purpose. Check that it still makes sense.",
                   "The project has {n} rules in .stingwardignore that hide some findings on purpose. Check that they still make sense."),
        "sources_h": "Sources consulted", "src_col": "Source", "src_role": "Used for", "src_status": "Status",
        "src": {"osv": ("OSV.dev", "known vulnerabilities and malicious packages"),
                "kev": ("CISA KEV", "vulnerabilities attackers are exploiting now"),
                "epss": ("EPSS (FIRST)", "likelihood of exploitation in the next 30 days"),
                "nvd": ("NVD", "severity scores missing from advisories")},
        "st_ok": "consulted", "st_partial": "partly answered: {detail}", "st_kev": "consulted, catalog {v}", "st_fail": "did not respond", "st_offline": "skipped (offline mode)",
        "st_off": "not run (dependency check turned off)", "st_nopkg": "not needed: no packages found",
        "st_nocve": "not needed: no CVE found", "st_noscore": "not needed: every advisory had a score",
        "st_empty": "consulted, no useful answer", "st_na": "not needed",
        "privacy": "Only package names and versions left the machine, to these services. The code did not.",
        "method_h": "How it was done",
        "method": ["Listed the target's files, skipping dependency and build folders such as node_modules and dist. In a third-party skill the build output is read, since that is what runs.",
                   "Read the lockfiles and asked OSV.dev about every package and version. Vulnerabilities on CISA's KEV list become critical; EPSS and NVD add the likelihood of exploitation and missing scores.",
                   "Ran {n} rules for secrets, common AI-built app mistakes, flaws in the project's own code, agent and MCP settings, and skill content. Test folders, docs and examples count less.",
                   "Graded the result from A to F by the most serious findings."],
        "limits_h": "Limitations",
        "limits": ["This is a fast, automated first line of defense: it reads the code and configuration looking for known mistakes and known vulnerabilities. It is not a penetration test: nobody tried to break into the running app.",
                   "Out of scope: the running app, login flows, business logic, server and cloud settings, and anything that is not in these files.",
                   "A clean report means the common mistakes this tool knows were not found on this date. It does not mean the app is secure.",
                   "New vulnerabilities are published every day: a dependency that is fine today can have a flaw tomorrow. Run the check again often, for example on every pull request.",
                   "A finding can be a false alarm. Each one shows where it is, so you can confirm before changing code."],
        "footer": "Generated by Stingward {v}, open source (Apache 2.0).",
        # human review (--review, --client, --notes)
        "client": "Prepared for", "review_meta": "Human review", "reviewer_none": "a person",
        "status": report.T["en"]["status"],
        "s_appendix": "Appendix: false positives",
        "notes_h": "Analyst summary",
        "grade_rule": "After the human review, false positives and what was fixed during the audit do not count.",
        "review_line": "Human review: {counts}.",
        "first_none_accepted": "Nothing critical or high left to fix now: what remains at those levels is accepted risk, with the reason next to the finding.",
        "clean_reviewed": "After the review, no finding still stands: they were false positives or were fixed during the audit. That does not prove it is safe.",
        "band_done": "No action planned: accepted risk or already fixed",
        "status_h": "Status",
        "review_h": "Review",
        "appendix_intro": "The reviewer checked these findings in the code and concluded they are not a problem in this project. They do not count toward the grade, the plan or what to fix first. They are listed so you can see what was discarded and why.",
        "human_h": "Human review",
        "human_intro": "After the automated scan, {who} checked the findings by hand against the code and configuration and marked each one as confirmed, false positive, accepted risk or fixed. The reviewer's comment appears next to each finding.",
        "human_rules_h": "How the review changes the grade",
        "human_rules": ["Confirmed findings, accepted risks and findings not reviewed yet count toward the grade.",
                        "False positives do not count: they leave the grade, the plan and the fix-first list, and move to the appendix with the reason.",
                        "What was fixed and verified during the audit does not count toward the grade or the fix-first list, but stays in the report, marked as fixed.",
                        "Accepted risks still count toward the grade, because the risk is there, but they leave the fix-first list: the decision to live with them is recorded next to the finding."],
        "method_review": "A person checked the findings by hand and marked the outcome of each one: confirmed, false positive, accepted risk or fixed.",
        "method_grade_review": "Graded the result from A to F by the most serious findings that still stand after the review.",
        "limits_review": ["This is an automated scan of the code and configuration, checked by a person. It is not a penetration test: nobody tried to break into the running app.",
                          "Out of scope: the running app, business logic, server and cloud settings, and anything that is not in these files, except what the analyst summary says was checked separately.",
                          "A clean report means the common mistakes this tool knows were not found on this date. It does not mean the app is secure.",
                          "New vulnerabilities are published every day: a dependency that is fine today can have a flaw tomorrow. Run the check again often, for example on every pull request.",
                          "The human review cuts down false alarms but does not rule out mistakes: it is one person's judgment with what was available on this date. If something does not match what you know about the app, ask the reviewer."],
    },
}
# Revisão por IA ("review_kind": "ai" no arquivo de revisão): só as frases que mudam. A IA confirma ou descarta; risco
# aceito não existe nela, e o que foi corrigido vem da nova varredura.
H_AI = {
    "pt": {
        "review_meta": "Revisão por IA", "reviewer_none": "uma IA", "notes_h": "Resumo",
        "grade_rule": "Depois da revisão por IA, os alarmes falsos e o que foi corrigido não contam.",
        "review_line": "Revisão por IA: {counts}.",
        "appendix_intro": "A revisão por IA leu o código destes achados e concluiu que não são problema neste projeto, com o motivo junto de cada um. Eles não contam para a nota, para o plano nem para o que corrigir primeiro. Ficam aqui para você ver o que foi descartado e por quê.",
        "human_h": "Revisão por IA",
        "human_intro": "Depois da varredura automática, {who} leu o código de cada achado e marcou cada um como confirmado ou alarme falso. Na dúvida, o achado ficou confirmado. O comentário da revisão aparece junto de cada achado.",
        "human_rules": ["Contam para a nota os achados confirmados e os que ainda não foram revisados.",
                        "Alarmes falsos não contam: saem da nota, do plano e da lista do que corrigir primeiro e ficam no apêndice, com o motivo.",
                        "O que foi corrigido e sumiu de uma nova varredura não conta para a nota, mas continua no relatório, marcado como corrigido."],
        "method_review": "Uma IA leu o código de cada achado e marcou o resultado: confirmado ou alarme falso.",
        "privacy": "Para essas bases saíram só nomes e versões de pacotes. Para a revisão por IA, o trecho de cada achado, com os segredos mascarados, foi enviado ao modelo de IA.",
        "limits_review": ["Conferimos o código e a configuração dos arquivos listados acima, nesta data, com as regras do Stingward, e uma IA revisou cada achado. Não é um teste de invasão: ninguém tentou entrar no app rodando.",
                          "Ficam de fora o app em funcionamento, as regras de negócio, as configurações do servidor e da nuvem e tudo o que não está nestes arquivos.",
                          "Um relatório limpo quer dizer que nenhum dos problemas comuns que o Stingward conhece apareceu nestes arquivos nesta data.",
                          "Falhas novas são publicadas todo dia: uma dependência boa hoje pode ter falha amanhã. Verifique de novo depois de mudar o app.",
                          "A revisão por IA tira a maior parte dos alarmes falsos, mas pode errar. Na dúvida, o achado ficou confirmado. Se algo não bater com o que você sabe do app, confira no código antes de mexer."],
    },
    "en": {
        "review_meta": "AI review", "reviewer_none": "an AI", "notes_h": "Summary",
        "grade_rule": "After the AI review, false positives and what was fixed do not count.",
        "review_line": "AI review: {counts}.",
        "appendix_intro": "The AI review read the code of these findings and concluded they are not a problem in this project, with the reason next to each one. They do not count toward the grade, the plan or what to fix first. They are listed so you can see what was discarded and why.",
        "human_h": "AI review",
        "human_intro": "After the automated scan, {who} read the code of each finding and marked each one as confirmed or false positive. When in doubt, the finding stayed confirmed. The review's comment appears next to each finding.",
        "human_rules": ["Confirmed findings and findings not reviewed yet count toward the grade.",
                        "False positives do not count: they leave the grade, the plan and the fix-first list, and move to the appendix with the reason.",
                        "What was fixed and is gone from a new scan does not count toward the grade, but stays in the report, marked as fixed."],
        "method_review": "An AI read the code of each finding and marked the outcome: confirmed or false positive.",
        "privacy": "Only package names and versions went to these services. For the AI review, the code excerpt of each finding, with secrets masked, was sent to the AI model.",
        "limits_review": ["We checked the code and configuration of the files listed above, on this date, with Stingward's rules, and an AI reviewed every finding. This is not a penetration test: nobody tried to break into the running app.",
                          "Out of scope: the running app, business logic, server and cloud settings, and anything that is not in these files.",
                          "A clean report means none of the common problems Stingward knows showed up in these files on this date.",
                          "New vulnerabilities are published every day: a dependency that is fine today can have a flaw tomorrow. Check again after you change the app.",
                          "The AI review removes most false alarms, but it can be wrong. When in doubt, the finding stayed confirmed. If something does not match what you know about the app, check the code before you change it."],
    },
}


def texts_for(lang, audit):
    """As frases do relatório: as da revisão por IA no lugar das da revisão humana quando o arquivo diz "ai"."""
    if audit is not None and audit.review is not None and audit.review.kind == "ai":
        return dict(H[lang], **H_AI[lang])
    return H[lang]


MONTHS = {"pt": ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"],
          "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]}


def _n(t, key, n, **kw):
    one, many = t[key]
    return (one if n == 1 else many).format(n=n, **kw)


# --------------------------------------------------------------------------- texto que vem do projeto auditado

# Invisíveis que o Unicode não marca como formato: seletores de variação do suplemento (contrabando de texto),
# preenchedores do hangul, CGJ, seletores mongóis e o branco do braile.
_HIDDEN_EXTRA = {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F, 0x2800, 0x3164, 0xFFA0}


def _hidden(ch):
    o = ord(ch)
    if ch == "\t":
        return False
    return unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") or o in _HIDDEN_EXTRA or 0xE0100 <= o <= 0xE01EF


def _code(ch):
    o = ord(ch)
    return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}"


def _h(s):
    """Texto curto do projeto auditado (nome, título, resumo): invisível vira \\uXXXX à vista, depois escapa o HTML."""
    return _html.escape("".join(_code(c) if _hidden(c) else c for c in str(s)))


def _path(p):
    """Caminho escapado, com ponto de quebra depois de cada barra para não cortar nome de arquivo ao meio."""
    return _h(p).replace("/", "/<wbr>")


def _code_html(s, t):
    """Linha de código: sequência longa de invisíveis vira um aviso com a contagem; curta, os códigos à vista."""
    out = []
    for hidden, run in itertools.groupby(s, _hidden):
        run = "".join(run)
        if not hidden:
            out.append(_html.escape(run))
        elif len(run) > 3:
            out.append(f'<span class="inv">{_html.escape(_n(t, "hidden", len(run)))}</span>')
        else:
            out.append(f'<span class="inv">{_html.escape("".join(_code(c) for c in run))}</span>')
    return "".join(out)


_SECRET_FILE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\.[\w.-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials|id_[a-z0-9_]+|"
                          r"[^/]*\.(?:pem|key|p12|pfx|jks|keystore))$")
# Bloco de chave privada. O do PGP termina em "PRIVATE KEY BLOCK-----".
_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_RUN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
# Referência a variável de ambiente é nome, não valor: apiKey: process.env.X fica à vista. Só quando ela é o valor
# inteiro (vem antes de , ; ) } ] ou do fim da linha). Assim process.env.TOKEN = "..." e password: process.env.X ||
# "fallback" continuam mascarados por inteiro: o valor ao lado pode ser segredo.
_ENV_REF = re.compile(
    r"(?:process\.env(?:\.[A-Za-z_$][\w$]*|\[\s*([\"'`])[\w.-]+\1\s*\])|import\.meta\.env\.[A-Za-z_$][\w$]*"
    r"|(?:os\.environ|ENV)\[\s*([\"'])[\w.-]+\2\s*\]"
    r"|\b(?:os\.environ\.get|os\.getenv|getenv|Deno\.env\.get|System\.getenv|ENV\.fetch|env)\(\s*([\"'])[\w.-]+\3\s*\))"
    r"(?=\s*(?:[,;)}\]]|$))")


def _opaque(s):
    """Rede de segurança depois do mascaramento: valor longo e aleatório que nenhum padrão reconheceu também some.
    Identificador feito de palavras (snake_case, caminho) fica; mistura de letra e número com entropia alta, não."""
    def sub(m):
        for seg in m.group(0).split("/"):
            if redact._high_entropy(seg) and any(re.search(r"\d", p) and re.search(r"[A-Za-z]", p) for p in re.split(r"[_-]+", seg)):
                return "[REDACTED:long_value]"
        return m.group(0)
    return _RUN.sub(sub, s)


_QUOTED = re.compile(r"([\"'`])((?:\\.|(?!\1).)*)\1")
_BRACKET_KEY = re.compile(r"\[\s*([\"'`])(?P<key>[\w.-]{1,64})\1\s*\]\s*(?:=(?!=)|:)")  # process.env["TOKEN"] = "..."


def _fallback(s):
    """Rede de segurança: depois de um nome sensível (password, token, apiKey...), todo texto entre aspas até a próxima
    vírgula some. O mascaramento troca o primeiro valor, mas o reserva de password: process.env.X || "senha" ficaria."""
    def literal(q):
        v = q.group(2)
        return q.group(0) if not v or "[REDACTED:" in v else f"{q.group(1)}[REDACTED:secret_field]{q.group(1)}"
    out, i = [], 0
    keys = sorted(itertools.chain(redact._ASSIGN_KEY.finditer(s), _BRACKET_KEY.finditer(s)), key=lambda m: m.start())
    for m in keys:
        if m.start() < i or not redact.is_sensitive_key(m.group("key")):
            continue
        j, quote = m.end(), None
        while j < len(s):
            c = s[j]
            if quote:
                if c == "\\":
                    j += 1
                elif c == quote:
                    quote = None
            elif c in "\"'`":
                quote = c
            elif c in ",;":
                break
            j += 1
        out += [s[i:m.end()], _QUOTED.sub(literal, s[m.end():j])]
        i = j
    return "".join(out) + s[i:]


def _mask(raw):
    """Mascara antes de cortar, como os trechos do resto do relatório: segredo cortado ao meio não seria reconhecido."""
    s = mask_line(raw)
    return s if len(s) <= SHOW else s[:SHOW - 1] + "…"


def mask_line(raw):
    """O mascaramento dos trechos, sem cortar. Vale também para a impressão digital dos achados e para o que quem
    revisou escreveu (comentários e parecer): um segredo colado ali sai mascarado como no trecho de código."""
    raw = str(raw).replace("\x00", "\ufffd")  # o \x00 é reservado às marcas internas do mascaramento
    refs = []

    def keep(m):
        ref = m.group(0)
        if secrets.mask(ref) != ref or _opaque(ref) != ref:  # os.getenv("ghp_...") por engano: o "nome" é a chave
            return ref
        refs.append(ref)
        return f"\x00V{len(refs) - 1}\x00"
    raw = _ENV_REF.sub(keep, raw)
    s = _opaque(_fallback(secrets.mask(raw)))
    if refs:  # o nome volta depois de todas as redes de segurança, que não o veem
        s = re.sub(r"\x00V(\d+)\x00", lambda m: refs[int(m.group(1))] if int(m.group(1)) < len(refs) else "", s)
    return s


def evidence(ctx, rel, line):
    """[(número, texto mascarado ou None se a linha é longa demais, tamanho)] da linha e uma de cada lado.

    Arquivo de segredos (.env, .npmrc, chave) mostra só a linha do achado. Linha dentro de um bloco de chave
    privada nunca aparece, mesmo quando o bloco começa fora da janela.

    O texto vem de ctx.read, o mesmo que as verificações leram: a mesma decodificação e as mesmas linhas (só "\\n"
    quebra linha), e não o arquivo de novo do disco, que pode ter mudado depois da varredura."""
    if not line:
        return None
    lo, hi = (line, line) if _SECRET_FILE.search(rel) else (max(1, line - 1), line + 1)
    lines = ctx.read(rel).split("\n")
    if lines[-1] == "":  # a quebra no fim do arquivo não abre outra linha; arquivo vazio ou ilegível não tem nenhuma
        lines.pop()
    rows = []
    in_key = False
    for n, raw in enumerate(lines, 1):
        raw = raw.rstrip("\r")
        in_key = in_key or bool(_KEY_BEGIN.search(raw))
        inside = in_key
        if in_key and _KEY_END.search(raw):
            in_key = False
        if n >= lo:
            if inside:
                rows.append((n, "[REDACTED:private_key]", 0))
            elif len(raw) > MAX_LINE:
                rows.append((n, None, len(raw)))
            else:
                rows.append((n, _mask(raw), len(raw)))
        if n >= hi:
            break
    return rows if any(n == line for n, _, _ in rows) else None


# --------------------------------------------------------------------------- pedaços

SHIELD = ('<svg class="logo" viewBox="0 0 64 64" aria-hidden="true" focusable="false"><clipPath id="sw-clip"><path d="M32 1.5 L52 13 '
          'V30 C52 40.5 45.8 47.2 37 51.2 C35 52.4 33.9 54.8 33.3 57.8 L32 63.5 L30.7 57.8 C30.1 54.8 29 52.4 27 51.2 C18.2 47.2 12 '
          '40.5 12 30 V13 Z"/></clipPath><path d="M32 1.5 L52 13 V30 C52 40.5 45.8 47.2 37 51.2 C35 52.4 33.9 54.8 33.3 57.8 L32 63.5 '
          'L30.7 57.8 C30.1 54.8 29 52.4 27 51.2 C18.2 47.2 12 40.5 12 30 V13 Z" fill="#F5B83D"/><g clip-path="url(#sw-clip)" '
          'fill="#1B1F27"><path d="M0 19.5 Q32 25 64 19.5 V26.5 Q32 32 0 26.5 Z"/><path d="M0 33 Q32 38.5 64 33 V40 Q32 45.5 0 40 Z"/>'
          '</g></svg>')


def _badge(sev, t):
    return f'<span class="sev sev-{sev}">{_html.escape(t["sev"][sev])}</span>'


def _std_link(sid):
    m = re.fullmatch(r"CWE-(\d+)", sid)
    if m:
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
    if re.fullmatch(r"LLM\d\d:\d{4}", sid):
        return "https://genai.owasp.org/llm-top-10/"
    if re.fullmatch(r"AST\d\d", sid):
        return "https://owasp.org/www-project-agentic-skills-top-10/"
    if re.fullmatch(r"ASI\d\d", sid):
        return "https://genai.owasp.org/"
    return None


def _link(url, label=None):
    """Só https vira link; o resto fica como texto."""
    text = _h(label if label is not None else url)
    if re.fullmatch(r"https://[^\s\"'<>\\]+", str(url)):
        return f'<a href="{_html.escape(url, quote=True)}" rel="noopener noreferrer">{text}</a>'
    return text


def _date(today, lang):
    m = MONTHS[lang][today.month - 1]
    return f"{today.day} de {m} de {today.year}" if lang == "pt" else f"{m} {today.day}, {today.year}"


def _name(ctx, target, t):
    if ctx.mode == "agents":
        return t["agents_name"]
    label = str(target or "")
    if re.match(r"^(https?://|git@)", label) or (label and not os.path.exists(label) and "/" in label):
        # URL ou dono/repositório (skill baixada): o nome é o último pedaço, sem .git
        return re.sub(r"\.git$", "", label.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]) or label
    return os.path.basename(os.path.abspath(ctx.root)) or ctx.root


def _level(findings):
    worst = max((SEV_RANK[f.severity] for f in findings), default=0)
    return "bad" if worst >= SEV_RANK["high"] else "mid" if worst == SEV_RANK["medium"] else "ok"


def _verdict(findings, mode, lang, t, ctx=None):
    level = _level(findings)
    if mode == "skill":  # o mesmo veredito do texto, sem o emoji; com arquivo sem ler, "incompleta" (report.verdict)
        if level != "bad" and report.incomplete(ctx):
            return "incomplete", report.incomplete_verdict(ctx, lang).split(" ", 1)[1]
        return level, report.T[lang]["verdict_" + level].split(" ", 1)[1]
    return level, t["verdict"]["agents" if mode == "agents" else "project"][level]


def _checks(checks, t):
    return " · ".join(t["check_name"][c] for c in checks)


def _where_short(entry, t, limit=3):
    places = entry.places
    shown = "".join(f"<code>{_path(p)}</code>" for p in places[:limit])
    if len(places) > limit:
        shown += f'<span class="more">{_html.escape(_n(t, "more_places", len(places) - limit))}</span>'
    return shown


# --------------------------------------------------------------------------- seções

def _md_inline(nodes):
    """Nós do Markdown pequeno (review.inline) em HTML, cada pedaço escapado por _h."""
    out = []
    for style, text in nodes:
        piece = _h(text)
        if "c" in style:
            piece = f"<code>{piece}</code>"
        if "b" in style:
            piece = f"<strong>{piece}</strong>"
        out.append(piece)
    return "".join(out)


def _md_html(blocks):
    out = []
    for kind, body in blocks:
        if kind == "p":
            out.append(f"<p>{_md_inline(body)}</p>")
        else:
            out.append("<ul>" + "".join(f"<li>{_md_inline(item)}</li>" for item in body) + "</ul>")
    return "".join(out)


def _status_chip(status, t):
    cls = status or "todo"
    return f'<span class="rv rv-{cls}">{_html.escape(t["status"][status])}</span>'


def _cover(ctx, valid, lang, t, name, target, today, commit, checks, toc_items, audit, findings):
    empty = report.nothing_read(ctx, findings)  # nada lido: sem nota e sem veredito verde
    g = "–" if empty else report.grade(valid)
    level, verdict = ("none", report.nothing_read_text(ctx, lang)) if empty else _verdict(valid, ctx.mode, lang, t, ctx)
    label = report.T[lang]["no_grade"] if empty else f'{t["grade"]} {g}'
    rows = []
    if audit is not None and audit.client:
        rows.append((t["client"], f"<strong>{_h(audit.client)}</strong>"))
    if target and ctx.mode != "agents":
        rows.append((t["target"], f"<code>{_path(target)}</code>"))
    rows.append((t["date"], _html.escape(_date(today, lang))))
    rows.append((t["type"], _html.escape(t["type_of"].get(ctx.mode, ctx.mode))))
    rows.append((t["found"], _html.escape(report.counts_line(valid, lang) or t["none_found"])))
    if audit is not None and audit.review is not None:
        who = _h(audit.reviewer) + " · " if audit.reviewer else ""
        rows.append((t["review_meta"], who + _html.escape(report.review_counts(findings, audit.review, lang) or "0")))
    if commit:
        rows.append((t["commit"], f"<code>{_h(commit)}</code>"))
    rows.append((t["tool"], f"Stingward {_html.escape(__version__)}"))
    meta = "".join(f"<div><dt>{_html.escape(k)}</dt><dd>{v}</dd></div>" for k, v in rows)
    warns = []
    if checks != CHECK_ORDER:
        warns.append(t["warn_only"].format(checks=_checks(checks, t)))
    if "deps" in checks and ctx.offline:
        warns.append(t["warn_offline"])
    elif "deps" in checks and report.osv_partial(ctx):
        warns.append(t["warn_osv_partial"].format(detail=report._clean(ctx.sources["osv_error"])))
    elif "deps" in checks and ctx.sources.get("osv_error"):
        warns.append(t["warn_osv"])
    elif "deps" in checks and ctx.sources.get("kev_error"):
        warns.append(t["warn_kev"])
    if ctx.too_big:  # código que ninguém leu: uma skill pode esconder o que faz num arquivo grande
        warns.append(_n(t, "warn_big", len(ctx.too_big), mb=report.size_cap(ctx.mode) // 1_000_000, scope=t["s_scope"]))
    if ctx.truncated:
        warns.append(t["warn_many"].format(n=report.thousands(_max_files(), lang)))
    warn = "".join(f'<p class="warn">{_html.escape(w)}</p>' for w in warns)
    toc = "".join(f'<li><a href="#{a}"><span class="toc-n">{n}</span>{_html.escape(label)}</a></li>' for a, n, label in toc_items)
    return f"""<section class="cover" id="cover">
<header class="brand">{SHIELD}<span class="brand-name">Stingward</span><span class="brand-sub">{_html.escape(t["brand_sub"])}</span></header>
<div class="cover-gap"></div>
<p class="eyebrow">{_html.escape(t["kind"].get(ctx.mode, t["kind"]["project"]))}</p>
<h1 class="title">{_h(name)}</h1>
<div class="verdict">
<div class="grade grade-{"none" if empty else g}" role="img" aria-label="{_html.escape(label)}"><span class="grade-k">{_html.escape(t["grade"])}</span><span class="grade-v">{g}</span></div>
<p class="verdict-text verdict-{level}">{_h(verdict)}</p>
</div>
{warn}
<dl class="meta">{meta}</dl>
<nav class="toc" aria-label="{_html.escape(t["toc"])}"><p class="toc-h">{_html.escape(t["toc"])}</p><ol>{toc}</ol></nav>
<p class="cover-foot">{_html.escape(t["footer"].format(v=__version__))} {_link(report.REPO_URL, report.REPO_URL.split("//")[1])}</p>
</section>"""


def _notes_html(audit, t, today, lang):
    if audit is None or not audit.notes:
        return ""
    sign = (f'<p class="sign">{_h(audit.reviewer)} · {_html.escape(_date(today, lang))}</p>' if audit.reviewer else "")
    return f'<div class="analyst"><h3 class="analyst-h">{_html.escape(t["notes_h"])}</h3><div class="md">{_md_html(audit.notes)}</div>{sign}</div>'


def _summary(valid, shown, numbers, lang, t, audit, findings, today, nothing=""):
    """nothing: o aviso de que nenhum arquivo foi lido, quando for o caso; então não há nota."""
    g = "–" if nothing else report.grade(valid)
    reviewed = audit is not None and audit.review is not None
    scale = "".join(f'<li class="grade-{k}{" on" if k == g else ""}"><span class="scale-g">{k}</span>'
                    f'<span class="scale-t">{_html.escape(v)}</span></li>' for k, v in t["scale"].items())
    c = Counter(f.severity for f in valid)
    shown_sev = [s for s in reversed(SEVERITIES) if s != "info" or c[s]]
    tiles = "".join(f'<li class="tile tile-{s}{" zero" if not c[s] else ""}"><span class="tile-n">{c[s]}</span>'
                    f'<span class="tile-k">{_html.escape(t["sev"][s])}</span><span class="tile-h">{_html.escape(t["sev_help"][s])}</span></li>'
                    for s in shown_sev)
    standing = [e for e in shown if e.status not in report.NOT_COUNTED]
    note = (f'<p class="note">{_html.escape(t["grouped"].format(n=len(valid), problems=_n(t, "problems", len(standing))))}</p>'
            if len(standing) != len(valid) else "")
    if reviewed:
        note += f'<p class="note review-line">{_html.escape(t["review_line"].format(counts=report.review_counts(findings, audit.review, lang) or "0"))}</p>'
    intro = t["grade_intro"] + (" " + t["grade_rule"] if reviewed else "")
    top = report.urgent(shown)
    if top:
        items = "".join(
            f'<li class="first-item sev-line-{e.severity}"><div class="first-head">{_badge(e.severity, t)}'
            f'<a class="first-title" href="#f{numbers[id(e)]}">{_h(e.title)}</a></div>'
            f'<p class="first-impact">{_h(report.impact(e, lang))}</p>'
            f'<p class="first-where"><span>{_html.escape(t["first_where"])}</span>{_where_short(e, t, 2)}</p></li>' for e in top)
        first = f'<h3>{_html.escape(t["first"])}</h3><ol class="first">{items}</ol>'
    elif valid:
        accepted = any(e.status == "accepted_risk" and SEV_RANK[e.severity] >= SEV_RANK["high"] for e in shown)
        first = f'<h3>{_html.escape(t["first"])}</h3><p class="calm">{_html.escape(t["first_none_accepted" if accepted else "first_none"])}</p>'
    elif nothing:
        first = f'<p class="warn">{_html.escape(nothing)}</p>'
    else:
        first = f'<p class="calm">{_html.escape(t["clean_reviewed" if reviewed and findings else "clean"])}</p>'
    return f"""<section id="summary">
<h2><span class="sec-n">1</span>{_html.escape(t["s_summary"])}</h2>
{_notes_html(audit, t, today, lang)}
<div class="grade-box">
<div class="grade grade-{"none" if nothing else g}"><span class="grade-k">{_html.escape(t["grade"])}</span><span class="grade-v">{g}</span></div>
<div><h3 class="grade-h">{_html.escape(t["grade_means"])}</h3><p>{_html.escape(intro)}</p></div>
</div>
<ol class="scale">{scale}</ol>
<ul class="tiles">{tiles}</ul>
{note}
{first}
</section>"""


def _plan(shown, numbers, t, gone=()):
    """gone: o que foi corrigido durante a auditoria e sumiu da varredura (review.Gone), no grupo sem ação prevista."""
    if not shown and not gone:
        body = f'<p class="calm">{_html.escape(t["plan_empty"])}</p>'
    else:
        rows = []
        todo = [e for e in shown if e.status in report.TODO]
        done = [e for e in shown if e.status not in report.TODO]
        for sev, group in itertools.groupby(todo, key=lambda e: e.severity):
            rows.append(f'<tr class="band band-{sev}"><th colspan="4" scope="colgroup">{_html.escape(t["band"][sev])}</th></tr>')
            for e in group:
                n = numbers[id(e)]
                eff = report.effort(e.rule, e.params)
                rows.append(f'<tr class="sev-line-{e.severity}"><td class="num">{n}</td><td class="problem"><a href="#f{n}">{_h(e.title)}</a></td>'
                            f'<td class="where">{_where_short(e, t)}</td><td class="effort effort-{eff}">{_html.escape(t["effort"][eff])}</td></tr>')
        if done or gone:
            rows.append(f'<tr class="band band-done"><th colspan="4" scope="colgroup">{_html.escape(t["band_done"])}</th></tr>')
            for e in done:
                n = numbers[id(e)]
                rows.append(f'<tr class="sev-line-{e.severity}"><td class="num">{n}</td><td class="problem"><a href="#f{n}">{_h(e.title)}</a> '
                            f'{_badge(e.severity, t)}</td><td class="where">{_where_short(e, t)}</td>'
                            f'<td class="effort">{_status_chip(e.status, t)}</td></tr>')
            for e in gone:  # sem ficha em "achados em detalhe": não estão mais no código
                rows.append(f'<tr class="sev-line-{e.severity}"><td class="num"></td><td class="problem">{_h(e.title)} '
                            f'{_badge(e.severity, t)}</td><td class="where">{_where_short(e, t)}</td>'
                            f'<td class="effort">{_status_chip(e.status, t)}</td></tr>')
        body = (f'<p class="legend">{_html.escape(t["effort_legend"])}</p><table class="plan"><thead><tr><th class="num" scope="col">{t["col_n"]}</th>'
                f'<th scope="col">{_html.escape(t["col_problem"])}</th><th scope="col">{_html.escape(t["col_where"])}</th>'
                f'<th scope="col">{_html.escape(t["effort_h"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')
    return f"""<section id="plan">
<h2><span class="sec-n">2</span>{_html.escape(t["s_plan"])}</h2>
<p class="lead">{_html.escape(t["plan_intro"])}</p>
{body}
</section>"""


def _evidence_html(ctx, entry, t):
    """Um bloco por trecho. Cada um vira uma linha da ficha, para a impressão não separar o rótulo do primeiro trecho."""
    blocks = []
    with_line = [f for f in entry.findings if f.line]
    for f in with_line[:MAX_EVIDENCE]:
        rows = evidence(ctx, f.file, f.line)
        cap = f'<figcaption><code>{_path(f.file)}</code> <span>{_html.escape(t["line"].format(n=f.line))}</span></figcaption>'
        if rows is None:
            blocks.append(f'<figure class="ev">{cap}<p class="ev-missing">{_html.escape(t["ev_missing"])}</p></figure>')
            continue
        lines = []
        for n, txt, size in rows:
            code = (f'<span class="inv">{_html.escape(t["ev_long"].format(n=size))}</span>' if txt is None else _code_html(txt, t))
            lines.append(f'<div class="ln{" hit" if n == f.line else ""}"><span class="ln-n">{n}</span><code>{code}</code></div>')
        blocks.append(f'<figure class="ev">{cap}<div class="code">{"".join(lines)}</div></figure>')
    skipped = len(with_line) - min(len(with_line), MAX_EVIDENCE)
    if skipped:
        blocks.append(f'<p class="ev-more">{_html.escape(_n(t, "ev_more", skipped))}</p>')
    return blocks


def _vulns_html(entry, t):
    vulns = entry.params.get("vulns") if entry.rule in ("DEP001", "DEP004") else None
    if not isinstance(vulns, list) or not vulns:
        return ""
    rows = []
    for v in vulns[:MAX_VULNS]:
        if not isinstance(v, dict):
            continue
        vid, osv = str(v.get("id") or ""), str(v.get("osv") or "")
        ident = _link(f"https://osv.dev/vulnerability/{osv}", vid) if re.fullmatch(r"[A-Za-z0-9._:-]+", osv) else _h(vid)
        tags = ""
        if v.get("kev"):
            tags += '<span class="tag tag-kev">KEV</span>'
        if isinstance(v.get("epss"), (int, float)) and v["epss"] >= 0.01:
            tags += f'<span class="tag">EPSS {v["epss"] * 100:.0f}%</span>'
        sev = v.get("severity") if v.get("severity") in SEV_RANK else "medium"
        rows.append(f'<tr><td class="vid">{ident}</td><td class="vsev">{_badge(sev, t)}</td><td class="vsum">{_h(v.get("summary") or "")}{tags}</td>'
                    f'<td class="vfix">{_h(v.get("fixed") or t["v_none"])}</td></tr>')
    more = (f'<p class="ev-more">{_html.escape(_n(t, "v_more", len(vulns) - MAX_VULNS))}</p>' if len(vulns) > MAX_VULNS else "")
    head = t["vulns_floor"] if entry.rule == "DEP004" else t["vulns"]
    return (f'<h5>{_html.escape(head)}</h5><table class="vulns"><thead><tr><th scope="col">{t["v_id"]}</th>'
            f'<th scope="col">{_html.escape(t["v_sev"])}</th><th scope="col">{_html.escape(t["v_summary"])}</th>'
            f'<th scope="col">{_html.escape(t["v_fixed"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>{more}')


def _row(key, value, cls=""):
    return f'<div class="f-row{cls}"><div class="f-k">{key}</div><div class="f-v">{value}</div></div>'


LONG_WHERE = 12  # acima disso a lista de lugares pode quebrar de página


def _finding(ctx, entry, n, t, audit=None):
    reviewed = audit is not None and audit.review is not None
    places = entry.places
    where = "".join(f"<li><code>{_path(p)}</code>{'' if f.line else ' <span>(' + _html.escape(t['whole_file']) + ')</span>'}</li>"
                    for p, f in zip(places[:MAX_PLACES], entry.findings))
    if len(places) > MAX_PLACES:
        where += f'<li class="more">{_html.escape(_n(t, "more_places", len(places) - MAX_PLACES))}</li>'
    long = len(places) > LONG_WHERE
    where = _row(_html.escape(t["where"]), f'<ul class="places">{where}</ul>', " long" if long else "")
    rows = []
    comment = audit.comment(entry.comment) if reviewed else []
    if comment:
        rows.append(_row(_html.escape(t["review_h"]), f'<div class="md review">{_md_html(comment)}</div>'))
    rows += [_row(_html.escape(t["evidence"]) if i == 0 else "", block, " cont" if i else "")
             for i, block in enumerate(_evidence_html(ctx, entry, t))]
    rows += [_row(_html.escape(t[k]), f"<p>{_h(v)}</p>") for k, v in (("why", entry.why), ("fix", entry.fix)) if v.strip()]
    vulns = _vulns_html(entry, t)
    if vulns:
        rows.append(_row("", vulns, " long cont"))
    std = " · ".join(_link(_std_link(s), s) if _std_link(s) else _h(s) for s in standards(entry.rule, entry.params))
    if std:
        rows.append(_row(_html.escape(t["standards"]), f'<p class="std">{std}</p>'))
    refs = "".join(f"<li>{_link(r)}</li>" for r in entry.refs)
    if refs:
        rows.append(_row(_html.escape(t["refs"]), f'<ul class="refs">{refs}</ul>'))
    chip = _status_chip(entry.status, t) if reviewed else ""
    head = (f'<header class="f-head"><span class="f-n">#{n}</span>{_badge(entry.severity, t)}{chip}'
            f'<span class="f-rule">{_html.escape(t["rule"])} {_html.escape(entry.rule)}</span></header>'
            f'<h4 class="f-title">{_h(entry.title)}</h4>')
    # Na impressão, cabeçalho, título e "onde" ficam na mesma página, a não ser que a lista de lugares seja longa.
    top = f'<div class="f-top">{head}</div>{where}' if long else f'<div class="f-top">{head}{where}</div>'
    status = f" rv-line-{entry.status or 'todo'}" if reviewed else ""
    return f"""<article class="finding sev-line-{entry.severity}{status}" id="f{n}">
{top}
{"".join(rows)}
</article>"""


def _findings(ctx, entries, numbers, t, audit=None):
    if not entries:
        return f"""<section id="findings">
<h2><span class="sec-n">3</span>{_html.escape(t["s_findings"])}</h2>
<p class="calm">{_html.escape(t["no_findings"])}</p>
</section>"""
    # Primeiro a área do achado mais grave que ainda vale (o corrigido durante a auditoria não puxa a área), depois a
    # que tem mais desses itens; no empate, a ordem fixa de GROUPS.
    present = {e.group for e in entries}
    fixed = [g for g in GROUPS if g in present] + sorted(present - set(GROUPS))

    def weight(g):
        standing = [e for e in entries if e.group == g and e.status not in report.NOT_COUNTED]
        return (-max((SEV_RANK[e.severity] for e in standing), default=-1), -len(standing), fixed.index(g))
    order = sorted(fixed, key=weight)
    parts = []
    for g in order:
        mine = [e for e in entries if e.group == g]
        label = t["group"].get(g, g.capitalize())
        parts.append(f'<h3 class="area">{_html.escape(label)} <span class="area-n">{len(mine)}</span></h3>')
        parts += [_finding(ctx, e, numbers[id(e)], t, audit) for e in mine]
    return f"""<section id="findings">
<h2><span class="sec-n">3</span>{_html.escape(t["s_findings"])}</h2>
<p class="lead">{_html.escape(t["ev_note"])}</p>
{"".join(parts)}
</section>"""


def _appendix(ctx, discarded, numbers, t, audit):
    articles = "".join(_finding(ctx, e, numbers[id(e)], t, audit) for e in discarded)
    return f"""<section id="appendix">
<h2><span class="sec-n">A</span>{_html.escape(t["s_appendix"])}</h2>
<p class="lead">{_html.escape(t["appendix_intro"])}</p>
{articles}
</section>"""


def _source_rows(ctx, checks, t):
    s = ctx.sources
    rows = []
    for key in ("osv", "kev", "epss", "nvd"):
        if "deps" not in checks:
            st = t["st_off"]
        elif ctx.offline:
            st = t["st_offline"]
        elif key == "osv":
            st = (t["st_partial"].format(detail=report._clean(s["osv_error"])) if report.osv_partial(ctx) else
                  t["st_ok"] if s.get("osv") else t["st_fail"] if s.get("osv_error") else t["st_nopkg"])
        elif not s.get("osv"):
            st = t["st_na"]
        elif key == "kev":
            kv = s.get("kev")
            st = (t["st_kev"].format(v=kv) if isinstance(kv, str) and kv else t["st_ok"] if kv else
                  t["st_fail"] if s.get("kev_error") else t["st_nocve"])
        elif key == "epss":
            st = t["st_ok"] if s.get("epss") else t["st_empty"] if "epss" in s else t["st_nocve"]
        else:
            st = t["st_ok"] if s.get("nvd") else t["st_noscore"]
        name, role = t["src"][key]
        rows.append(f"<tr><th scope=\"row\">{_html.escape(name)}</th><td>{_html.escape(role)}</td><td>{_h(st)}</td></tr>")
    return "".join(rows)


MAX_UNREAD = 20  # arquivos que o escopo lista pelo nome; o resto vira "e mais N"


def _max_files():
    from . import scan
    return scan.MAX_FILES


def _size(n, lang):
    """Tamanho legível, com a vírgula decimal em português: 12,4 MB."""
    for unit, base in (("MB", 1_000_000), ("KB", 1_000)):
        if n >= base:
            text = f"{n / base:.1f} {unit}"
            return text.replace(".", ",") if lang == "pt" else text
    return f"{n} B"


def _unread(ctx, lang, t):
    """O que a varredura não leu: os arquivos acima do limite de tamanho, com o tamanho de cada um (se ainda estão no
    disco), e a nota do limite de arquivos. Os nomes vêm do projeto auditado: escapados como qualquer caminho."""
    out = ""
    if ctx.too_big:
        rows = []
        for rel in ctx.too_big[:MAX_UNREAD]:
            try:
                size = f' <span class="size">{_html.escape(_size(os.stat(os.path.join(ctx.root, rel)).st_size, lang))}</span>'
            except (OSError, ValueError):
                size = ""
            rows.append(f"<li><code>{_path(rel)}</code>{size}</li>")
        if len(ctx.too_big) > MAX_UNREAD:
            rows.append(f'<li class="more">{_html.escape(_n(t, "unread_more", len(ctx.too_big) - MAX_UNREAD))}</li>')
        head = _n(t, "unread_big", len(ctx.too_big), mb=report.size_cap(ctx.mode) // 1_000_000)
        out += f'<p class="warn">{_html.escape(head)}</p><ul class="facts unread">{"".join(rows)}</ul>'
    if ctx.truncated:
        out += f'<p class="warn">{_html.escape(t["warn_many"].format(n=report.thousands(_max_files(), lang)))}</p>'
    return out


def _scope(ctx, lang, t, checks, audit=None, findings=()):
    from . import scan  # aqui e não no topo: scan carrega as verificações, que o relatório só usa para ler o .stingwardignore

    reviewed = audit is not None and audit.review is not None
    what = [_n(t, "files", len(ctx.files)),
            _n(t, "pkgs", ctx.sources.get("packages", 0)) if "deps" in checks else t["pkgs_skipped"],
            f'{t["checks"]}: {_checks(checks, t)}', t["rules"].format(n=len(RULES))]
    items = "".join(f"<li>{_html.escape(w)}</li>" for w in what)
    ignored = len(scan.load_ignore(ctx.root)) if ctx.mode == "project" else 0
    ign = f'<p class="warn">{_html.escape(_n(t, "ignore", ignored))}</p>' if ignored else ""
    steps = list(t["method"])
    if reviewed:
        steps[-1:] = [t["method_review"], t["method_grade_review"]]
    method = "".join(f"<li>{_html.escape(m.format(n=len(RULES)))}</li>" for m in steps)
    limits = "".join(f"<li>{_html.escape(m)}</li>" for m in t["limits_review" if reviewed else "limits"])
    human = ""
    if reviewed:
        who = audit.reviewer or t["reviewer_none"]
        counts = "".join(f"<li>{_html.escape(c)}</li>" for c in report.review_parts(findings, audit.review, lang))
        rules = "".join(f"<li>{_html.escape(r)}</li>" for r in t["human_rules"])
        human = (f'<h3>{_html.escape(t["human_h"])}</h3><p>{_h(t["human_intro"].format(who=who))}</p>'
                 f'<ul class="facts review-counts">{counts}</ul>'
                 f'<h3>{_html.escape(t["human_rules_h"])}</h3><ul class="limits">{rules}</ul>')
    return f"""<section id="scope">
<h2><span class="sec-n">4</span>{_html.escape(t["s_scope"])}</h2>
<h3>{_html.escape(t["scope_what"])}</h3>
<ul class="facts">{items}</ul>
{_unread(ctx, lang, t)}
{ign}
{human}
<h3>{_html.escape(t["sources_h"])}</h3>
<table class="sources"><thead><tr><th scope="col">{_html.escape(t["src_col"])}</th><th scope="col">{_html.escape(t["src_role"])}</th>
<th scope="col">{_html.escape(t["src_status"])}</th></tr></thead><tbody>{_source_rows(ctx, checks, t)}</tbody></table>
<p class="small">{_html.escape(t["privacy"])}</p>
<h3>{_html.escape(t["method_h"])}</h3>
<ol class="steps">{method}</ol>
<h3>{_html.escape(t["limits_h"])}</h3>
<ul class="limits">{limits}</ul>
</section>"""


# --------------------------------------------------------------------------- documento

def render(ctx, findings, lang="pt", target=None, checks=None, today=None, audit=None):
    """O relatório inteiro. checks: verificações que rodaram (padrão: todas). today: data do relatório (padrão: hoje).
    audit: a revisão humana (review.Audit), com cliente, parecer e o status e comentário de cada achado."""
    lang = lang if lang in H else "en"
    t = texts_for(lang, audit)
    checks = [c for c in CHECK_ORDER if checks is None or c in checks]
    today = today or datetime.date.today()
    rv = audit.review if audit is not None else None
    valid = report.counted(findings, rv)
    shown, discarded = report.split(report.merge(findings, lang, rv))
    numbers = {id(e): i for i, e in enumerate(shown + discarded, 1)}
    target = report.shown_target(target) if target else target  # sem o token de uma URL https://token@...
    name = _name(ctx, target, t)
    commit = gitsafe.head(ctx.root) if ctx.mode != "agents" else None
    toc = [("summary", 1, t["s_summary"]), ("plan", 2, t["s_plan"]), ("findings", 3, t["s_findings"]), ("scope", 4, t["s_scope"])]
    if discarded:
        toc.append(("appendix", "A", t["s_appendix"]))
    parts = [
        _cover(ctx, valid, lang, t, name, target, today, commit, checks, toc, audit, findings),
        _summary(valid, shown, numbers, lang, t, audit, findings, today,
                 report.nothing_read_text(ctx, lang) if report.nothing_read(ctx, findings) else ""),
        _plan(shown, numbers, t, audit.gone if audit is not None else ()),
        _findings(ctx, shown, numbers, t, audit),
        _scope(ctx, lang, t, checks, audit, findings),
    ]
    if discarded:
        parts.append(_appendix(ctx, discarded, numbers, t, audit))
    body = "\n".join(parts)
    return f"""<!doctype html>
<html lang="{"pt-BR" if lang == "pt" else "en"}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="generator" content="Stingward {_html.escape(__version__)}">
<title>{_html.escape(t["doc"])} · {_h(name)}</title>
<style>{CSS}</style>
</head>
<body>
<main class="doc">
{body}
<footer class="end"><p>{_html.escape(t["footer"].format(v=__version__))} {_link(report.REPO_URL, report.REPO_URL.split("//")[1])}</p></footer>
</main>
</body>
</html>
"""


CSS = """
:root{--ink:#1b1f27;--muted:#525a68;--faint:#8a919e;--line:#dde0e5;--soft:#f5f6f8;--paper:#fff;--page:#e8eaee;--honey:#f5b83d;
--crit:#b42318;--crit-bg:#fef1f0;--high:#b54708;--high-bg:#fff3e6;--medium:#806000;--medium-bg:#fdf7df;--low:#175cd3;--low-bg:#edf3ff;
--info:#475467;--info-bg:#f2f4f7;--gA:#1a7f37;--gB:#4d7c0f;--gC:#806000;--gD:#b54708;--gF:#b42318;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;
--mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Menlo,Consolas,"Liberation Mono",monospace;color-scheme:light}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 var(--sans);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.doc{max-width:880px;margin:32px auto;background:var(--paper);box-shadow:0 1px 2px rgba(16,24,40,.06),0 12px 32px rgba(16,24,40,.08)}
section{padding:56px 64px}
section+section{border-top:1px solid var(--line)}
h1,h2,h3,h4,h5,p,ol,ul,dl,dd,figure{margin:0}
h2{display:flex;align-items:baseline;gap:14px;font-size:26px;line-height:1.2;letter-spacing:-.01em;margin-bottom:22px}
h3{font-size:17px;margin:30px 0 12px}
h5{font-size:13px;margin:16px 0 8px}
p{max-width:72ch}
a{color:inherit;text-decoration:underline;text-decoration-color:var(--faint);text-underline-offset:2px}
code{font-family:var(--mono);font-size:.88em;unicode-bidi:isolate;overflow-wrap:anywhere}
.sec-n{display:inline-grid;place-items:center;min-width:34px;height:34px;padding:0 6px;border-radius:8px;background:var(--ink);color:var(--honey);font-size:17px}
.lead{color:var(--muted);margin-bottom:18px}
.small{font-size:13px;color:var(--muted);margin-top:10px}
.calm{padding:14px 16px;border:1px solid var(--line);border-radius:8px;background:var(--soft)}
.note{font-size:13.5px;color:var(--muted);margin-top:12px}
.warn{margin-top:16px;padding:10px 14px;border:1px solid #e9b44c;border-left:5px solid #c98a00;border-radius:6px;background:#fff8e6;font-size:14px}
.more{font-size:12.5px;color:var(--muted)}
.unread{margin-top:10px}.unread .size{color:var(--muted);font-size:13px;white-space:nowrap}
/* capa */
.cover{display:flex;flex-direction:column;min-height:1040px;padding-top:44px}
.brand{display:flex;align-items:center;gap:10px;padding-bottom:18px;border-bottom:4px solid var(--honey)}
.logo{width:34px;height:34px;flex:none}
.brand-name{font-weight:800;font-size:19px;letter-spacing:-.01em}
.brand-sub{margin-left:auto;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.cover-gap{flex:0 1 96px;min-height:24px}
.eyebrow{font-size:13px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.title{margin-top:10px;font-size:46px;line-height:1.08;letter-spacing:-.025em;overflow-wrap:anywhere}
.verdict{display:flex;align-items:center;gap:26px;margin-top:40px;padding:22px 24px;border:1px solid var(--line);border-radius:12px;background:var(--soft)}
.verdict-text{font-size:19px;line-height:1.4;font-weight:600}
.verdict-incomplete{color:var(--high)}
.grade{flex:none;display:flex;flex-direction:column;align-items:center;justify-content:center;width:112px;height:112px;border:4px solid var(--g);
border-radius:16px;background:#fff;color:var(--g)}
.grade-k{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}
.grade-v{font-size:64px;font-weight:800;line-height:.95}
.grade-A{--g:var(--gA)}.grade-B{--g:var(--gB)}.grade-C{--g:var(--gC)}.grade-D{--g:var(--gD)}.grade-F{--g:var(--gF)}.grade-none{--g:var(--faint)}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 32px;margin-top:36px}
.meta div{padding:10px 0;border-bottom:1px solid var(--line)}
.meta dt{font-size:11.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.meta dd{margin-top:2px;overflow-wrap:anywhere}
.toc{margin-top:auto;padding-top:40px}
.toc-h{font-size:11.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.toc ol{list-style:none;padding:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 32px}
.toc a{display:flex;gap:10px;padding:6px 0;text-decoration:none;font-weight:600}
.toc-n{color:var(--faint);font-variant-numeric:tabular-nums}
.cover-foot{margin-top:24px;padding-top:14px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted);max-width:none}
/* resumo */
.grade-box{display:flex;gap:24px;align-items:center}
.grade-box .grade{width:88px;height:88px;border-width:3px;border-radius:14px}
.grade-box .grade-v{font-size:48px}
.grade-h{margin-top:0;margin-bottom:4px}
.scale{list-style:none;padding:0;margin-top:18px;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px}
.scale li{display:flex;flex-direction:column;gap:6px;padding:10px;border:1px solid var(--line);border-radius:8px;font-size:12.5px;line-height:1.35;color:var(--muted)}
.scale li.on{border:2px solid var(--g);background:var(--soft);color:var(--ink);font-weight:700}
.scale-g{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:6px;border:2px solid var(--g);color:var(--g);font-weight:800;font-size:14px}
.tiles{list-style:none;padding:0;margin-top:22px;display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.tile{padding:12px 14px 10px;border:1px solid var(--line);border-top:4px solid var(--c);border-radius:8px;background:var(--cb)}
.tile.zero{background:#fff;border-top-color:var(--line)}
.tile.zero .tile-n{color:var(--faint)}
.tile-n{display:block;font-size:28px;font-weight:800;line-height:1.1;color:var(--c);font-variant-numeric:tabular-nums}
.tile-k{display:block;font-weight:700;font-size:14px}
.tile-h{display:block;font-size:12px;color:var(--muted);line-height:1.35;margin-top:2px}
.tile-critical,.sev-critical,.sev-line-critical,.band-critical{--c:var(--crit);--cb:var(--crit-bg)}
.tile-high,.sev-high,.sev-line-high,.band-high{--c:var(--high);--cb:var(--high-bg)}
.tile-medium,.sev-medium,.sev-line-medium,.band-medium{--c:var(--medium);--cb:var(--medium-bg)}
.tile-low,.sev-low,.sev-line-low,.band-low{--c:var(--low);--cb:var(--low-bg)}
.tile-info,.sev-info,.sev-line-info,.band-info{--c:var(--info);--cb:var(--info-bg)}
.sev{display:inline-block;padding:1px 7px;border:1.5px solid var(--c);border-radius:4px;background:var(--cb);color:var(--c);font-size:11px;font-weight:800;
letter-spacing:.07em;text-transform:uppercase;line-height:1.5;white-space:nowrap;vertical-align:1px}
.first{list-style:none;padding:0;display:grid;gap:10px;counter-reset:first}
.first-item{position:relative;min-width:0;padding:12px 16px 12px 50px;border:1px solid var(--line);border-left:5px solid var(--c);border-radius:8px;
break-inside:avoid;overflow-wrap:anywhere}
.first-item::before{counter-increment:first;content:counter(first);position:absolute;left:16px;top:11px;font-size:20px;font-weight:800;color:var(--faint)}
.first-head{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px}
.first-title{font-weight:700;text-decoration:none;font-size:16px;line-height:1.35}
.first-impact{margin-top:5px}
.first-where{margin-top:5px;display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;font-size:13px;color:var(--muted)}
.first-where code{font-size:12.5px}
/* plano */
.legend{font-size:13px;color:var(--muted);margin:-6px 0 16px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line)}
thead th{font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);border-bottom:2px solid var(--ink);padding-top:0}
thead{display:table-header-group}
tr{break-inside:avoid}
.plan .num{width:40px;font-variant-numeric:tabular-nums;font-weight:800;color:var(--c,var(--muted))}
.plan .problem a{text-decoration:none;font-weight:600}
.plan .where{width:34%}
.plan .where code{display:block;font-size:12.5px}
.plan .effort{width:80px;font-weight:600;white-space:nowrap}
.band th{padding:16px 10px 6px;border-bottom:2px solid var(--c);color:var(--c);font-size:12px;letter-spacing:.08em;text-transform:uppercase}
/* achados */
.area{display:flex;align-items:center;gap:10px;margin:40px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--ink);font-size:19px}
.lead+.area{margin-top:8px}
.area-n{font-size:13px;color:var(--muted);font-weight:600}
.finding{margin-top:18px;padding:18px 20px 16px;border:1px solid var(--line);border-left:5px solid var(--c);border-radius:8px}
.f-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;break-after:avoid}
.f-n{font-weight:800;color:var(--faint);font-variant-numeric:tabular-nums}
.f-rule{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--muted)}
.f-title{margin-top:8px;font-size:18px;line-height:1.3;overflow-wrap:anywhere;break-after:avoid}
.f-row{display:grid;grid-template-columns:132px minmax(0,1fr);gap:0 18px;margin-top:10px}
.f-top .f-row{margin-top:14px}
.f-row.cont{margin-top:8px}
.f-k{font-size:11.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding-top:3px}
.f-v{min-width:0}
.places,.refs{list-style:none;padding:0;display:grid;gap:2px}
.places span{color:var(--muted);font-size:13px}
.refs a{font-size:13px;overflow-wrap:anywhere}
.std a{font-family:var(--mono);font-size:13px}
.ev{break-inside:avoid}
.ev figcaption{font-size:12.5px;color:var(--muted);margin-bottom:4px}
.ev figcaption code{color:var(--ink)}
.code{border:1px solid var(--line);border-radius:6px;background:#fafbfc;padding:6px 0;font-family:var(--mono);font-size:12.5px;line-height:1.5}
.ln{display:grid;grid-template-columns:44px minmax(0,1fr);min-height:1.5em}
.ln-n{padding-right:10px;text-align:right;color:var(--faint);user-select:none}
.ln code{font-size:inherit;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:4;padding-right:10px}
.ln.hit{background:#fff3cf;box-shadow:inset 3px 0 0 #c98a00}
.ln.hit .ln-n{color:var(--ink);font-weight:700}
.inv{display:inline-block;margin:0 2px;padding:0 5px;border:1px dashed #b42318;border-radius:4px;color:#b42318;font-family:var(--sans);font-size:11.5px;
font-weight:700;white-space:nowrap}
.ev-missing,.ev-more{font-size:13px;color:var(--muted)}
.ev-more{margin-top:8px}
.vulns{font-size:13px}
.vulns td,.vulns th{padding:6px 8px}
.vid{white-space:nowrap;font-family:var(--mono);font-size:12.5px}
.tag{display:inline-block;margin-left:6px;padding:0 6px;border:1px solid var(--muted);border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.tag-kev{border-color:var(--crit);color:var(--crit)}
/* revisão humana */
.rv{display:inline-block;padding:1px 7px;border:1.5px solid var(--rc);border-radius:4px;background:#fff;color:var(--rc);font-size:11px;font-weight:800;
letter-spacing:.07em;text-transform:uppercase;line-height:1.5;white-space:nowrap;vertical-align:1px}
.rv-confirmed{--rc:var(--ink)}.rv-false_positive{--rc:var(--muted)}.rv-accepted_risk{--rc:#6941c6}.rv-fixed{--rc:var(--gA)}
.rv-todo{--rc:var(--muted);border-style:dashed}
.finding.rv-line-false_positive,.finding.rv-line-fixed{border-left-color:var(--line)}
.analyst{margin-bottom:28px;padding:16px 20px;border:1px solid var(--line);border-left:5px solid var(--honey);border-radius:8px;background:#fffcf4}
.analyst-h{margin:0 0 8px}
.md p+p,.md p+ul,.md ul+p,.md ul+ul{margin-top:8px}
.md ul{padding-left:20px;display:grid;gap:4px}
.md code{padding:0 3px;border-radius:3px;background:var(--soft)}
.md.review{padding:8px 12px;border-radius:6px;background:var(--soft)}
.sign{margin-top:12px;font-size:13px;color:var(--muted)}
.review-line{color:var(--ink);font-weight:600}
.review-counts{margin-top:10px}
.band-done{--c:var(--info);--cb:var(--info-bg)}
.plan .problem .sev{margin-left:4px}
/* escopo */
.facts,.limits,.steps{padding-left:20px;display:grid;gap:6px}
.sources th[scope=row]{white-space:nowrap}
.end{padding:20px 64px 28px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted)}
@media (max-width:700px){
body{font-size:15px}
.doc{margin:0;box-shadow:none}
section{padding:36px 16px}
.end{padding:18px 16px}
.cover{min-height:0}
.cover-gap{flex-basis:48px}
.title{font-size:34px}
.verdict{flex-direction:column;align-items:flex-start}
.meta,.toc ol{grid-template-columns:minmax(0,1fr)}
.scale{grid-template-columns:minmax(0,1fr)}
.scale li{flex-direction:row;align-items:center}
.f-row{grid-template-columns:minmax(0,1fr)}
.f-row,.f-top .f-row{margin-top:10px}
.f-row.cont{margin-top:6px}
.f-row.cont .f-k{display:none}
.finding{padding:14px 14px 12px}
.plan thead{display:none}
.plan,.plan tbody{display:block}
.plan tr{display:grid;grid-template-columns:32px minmax(0,1fr) auto;gap:2px 8px;padding:10px 0;border-bottom:1px solid var(--line)}
.plan td,.plan th,.plan .num,.plan .where,.plan .effort{border:0;padding:0;width:auto}
.plan .num{grid-row:1/3}
.plan .problem{grid-column:2;grid-row:1}
.plan .effort{grid-column:3;grid-row:1;text-align:right}
.plan .where{grid-column:2/4;grid-row:2}
.plan .band{display:block;padding:14px 0 0;border-bottom:2px solid var(--c)}
.plan .band th{display:block;padding:0 0 4px;border:0}
.vulns thead{display:none}
.vulns,.vulns tbody{display:block}
.vulns tr{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:2px 8px;padding:8px 0;border-bottom:1px solid var(--line)}
.vulns td{border:0;padding:0}
.vulns .vsum{grid-column:1/3}
.vid{white-space:normal}
}
@page{size:A4;margin:16mm 15mm 17mm;@bottom-right{content:counter(page) " / " counter(pages);font:8pt system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#8a919e}
@bottom-left{content:"Stingward";font:8pt system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#8a919e}}
@page:first{@bottom-right{content:none}@bottom-left{content:none}}
@media print{
body{background:#fff;font-size:10pt;line-height:1.45}
.doc{max-width:none;margin:0;box-shadow:none}
section{padding:0;break-before:page}
section+section{border-top:0}
.cover{break-before:auto;height:262mm;min-height:0;padding-top:0}
.cover-gap{flex-basis:60mm;min-height:6mm}
.end{display:none}
h2{font-size:18pt;margin-bottom:12pt}
h3{margin:16pt 0 8pt}
h2,h3,h4,h5,.area,.f-head,.f-title,.band{break-after:avoid}
.title{font-size:32pt}
a{text-decoration:none}
.scale li{font-size:8.5pt;padding:7pt}
.tiles{display:flex;margin-top:14pt}
.tile{flex:1 1 0;min-width:0}
.first-item,.code,tr,.grade-box,.tiles,.scale,.verdict,.ev,.md p,.md li{break-inside:avoid}
.first-title{font-size:11pt}
.finding{padding:11pt 13pt 9pt}
.f-row{grid-template-columns:28mm minmax(0,1fr)}
.f-top,.f-row{break-inside:avoid}
.f-row.long{break-inside:auto}
.finding>.f-row:last-child,tbody tr:last-child{break-before:avoid}
table{font-size:9.5pt}
.code{font-size:8.5pt}
.toc a{padding:3pt 0}
}
"""
