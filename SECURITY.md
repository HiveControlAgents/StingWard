# Security policy

[Português](#português)

## Reporting a vulnerability

If you find a vulnerability in Stingward itself, for example a way for an audited project or skill to run code, hide findings or leak data through the report, please report it privately: open the repository's **Security** tab and choose **[Report a vulnerability](https://github.com/HiveControlAgents/StingWard/security/advisories/new)**. Do not open a public issue.

Please include the Stingward version (`stingward --version`), the command you ran and a minimal sample that reproduces it. We aim to reply within 7 days and to ship a fix for confirmed issues as a new release, crediting you if you want.

## Supported versions

Security fixes go into the latest release. Upgrade with `pipx upgrade stingward`, `npx stingward@latest`, `/plugin update` in Claude Code, `codex plugin marketplace upgrade` followed by `codex plugin add stingward@stingward` in Codex, or by keeping the Action on `@v0`.

## Scope

Stingward reads untrusted content by design. These are in scope: code execution or file writes caused by audited content, findings that audited content can hide or downgrade below what the docs promise, secrets reaching any report format, terminal, markdown or HTML injection through reports, and anything that sends more than package names and versions off the machine.

Findings that Stingward reports about *your* project are not vulnerabilities in Stingward. False positives and misses are welcome as [regular issues](https://github.com/HiveControlAgents/StingWard/issues/new?template=false-positive.yml).

## Português

Achou uma vulnerabilidade no próprio Stingward? Relate em particular pela aba **Security** do repositório, em **[Report a vulnerability](https://github.com/HiveControlAgents/StingWard/security/advisories/new)**, e não abra issue pública. Inclua a versão (`stingward --version`), o comando e um exemplo mínimo. Respondemos em até 7 dias. Achados que o Stingward mostra sobre o *seu* projeto não são vulnerabilidades dele; alarmes falsos podem ir como issue comum.
