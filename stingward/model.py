"""Tipos básicos: achado, severidade e o contexto de uma auditoria."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def bump(sev: str, steps: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, SEV_RANK[sev] + steps)]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int | None = None
    # Valores para preencher os textos da regra (rules.py), nunca o segredo em si.
    params: dict = field(default_factory=dict)
    refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Identidade estável do achado (review.assign): o arquivo de revisão aponta para ela, não para o número da linha.
    fingerprint: str = field(default="", compare=False)

    def key(self):
        return (self.rule, self.file, self.line, tuple(sorted((k, str(v)) for k, v in self.params.items())))


@dataclass
class Context:
    root: str
    files: list[str]          # caminhos relativos a root
    offline: bool = False
    git_tracked: set[str] | None = None
    sources: dict = field(default_factory=dict)   # metadados das bases consultadas
    mode: str = "project"                          # project | skill | agents
    too_big: list = field(default_factory=list)    # arquivos de código e texto que o limite de tamanho deixou de fora
    truncated: bool = False                        # a listagem parou em scan.MAX_FILES
    _cache: dict = field(default_factory=dict)

    def read(self, rel: str) -> str:
        # utf-8-sig: o BOM que o Bloco de Notas e o PowerShell gravam no início quebraria o json.loads do .mcp.json
        # e as regras ancoradas no começo do arquivo, e o arquivo sairia da auditoria calado.
        if rel not in self._cache:
            try:
                with open(os.path.join(self.root, rel), encoding="utf-8-sig", errors="replace") as fh:
                    self._cache[rel] = fh.read()
            except OSError:
                self._cache[rel] = ""
        return self._cache[rel]
