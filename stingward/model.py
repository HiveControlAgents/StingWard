"""Tipos básicos: achado, severidade e o contexto de uma auditoria."""
from __future__ import annotations

import codecs
import os
from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


# O BOM no início diz a codificação. UTF-16 é o que o PowerShell grava com > (pip freeze > requirements.txt) e o
# Bloco de Notas com "Unicode"; o UTF-32 vem antes porque o BOM dele começa com o do UTF-16.
_BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
         (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))
TEXT_BOMS = tuple(bom for bom, _ in _BOMS)


def decode_text(data: bytes, errors: str = "replace") -> str:
    """Texto de um arquivo como as verificações e o relatório o leem: UTF-8 sem o BOM, ou UTF-16/32 pelo BOM; \r\n
    e \r viram \n, como no open() em modo texto. Com errors="strict", byte inválido levanta UnicodeDecodeError em vez
    de virar \ufffd: o arquivo de revisão e o parecer, escritos à mão, são recusados em vez de mudar calados."""
    enc = next((e for bom, e in _BOMS if data.startswith(bom)), "utf-8-sig")
    return data.decode(enc, errors=errors).replace("\r\n", "\n").replace("\r", "\n")


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
        # Sem tirar o BOM (UTF-8 do Bloco de Notas, UTF-16 do PowerShell), o json.loads do .mcp.json e as regras
        # ancoradas no começo do arquivo falhariam, e o arquivo sairia da auditoria calado.
        if rel not in self._cache:
            try:
                with open(os.path.join(self.root, rel), "rb") as fh:
                    self._cache[rel] = decode_text(fh.read())
            except OSError:
                self._cache[rel] = ""
        return self._cache[rel]
