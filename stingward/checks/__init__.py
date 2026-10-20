"""Verificações. Cada módulo expõe check(ctx) -> list[Finding]."""
from __future__ import annotations

import re

_TEXT_EXT = {
    "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte", "astro", "go", "rb", "php", "java", "kt",
    "rs", "cs", "swift", "dart", "sh", "bash", "zsh", "ps1", "sql", "json", "jsonc", "yaml", "yml", "toml",
    "ini", "cfg", "conf", "env", "md", "mdx", "mdc", "txt", "html", "xml", "properties", "tf", "rules",
}
_TEXT_NAMES = {"Dockerfile", "Makefile", "Procfile", ".cursorrules", ".windsurfrules", ".npmrc", ".pypirc", ".netrc"}
_SKIP = re.compile(r"(\.min\.(js|css)|\.map|\.lock|-lock\.json|-lock\.yaml|\.snap)$|(^|/)(go\.sum|bun\.lockb?)$")
_LOCKS = re.compile(r"(\.lock|-lock\.json|-lock\.yaml)$|(^|/)(go\.sum|bun\.lockb?)$")


def is_text_source(rel: str, mode: str = "project") -> bool:
    name = rel.rsplit("/", 1)[-1]
    # Numa skill, o bundle minificado é justamente o código que vai rodar.
    if (_LOCKS if mode == "skill" else _SKIP).search(rel):
        return False
    if name in _TEXT_NAMES or name.startswith(".env"):
        return True
    return "." in name and name.rsplit(".", 1)[-1].lower() in _TEXT_EXT


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1
