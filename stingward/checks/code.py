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

_SRC = {REQ: ("dados da requisição", "request input"), PARAM: ("um argumento da função", "a function argument")}


def _src(origin):
    pt, en = _SRC[origin]
    return {"source_pt": pt, "source_en": en}


_LLM_SINK = {
    # tipo: (onde chega pt, en, o que vira pt, en, como corrigir pt, en)
    "code": ("eval/exec", "eval/exec", "código rodando no seu servidor", "code running on your server",
             "não execute a resposta; peça JSON, valide os campos e chame só funções de uma lista fixa.",
             "do not run the answer; ask for JSON, validate it and call only functions from a fixed list."),
    "shell": ("um comando de shell", "a shell command", "comandos rodando no seu servidor", "commands running on your server",
              "mapeie a resposta para comandos de uma lista fixa e passe os argumentos em lista, sem shell.",
              "map the answer to commands from a fixed list and pass arguments as a list, without a shell."),
    "template": ("um template", "a template", "código rodando no seu servidor", "code running on your server",
                 "use um template fixo e passe a resposta como variável.", "use a fixed template and pass the answer as a variable."),
    "sql": ("uma consulta SQL", "a SQL query", "leitura ou exclusão dos seus dados", "reading or deleting your data",
            "rode com um usuário de banco só de leitura, limitado às tabelas necessárias, ou deixe o modelo só preencher "
            "parâmetros de consultas escritas por você.",
            "run it with a read-only database user limited to the tables it needs, or let the model only fill parameters "
            "of queries you wrote."),
    "html": ("a página como HTML", "the page as HTML", "scripts rodando no navegador de quem usa o app",
             "scripts running in your users' browsers",
             "mostre como texto, ou converta o Markdown e limpe com DOMPurify.sanitize antes de inserir.",
             "show it as text, or convert the Markdown and clean it with DOMPurify.sanitize before inserting it."),
}


def _llm_params(kind):
    s = _LLM_SINK[kind]
    return {"sink_pt": s[0], "sink_en": s[1], "impact_pt": s[2], "impact_en": s[3], "fix_pt": s[4], "fix_en": s[5]}


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

    def list(self):
        found = sorted(self.items.values(), key=lambda f: (-SEV_RANK[f.severity], f.line or 0))
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
_SQL_DDL = re.compile(r"\s*\(?\s*(?:pragma|create|drop|alter|truncate)\b", re.I)


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
_TOOL_DECO = re.compile(r"(?:^|\.)(?:tool|function_tool|call_tool)$")
_NOT_REQ_ANN = re.compile(r"(?i)(?:dep|deps|dependency|session|db|user|request|response|websocket|tasks?|connection|"
                          r"settings|config|client|logger|context|ctx|engine|cursor)$")
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
_GUARD_URL = re.compile(r"urlparse|urlsplit|\.hostname|\.netloc|ipaddress|is_private|allow(?:ed)?_?(?:hosts|domains|list)|"
                        r"whitelist|allowlist|startswith")
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


class _Py:
    def __init__(self, rel, text, tree):
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
        self.clients = set()
        self.hashers = {}
        self.llm_funcs = set()
        self.routes = []   # (função, decoradores) para APP011

    # ------------------------------------------------------------------ origem dos valores

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

    def origins(self, node, env):
        out = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n is None:
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
                out |= env.get(n.id, set())
                continue
            if isinstance(n, ast.Attribute):
                key = _attr_key(n)
                if key and key in env:
                    out |= env[key]
                    continue
                if n.attr in ("name", "stem", "suffix") and isinstance(n.value, ast.Call) and \
                        self._dot(n.value.func).endswith(("Path", "PurePath")):
                    continue
                stack.append(n.value)
                continue
            if isinstance(n, ast.Subscript):
                stack.append(n.value)
                continue
            if isinstance(n, (ast.Compare, ast.Lambda)):
                continue
            if isinstance(n, ast.IfExp):
                stack += [n.body, n.orelse]
                continue
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                stack += [g.iter for g in n.generators]
                stack += [n.key, n.value] if isinstance(n, ast.DictComp) else [n.elt]
                continue
            stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, _SKIP_NODES))
        return out

    # ------------------------------------------------------------------ strings montadas

    def pieces(self, node, env, depth=0):
        """Partes de uma string montada: [("lit", texto) | ("expr", nó)]."""
        if depth > 6 or node is None:
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
            return self.pieces(node.left, env, depth + 1) + self.pieces(node.right, env, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _const_str(node.left):
            return _percent_pieces(node.left.value, node.right)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
                and _const_str(node.func.value):
            return _format_pieces(node.func.value.value, node)
        if isinstance(node, ast.Name) and node.id in self.strs:
            out = []
            for part in self.strs[node.id]:
                out += self.pieces(part, env, depth + 1)
            return out
        return [("expr", node)]

    def static(self, node):
        """Valor que não vem de fora: constante, número, placeholder (",".join("?" * n)), nome de tabela do próprio código."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id.isupper() or bool(re.search(r"(?i)placeholder|marks|^ph$|^qs$|params?_?(?:str|sql|list)|bind|"
                                                       r"^(?:table|tables|table_name|tablename|schema|columns?|cols|fields|"
                                                       r"col|column_name|order|direction|sort_dir|where|where_clause|"
                                                       r"conditions?|clause|set_clause|joins?|filters?_sql|sql|query|"
                                                       r"select|limit|offset|n|i|idx|count)$", node.id))
        if isinstance(node, ast.Attribute):
            return bool(re.search(r"(?i)table|schema|column|_meta|model|index|collection|^name$", node.attr)) and \
                isinstance(node.value, (ast.Name, ast.Attribute))
        if isinstance(node, ast.Call):
            d = self._dot(node.func)
            last = d.rsplit(".", 1)[-1] if d else ""
            if last in _KILL or last in ("Identifier", "quote_ident", "quote_name"):
                return True
            if last == "join":
                return any(_const_str(c) and re.search(r"\?|%s|%\(|\$\d|:\w|\{\}", c.value)
                           for c in _walk(node) if c is not node.func)
        return False

    def sql_verdict(self, node, env):
        """(severidade, origem) para uma consulta montada com valores no meio do texto, ou None."""
        parts = self.pieces(node, env)
        exprs = [(i, p) for i, (k, p) in enumerate(parts) if k == "expr"]
        if not exprs:
            return None
        lit = "".join(p if k == "lit" else "x1" for k, p in parts)
        if not looks_sql(lit):
            return None
        # PRAGMA e DDL não aceitam parâmetros (nome de tabela, de índice): com origem desconhecida, não há o que corrigir.
        ddl = bool(_SQL_DDL.match(lit))
        best = None
        for i, expr in exprs:
            if expr is None or self.static(expr):
                continue
            o = self.origins(expr, env)
            before = "".join(p for k, p in parts[:i] if k == "lit")
            if o & MODEL:
                return ("high", LLM)
            if o & REQ_ANY:
                best = ("high", REQ)
            elif PARAM in o and not ddl and _VALUE_POS.search(before):
                best = best or ("medium", PARAM)
        return best

    # ------------------------------------------------------------------ percurso

    def run(self):
        self.body(self.tree.body, {}, _Fn(None, False, False, ""))
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
            for item in st.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.function(item, {})
                else:
                    self.stmt(item, {}, fn)
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
                env[st.target.id] = env.get(st.target.id, set()) | o
                if isinstance(st.op, ast.Add) and st.target.id in self.strs:
                    if len(self.strs[st.target.id]) < _STR_PARTS:
                        self.strs[st.target.id] = self.strs[st.target.id] + [st.value]
                    else:
                        del self.strs[st.target.id]  # texto montado em dezenas de passos: segue só a origem
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            _bind(st.target, self.origins(st.iter, env), env)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for it in st.items:
                if it.optional_vars is not None:
                    _bind(it.optional_vars, self.origins(it.context_expr, env), env)
                    if isinstance(it.optional_vars, ast.Name) and isinstance(it.context_expr, ast.Call) and \
                            self._dot(it.context_expr.func) in _PY_CLIENT_CTOR:
                        self.clients.add(it.optional_vars.id)
        elif isinstance(st, ast.Return) and st.value is not None:
            self.returned(st, env, fn)
        for b in _bodies(st):
            self.body(b, env, fn)

    def function(self, node, outer):
        decos = [self._dot(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list]
        route = any(_ROUTE_DECO.search(d) for d in decos if d)
        tool = any(_TOOL_DECO.search(d) for d in decos if d)
        env = dict(outer)
        saved = self.strs, self.vals
        self.strs, self.vals = dict(saved[0]), dict(saved[1])
        a = node.args
        params = a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]
        defaults = dict(zip([p.arg for p in (a.posonlyargs + a.args)][::-1], a.defaults[::-1]))
        defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
        # Comando de linha (click, typer): quem passa o argumento é quem roda o programa.
        cli = not route and not tool and any(_CLI_DECO.search(d) for d in decos if d)
        segs = _route_segments(node) if route else {}
        for p in params:
            if p.arg in ("self", "cls") or cli or segs.get(p.arg) == "typed" or _scalar_annotation(p.annotation):
                env.pop(p.arg, None)  # o parâmetro esconde a variável de fora com o mesmo nome
                continue
            origin = PARAM
            if tool:
                origin = TOOL
            elif route and not _framework_param(p, defaults.get(p.arg), self.imports):
                origin = SEG if segs.get(p.arg) == "seg" else REQ
            env[p.arg] = {origin}
        head_start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        head_end = max(head_start, node.body[0].lineno - 1) if node.body else node.lineno
        fn = _Fn(node, route, tool, self.seg(node), "\n".join(self.lines[head_start - 1:head_end]))
        if route:
            self.routes.append((node, decos))
        if self.llm_sdk and any(isinstance(c, ast.Call) and self.is_llm_call(c, cost=True) for c in _walk(node)):
            self.llm_funcs.add(node.name)
        self.body(node.body, env, fn)
        self.strs, self.vals = saved

    def assign(self, targets, value, env, fn):
        o = self.origins(value, env)
        for t in targets:
            self.assigned(t, value, fn)
            _bind(t, o, env)
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
        if name and secret_name(name) and self.weak_random(value):
            self.out.add("COD010", "low", ln, {"name": name})

    def returned(self, st, env, fn):
        if fn.node is not None and secret_name(fn.name) and self.weak_random(st.value):
            self.out.add("COD010", "low", st.lineno, {"name": fn.name})
        if fn.route and self.flaskish and _builds_string(st.value):
            self.html_response(st.value, env, st.lineno)

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
        built = _builds_string(cmd) or (isinstance(cmd, ast.Name) and cmd.id in self.strs)
        if shell:
            o = self.origins(cmd, env)
        else:
            # Sem shell, o perigo é o programa vir de fora: ["git", "log", x] é seguro, [x, ...] ou x.split() não.
            prog = cmd.elts[0] if isinstance(cmd, (ast.List, ast.Tuple)) and cmd.elts else cmd
            if isinstance(prog, ast.Starred) or _const_str(prog):
                return
            o, built = self.origins(prog, env), False
        if LLM in o or (TOOL in o and built):
            self.out.add("APP009", "critical", ln, _llm_params("shell"))
        elif TOOL in o:
            # Ferramenta feita para rodar o comando que o modelo escolher: é o desenho, mas qualquer injeção vira comando.
            self.out.add("APP009", "high", ln, _llm_params("shell"))
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
        o = self.origins(code, env)
        built = _builds_string(code)
        if LLM in o or (TOOL in o and built):
            self.out.add("APP009", "critical", ln, _llm_params(kind))
        elif TOOL in o:
            self.out.add("APP009", "high", ln, _llm_params(kind))
        elif o & REQ_ANY:
            self.out.add("COD003", "critical", ln, dict(_src(REQ), sink=sink))
        elif PARAM in o and kind == "code" and self.server and built:
            self.out.add("COD003", "medium", ln, dict(_src(PARAM), sink=sink))

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
        text_call = d in ("sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text", "sqlmodel.text")
        if not text_call:
            if last not in _PY_SQL_METHODS or not isinstance(call.func, ast.Attribute):
                return
            if last in ("fetch", "query", "sql") and not _PY_SQL_RECEIVER.search(_receiver(call)):
                return
        q = _arg(call, 0, "sql", "query", "statement", "operation")
        if q is None or _const_str(q):
            return
        v = self.sql_verdict(q, env)
        if v is None and (text_call or _PY_SQL_RECEIVER.search(_receiver(call))):
            # SQL escrito pelo modelo (text-to-SQL) ou mandado na requisição. Argumento de ferramenta que é a consulta
            # inteira é uma ferramenta de SQL por desenho: o risco está nas permissões do banco, não neste código.
            o = self.whole_query(q, env)
            v = ("high", LLM) if LLM in o else ("high", REQ) if o & REQ_ANY else None
        if v is None:
            return
        sev, origin = v
        if origin == LLM:
            self.out.add("APP009", sev, ln, _llm_params("sql"))
        else:
            self.out.add("COD001", sev, ln, _src(origin))

    def deserialize(self, call, d, env, ln):
        if d in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"):
            if not self.imported(call.func):
                return  # yaml = YAML() do ruamel, ou outro objeto com load()
            loader = _kw(call, "Loader") if _kw(call, "Loader") is not None else (call.args[1] if len(call.args) > 1 else None)
            ld = self._dot(loader) if loader is not None else ""
            if "unsafe" not in d and loader is not None and not ld.endswith(("Loader", "UnsafeLoader")):
                return  # SafeLoader, CSafeLoader, BaseLoader, FullLoader
            if ld.endswith(("SafeLoader", "BaseLoader", "FullLoader")):
                return
            data = _arg(call, 0, "stream")
            o = self.origins(data, env) if data is not None else set()
            explicit = "unsafe" in d or loader is not None
            sev = "high" if o & (REQ_ANY | {LLM}) else "medium" if explicit or NET in o else "low"
            self.out.add("COD004", sev, ln, {"what": "yaml." + d.split(".", 1)[1] + ("" if loader is None else f"(Loader={ld.rsplit('.', 1)[-1]})")})
        elif d in _PY_UNPICKLE:
            if d == "numpy.load" and not _is_true(_kw(call, "allow_pickle")):
                return
            data = _arg(call, 0, "data", "file", "filename")
            o = self.origins(data, env) if data is not None else set()
            if o & (REQ_ANY | {LLM}):
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
        if REQ in self.origins(target, env):
            self.out.add("COD007", "high", ln, {"sink": (d or last) + "()"})

    def is_path(self, v):
        if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Div):
            return True
        return isinstance(v, ast.Call) and self._dot(v.func).endswith(("Path", "PurePath", "os.path.join", "joinpath"))

    def start_controlled(self, node, env):
        """A requisição decide o começo do endereço (esquema e host), não só um pedaço do caminho."""
        if isinstance(node, ast.BoolOp):
            return self.start_controlled(node.values[0], env)
        if isinstance(node, ast.Name) and node.id in self.strs:
            parts = self.pieces(node, env)
        elif _builds_string(node):
            parts = self.pieces(node, env)
        else:
            return REQ in self.origins(node, env)
        parts = [p for p in parts if not (p[0] == "lit" and p[1] == "")]
        return bool(parts) and parts[0][0] == "expr" and parts[0][1] is not None and REQ in self.origins(parts[0][1], env)

    def urls(self, call, d, last, env, fn, ln):
        f = call.func
        http = (d.startswith(("requests.", "httpx.")) and last in _PY_HTTP and last not in ("Client", "AsyncClient", "Session")) or \
            d in ("urllib.request.urlopen", "urllib.request.Request", "urlopen", "requests.request") or \
            (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in self.clients and last in _PY_HTTP)
        if http:
            url = _arg(call, 1 if last == "request" else 0, "url")
            if url is not None and not _const_str(url) and not fn.guard_url and not fn.admin and self.start_controlled(url, env):
                self.out.add("COD008", "high", ln, {"sink": d + "()"})
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


def _builds_string(node):
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(_const_str(n) or isinstance(n, ast.JoinedStr) for n in _walk(node))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _const_str(node.func.value)
    return _const_str(node)


def _percent_pieces(fmt, right):
    vals = right.elts if isinstance(right, ast.Tuple) else None
    names = right if isinstance(right, ast.Dict) else None
    out, i = [], 0
    pos = 0
    for m in re.finditer(r"%(?:\(([^)]*)\))?[-#0 +]*\d*(?:\.\d+)?([sdifrxXeEgGcab%])", fmt):
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


def _framework_param(p, default, imports):
    """Parâmetro de rota que o framework injeta (banco, usuário logado, Request), não dado de quem chama."""
    if p.arg in _NOT_REQ_PARAM:
        return True
    if default is not None and isinstance(default, ast.Call):
        d = _dotted(default.func, imports) or ""
        if d.endswith(("Depends", "Security")):
            return True
    ann = p.annotation
    if ann is not None:
        for n in _walk(ann):
            if isinstance(n, ast.Call) and (_dotted(n.func, imports) or "").endswith(("Depends", "Security")):
                return True
        if isinstance(ann, ast.Name) and _NOT_REQ_ANN.search(ann.id):
            return True
        if isinstance(ann, ast.Attribute) and _NOT_REQ_ANN.search(ann.attr):
            return True
    return False


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


def scan_python(rel, text):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarning de escape inválido no código auditado não vai para o terminal
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    try:
        return _Py(rel, text, tree).run()
    except RecursionError:
        return []


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
    long_lines = 0
    for line in text.split("\n", 2000):
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
_JS_CALL_NAME = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>\s*)?\(")
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
_JS_DECL = re.compile(r"(?:const|let|var)\s+(\{[^{}]*\}|\[[^\[\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[^=;\n]{1,120}?)?=(?![=>])")
_JS_FUNC = re.compile(r"function\b\s*\*?\s*([A-Za-z_$][\w$]*)?\s*(?:<[^>()]{0,200}>)?\s*\(")
_JS_ARROW_TYPE = re.compile(r"\)\s*:\s*[^=;{}()]{1,80}$")
_JS_METHOD = re.compile(r"\n[ \t]*(?:(?:public|private|protected|static|async|override|readonly)[ \t]+)*"
                        r"([A-Za-z_$][\w$]*)[ \t]*(?:<[^>()\n]{0,200}>)?[ \t]*(\()")
_WORDCH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
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


def _near(hint, full, text, back=60, ahead=200):
    """full.search(text), mas só perto de onde hint (que começa com texto fixo e é rápida) acha um começo possível."""
    for m in hint.finditer(text):
        if full.search(text, max(0, m.start() - back), m.end() + ahead):
            return True
    return False
_JS_NOT_METHOD = {"if", "for", "while", "switch", "catch", "function", "return", "with", "await", "typeof", "new", "super",
                  "else", "do", "try", "throw", "delete", "void", "yield", "import", "export", "case"}
_JS_ROUTE_FN = re.compile(r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(|"
                          r"export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\(|function)")
_JS_TOOL_CALL = re.compile(r"\.\s*(?:tool|registerTool)\s*\(|tool\s*\(|new\s+(?:DynamicStructuredTool|DynamicTool)\s*\(|"
                           r"setRequestHandler\s*\(\s*CallToolRequestSchema")
_JS_EXECUTE_KEY = re.compile(r"\b(?:execute|func|handler)\s*:\s*(?:async\s*)?(?:function\s*\w*\s*)?$")


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


def _param_names(text):
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
            out += _pattern_names(p[:close + 1] if close > 0 else p)
            continue
        m = re.match(r"(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)", p)
        if m:
            out.append(m.group(1))
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
_TPL_HTML = re.compile(r"""\bv-html\s*=\s*"([^"]{0,2000})"|\{@html\s+([^}]{0,2000})\}|\bset:html\s*=\s*\{([^}]{0,2000})\}""")
_JS_SANITIZE = re.compile(r"(?i)DOMPurify|purify|sanitiz|\bxss\b|filterXSS|escape|encodeHTML|he\s*\.\s*encode|insane|"
                          r"JSON\s*\.\s*stringify|serialize|highlight|katex|prism|shiki|hljs|mermaid|icon|svg|\bcss\b|style")
_JS_TLS = re.compile(r"\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b")
_NODE_TLS = re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=(?!=)\s*['\"]?0\b")
_ENV_TLS = re.compile(r"(?m)\b(NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY)['\"]?\s*[=:]\s*['\"]?0\b")
_JS_FS = re.compile(r"fs(?:\s*\.\s*promises)?\s*\.\s*(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|"
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
                            r"\.test\s*\(|isWithin|isInside|isSubPath|isSafePath")
_JS_GUARD_REDIRECT = re.compile(r"startsWith\s*\(\s*['\"]/|isSafe|safeRedirect|isValidRedirect|isRelative|allowed|whitelist|"
                                r"allowlist|\.origin\s*[!=]==|\.host(?:name)?\s*[!=]==")
_JS_GUARD_URL = re.compile(r"(?i)allowed|whitelist|allowlist|isPrivate|private|\.hostname\s*[!=]==|\.host\s*[!=]==|startsWith\s*\(")
_JS_RANDOM = re.compile(r"Math\s*\.\s*random\s*\(")
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
_JS_USE_SERVER = re.compile(r"""^\s*(['"])use server\1""", re.M)
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
    def __init__(self, rel, text, project):
        self.rel, self.text, self.project = rel, text, project
        self.code, self.mask, lits = _js_mask(_script_only(rel, text))
        self.sql_lits = any(_SQL_VERB.match(self.code, x, y) for x, y in lits)
        self.out = _Out(rel)
        self.budget = _JS_BUDGET + 40 * len(text)
        self.env = {"searchParams": {REQ}}
        self.strs = {}
        self.mcp = "CallToolRequestSchema" in self.code
        self.cp_mods, self.cp_funcs = set(), {}
        self.use_client = bool(re.match(r"""\s*(['"])use client\1""", self.code))
        self.chat_hooks = any(h in self.mask for h in ("useChat", "useCompletion", "useAssistant", "useObject")) and \
            bool(re.search(r"(?<![\w$.])use(?:Chat|Completion|Assistant|Object)\s*\(", self.mask))
        self._server = self._llm_file = None
        self.tool_spans = []
        self.has_req = self.has_llm = False

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
        """Posição do ( que abre o ) em j, ou -1."""
        depth = 0
        for i in range(j, max(-1, j - limit), -1):
            c = self.mask[i]
            if c in ")]}":
                depth += 1
            elif c in "([{":
                depth -= 1
                if depth == 0:
                    return i
        return -1

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
        mask = self.mask
        depth = 0
        n = min(len(mask), p + limit)
        self.spend(min(n - p, 400))  # o fim costuma vir logo; o resto é cobrado em origins()
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
        if self.mcp and _JS_MCP_ARGS.search(m):
            o.add(TOOL)
            m = _JS_MCP_ARGS.sub(" ", m)
        if "file" in m:
            m = _JS_UPLOAD.sub(lambda x: " " * len(x.group()), m)
        if self.has_req and _JS_REQ.search(m):
            o.add(REQ)
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

    def pieces(self, a, b, depth=0):
        a, b = self.trim(a, b)
        if a >= b or depth > 6:
            return []
        ops = self.split_plus(a, b)
        if len(ops) > 1:
            return [p for x, y in ops for p in self.pieces(x, y, depth + 1)]
        c = self.code[a]
        if c in "'\"" and self.code[b - 1] == c and b - a >= 2 and not self.mask[a + 1:b - 1].strip():
            return [("lit", self.code[a + 1:b - 1])]
        if c == "`" and self.code[b - 1] == "`":
            return self.template(a, b)
        word = self.code[a:b]
        if word in self.strs:
            out = []
            for x, y in self.strs[word]:
                out += self.pieces(x, y, depth + 1)
            return out
        if c == "(" and self.close(a) == b - 1:
            return self.pieces(a + 1, b - 1, depth + 1)
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

    def static(self, a, b):
        s = self.code[a:b].strip()
        if re.fullmatch(r"\d+(?:\.\d+)?|[A-Z][A-Z0-9_]*|true|false|null|undefined", s):
            return True
        if re.fullmatch(r"(?:window\.)?location\.(?:origin|host|hostname|protocol)|(?:process|import\.meta)\.env\.\w+", s):
            return True
        if re.search(r"(?i)placeholder|^(?:table|tableName|schema|columns?|cols|fields|order|direction|sortDir|where|"
                     r"whereClause|conditions?|clause|setClause|joins?|sql|query|select|limit|offset|i|idx|n|count)$", s):
            return True
        if re.search(r"\.join\s*\(", s) and re.search(r"[?$]|%s|:\w", s):
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
        if "tool" in mask or "Tool" in mask:
            self.tool_spans = [(m.end(), self.close(m.end() - 1)) for m in _JS_TOOL_CALL.finditer(mask)
                               if m.group()[0] in ".ns" or self.lead_ok(m.start(), False)]
        self.has_req = "searchParams" in mask or _near(_JS_REQ_HINT, _JS_REQ, mask, 40, 40) or \
            any(t in mask for t in _JS_REQ_CALLS) and bool(_JS_REQ.search(mask)) or \
            "export" in mask and bool(_JS_ROUTE_FN.search(mask))
        self.has_llm = _near(_JS_LLM_HINT, _JS_LLM, mask)
        tool = self.mcp or bool(self.tool_spans) or any(t in mask for t in ("execute", "handler", "func:", "func :")) and \
            bool(re.search(r"(?:execute|func|handler)\s*:", mask))
        return self.has_req, self.has_llm or tool

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
        if req:
            if any(t in mask for t in ("fs", "sendFile", "download", "Bun", "Deno")):
                rules.append((_JS_FS, self.files))
                if _FS_IMPORT.search(code):
                    rules.append((_JS_FS_BARE, self.files))
            if any(t in mask for t in ("fetch", "got", "ky", "needle", "axios", "superagent", "http")) and self.server:
                rules.append((_JS_FETCH, self.fetch))
            if any(t in mask for t in ("redirect", "Redirect", "location", "router")):
                rules.append((_JS_REDIRECT, self.redirect))
            if any(t in mask for t in ("system", "instructions")):
                rules.append((_JS_SYSTEM_KEY, self.system_key))
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
        if events or tpl:
            events += self.flow_events()
            events.sort(key=lambda e: (e[0], e[1]))
            for _, _, kind, data in events:
                if kind == "decl":
                    self.declare(*data)
                elif kind == "params":
                    names, origin = data
                    for n in names:
                        self.env[n] = {origin}
                        self.strs.pop(n, None)
                else:
                    fn, m = data
                    fn(m)
        if tpl:
            self.template_html()

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
            self.params_event("function", m.start(), m.end() - 1, None, events)
        for m in _JS_METHOD.finditer("\n" + mask):
            if m.group(1) not in _JS_NOT_METHOD:
                self.params_event("method", m.start(1) - 1, m.start(2) - 1, None, events)
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

    def params_event(self, kind, at, op, name, events):
        if name:
            names, start = [name], at
        else:
            cl = self.close(op, 2000)
            if cl < 0:
                return
            if kind == "method" and not re.match(r"\s*(?::\s*[^{;=]{1,120})?\{", self.mask[cl + 1:cl + 130]):
                return
            names, start = _param_names(self.mask[op + 1:cl]), op
        if not names:
            return
        before = self.mask[max(0, at - 120):at]
        origin = PARAM
        if any(a <= start <= b for a, b in self.tool_spans) or _JS_EXECUTE_KEY.search(before):
            origin = TOOL
        elif op is not None and kind != "method" and self.route_head(at, op):
            # GET(req, { params }): o segundo argumento é o pedaço da URL.
            names = names[1:]
            origin = REQ
        events.append((start, 0, "params", (names, origin)))

    def route_head(self, at, op):
        r = _JS_ROUTE_FN.search(self.mask, max(0, at - 80), op + 1)
        return bool(r) and r.end() == op + 1

    def declare(self, names, start, op):
        end = self.expr_end(start)
        o = self.origins(start, end)
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
            if self.static(x, y):
                continue
            o = self.origins(x, y)
            before = "".join(p for k, p in parts[:i] if k == "lit")
            if o & MODEL:
                return ("high", LLM)
            if REQ in o:
                best = ("high", REQ)
            elif PARAM in o and not ddl and _VALUE_POS.search(before):
                best = best or ("medium", PARAM)
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
        shell = fn in ("exec", "execSync", "execShell", "execaCommand", "execaCommandSync") or bool(re.search(r"\bshell\s*:\s*true", rest))
        parts = self.pieces(a, b)
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
            o = self.origins(a, b) if not (parts and parts[0][0] == "lit") else set()
            built = False
        self.report_exec(o, built, "shell", m, "COD002", _src(REQ))

    def report_exec(self, o, built, kind, m, rule, params):
        ln = self.line(m.start())
        if LLM in o or (TOOL in o and built):
            self.out.add("APP009", "critical", ln, _llm_params(kind))
        elif TOOL in o:
            self.out.add("APP009", "high", ln, _llm_params(kind))
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
        if not parts or all(k == "lit" for k, _ in parts) or _JS_SANITIZE.search(s):
            return
        o = set()
        for k, p in parts:
            if k == "expr":
                o |= self.origins(*p)
        built = any(k == "lit" and "<" in p for k, p in parts) and any(k == "expr" and not self.static(*p) for k, p in parts)
        ln = self.line(pos)
        if LLM in o or TOOL in o or (self.chat_hooks and re.search(r"\.(?:content|text)\b|\bcompletion\b|\.parts\b", s)):
            self.out.add("APP009", "medium", ln, _llm_params("html"))
        elif REQ in o:
            self.out.add("COD005", "medium", ln, {"sink": sink})
        elif built and sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            self.out.add("COD005", "low", ln, {"sink": sink})

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
        if _JS_GUARD_PATH.search(self.code, max(0, m.start() - 800), m.start()):
            return
        if REQ in self.origins(a, b):
            self.out.add("COD007", "high", self.line(m.start()), {"sink": re.sub(r"\s", "", m.group(0)).rstrip("(") + "()"})

    def start_controlled(self, a, b):
        a, b = self.trim(a, b)
        s = self.mask[a:b]
        w = re.match(r"(?:new\s+URL|decodeURIComponent|decodeURI|String|encodeURI)\s*\(", s)
        if w:
            inner = self.args(a + w.end())
            if not inner:
                return False
            a, b = inner[0]
        parts = self.pieces(a, b)
        parts = [p for p in parts if not (p[0] == "lit" and not p[1])]
        if not parts or parts[0][0] != "expr":
            return False
        x, y = parts[0][1]
        first = re.split(r"\s*(?:\|\||\?\?|\?(?!\.))\s*", self.mask[x:y].strip(), maxsplit=1)[0]
        return REQ in self.origins(x, x + len(first)) if first else False

    def fetch(self, m):
        if not self.server or not self.lead_ok(m.start(), not _JS_BARE_FETCH.match(m.group(0))):
            return
        args = self.args(m.end())
        if not args or self.code[args[0][0]] in "{[":
            return
        if _JS_GUARD_URL.search(self.mask, max(0, m.start() - 800), m.start()):
            return
        if self.start_controlled(*args[0]):
            self.out.add("COD008", "high", self.line(m.start()), {"sink": re.sub(r"\s", "", m.group(0)).rstrip("(") + "()"})

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
        for m in _JS_RANDOM.finditer(self.mask):
            start = self.mask.rfind("\n", 0, m.start()) + 1
            head = self.mask[start:m.start()]
            name = None
            d = re.search(r"(?:(?:const|let|var)\s+|this\s*\.\s*|\.)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?\s*[:=](?!=)[^=:]*$", head)
            if d:
                name = d.group(1)
            elif re.match(r"\s*return\b", head):
                fn = None
                for f in re.finditer(r"(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
                                     r"(?:\([^()]*\)|[\w$]+)\s*(?::[^=]+)?=>|^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*(?::[^{]+)?\{)",
                                     self.mask[max(0, m.start() - 1500):m.start()], re.M):
                    fn = f.group(1) or f.group(2) or f.group(3)
                name = fn
            if name and secret_name(name):
                self.out.add("COD010", "low", self.line(m.start()), {"name": name})

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


def scan_js(rel, text, project=None):
    if _minified(text):
        return []
    return _Js(rel, text, project or {}).run()


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


def _skip(rel):
    return rel.endswith((".d.ts", ".min.js", ".bundle.js")) or "/vendor/" in "/" + rel or "/static/vendor/" in rel


def analyze(ctx):
    """Todos os achados de código, calculados uma vez por auditoria (check e ai_check leem daqui)."""
    if _CACHE_KEY in ctx._cache:
        return ctx._cache[_CACHE_KEY]
    out = []
    if ctx.mode != "agents":
        py = [r for r in ctx.files if r.endswith(".py") and is_text_source(r, ctx.mode) and not _skip(r)]
        js = [r for r in ctx.files if r.endswith(_JS_EXT) and is_text_source(r, ctx.mode) and not _skip(r)]
        project = _project(ctx, py, js)
        py_deps = any(_PY_ROUTER_DEPS.search(ctx.read(r)) for r in py if "include_router" in ctx.read(r) or "add_middleware" in ctx.read(r))
        for rel in py:
            text = ctx.read(rel)
            if text and len(text) <= _PY_MAX:
                found = scan_python(rel, text)
                out += [f for f in found if not (f.rule == "APP011" and py_deps)]
        for rel in js:
            text = ctx.read(rel)
            if text and len(text) <= _JS_MAX:
                out += scan_js(rel, text, project)
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
