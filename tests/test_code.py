"""Falhas no código (COD001-COD011) e erros de código que chama modelos ou expõe ferramentas a eles (APP009-APP014).

Cada regra tem o caso que precisa disparar e o quase-acerto que não pode disparar: a consulta com parâmetro, o
comando em lista, o HTML limpo com DOMPurify. Nada aqui roda o código auditado; os arquivos só existem para serem lidos.
"""
import json
import os
import sys
import tempfile
import time
import unittest

from stingward import report, scan
from stingward.checks import code
from stingward.rules import RULES, texts

_DIRS = []


def tearDownModule():
    for d in _DIRS:
        d.cleanup()


def run(files, mode="project", only=("app", "code")):
    d = tempfile.TemporaryDirectory()
    _DIRS.append(d)
    for rel, content in files.items():
        p = os.path.join(d.name, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    return scan.run(d.name, mode=mode, offline=True, only=set(only) if only else None)[1]


NEW = ("COD", "APP009", "APP010", "APP011", "APP012", "APP013", "APP014")


def got(findings):
    return sorted((f.rule, f.file, f.line, f.severity) for f in findings if f.rule.startswith(NEW))


FLASK = "from flask import Flask, request, redirect, url_for, render_template_string, Markup\napp = Flask(__name__)\n"
FASTAPI = "from fastapi import FastAPI, Depends\napp = FastAPI()\n"
EXPRESS = "const express = require('express')\nconst app = express()\n"
OPENAI_PY = "from openai import OpenAI\nclient = OpenAI()\n"


class Checks(unittest.TestCase):
    def check(self, files, want, mode="project"):
        self.assertEqual(got(run(files, mode)), sorted(want))

    def silent(self, files, mode="project"):
        self.assertEqual(got(run(files, mode)), [])


class CodeRules(Checks):

    # ------------------------------------------------------------------ COD001 SQL

    def test_cod001_python_request_in_sql(self):
        src = FLASK + ("import sqlite3\n"
                       "@app.get('/users')\n"
                       "def users():\n"
                       "    cur = sqlite3.connect('db').cursor()\n"
                       "    cur.execute(f\"SELECT * FROM users WHERE name = '{request.args['name']}'\")\n"
                       "    cur.execute(\"SELECT * FROM users WHERE id = \" + request.args['id'])\n")
        self.check({"app.py": src}, [("COD001", "app.py", 7, "high"), ("COD001", "app.py", 8, "high")])

    def test_cod001_fastapi_query_param_and_sqlalchemy_text(self):
        src = FASTAPI + ("from sqlalchemy import text\n"
                         "@app.get('/items')\n"
                         "def items(q: str, db=Depends(get_db)):\n"
                         "    return db.execute(text(f\"SELECT * FROM items WHERE title LIKE '%{q}%'\")).all()\n")
        self.check({"main.py": src}, [("COD001", "main.py", 6, "high")])

    def test_fastapi_body_models_are_request_data(self):
        """request: ChatRequest, req: QueryIn, user: UserCreate: o modelo é o corpo da requisição. O nome do parâmetro e o
        fim "Request" do tipo só dizem "injetado pelo framework" quando o tipo é do framework (Request, Depends)."""
        src = FASTAPI + ("import subprocess, httpx\nfrom typing import Annotated\n"
                         "from fastapi import Request, Body\nfrom starlette.requests import Request as StarletteRequest\n"
                         "from pydantic import BaseModel\n"
                         "class ChatRequest(BaseModel):\n    message: str\n    url: str\n"
                         "@app.post('/chat')\n"
                         "async def chat(request: ChatRequest):\n"
                         "    subprocess.run(request.message, shell=True)\n"
                         "@app.post('/users')\n"
                         "def create(user: 'schemas.UserCreate', db=Depends(get_db)):\n"
                         "    db.execute(f\"INSERT INTO users (name) VALUES ('{user.name}')\")\n"
                         "@app.post('/fetch')\n"
                         "async def fetch(req: Annotated[ChatRequest, Body()]):\n"
                         "    return httpx.get(req.url)\n"
                         "@app.get('/ok')\n"
                         "async def ok(request: Request, raw: StarletteRequest, user: User = Depends(current_user),\n"
                         "             db: Session = Depends(get_db), settings: AppSettings = Depends(get_settings)):\n"
                         "    subprocess.run(request.app.state.cmd + raw.scope['x'] + user.home + settings.cmd, shell=True)\n")
        # Injetados pelo framework: argumento de função (médio), não dado da requisição.
        self.check({"main.py": src}, [("COD002", "main.py", 13, "critical"), ("COD001", "main.py", 16, "high"),
                                      ("COD008", "main.py", 19, "high"), ("COD002", "main.py", 23, "medium")])

    def test_cod001_python_guards_before_the_query(self):
        """if x not in ALLOWED: abort(400), if not x.isdigit(): return, if not re.fullmatch(...): raise: depois do if, o
        valor é um dos permitidos. Um if que não sai da função, ou uma lista que vem da requisição, não protege."""
        src = FLASK + ("import sqlite3, re\nconn = sqlite3.connect('d')\nALLOWED = {'name', 'date'}\n"
                       "@app.get('/a')\ndef a():\n"
                       "    sort = request.args.get('sort')\n"
                       "    if not sort or sort not in ALLOWED:\n"
                       "        abort(400)\n"
                       "    uid = request.args['id']\n"
                       "    if not uid.isdigit():\n"
                       "        return 'bad', 400\n"
                       "    t = request.args['table']\n"
                       "    if not re.fullmatch(r'[a-z_]+', t):\n"
                       "        raise ValueError('bad')\n"
                       "    conn.execute(f'SELECT * FROM {t} WHERE id = {uid} ORDER BY {sort}')\n"
                       "    c = request.args['c']\n"
                       "    if not re.match(r'^[a-z_]+$', c) or not validate_column(c):\n"
                       "        return 'bad', 400\n"
                       "    d = request.args['d']\n"
                       "    if not re.match(r'[a-z_]+', d):\n"
                       "        return 'bad', 400\n"
                       "    conn.execute(f'SELECT {c}, {d} FROM t')\n"
                       "    e = request.args['e']\n"
                       "    if not re.search(r'[a-z_]+$', e):\n"
                       "        return 'bad', 400\n"
                       "    conn.execute(f'SELECT {c}, {e} FROM t')\n"
                       "    w = request.args['w']\n"
                       "    if w not in request.args.getlist('ok'):\n"
                       "        abort(400)\n"
                       "    x = request.args['x']\n"
                       "    if x not in ALLOWED:\n"
                       "        print('odd')\n"
                       "    return str(conn.execute(f\"SELECT * FROM t WHERE w = '{w}' AND x = '{x}'\").fetchall())\n")
        self.check({"app.py": src}, [("COD001", "app.py", 24, "high"), ("COD001", "app.py", 28, "high"),
                                     ("COD001", "app.py", 35, "high")])

    def test_cod001_django_extra(self):
        """QuerySet.extra(where=[...], select={...}, tables=[...]) põe cada pedaço cru no SQL, como RawSQL: o valor de
        fora no meio do texto é injeção. Com %s e params=[...], ou texto fixo, fica quieto."""
        src = ("from django.http import JsonResponse\nfrom .models import Item\n"
               "def search(request):\n"
               "    q = request.GET['q']\n"
               "    a = Item.objects.extra(where=[f\"name = '{q}'\"])\n"
               "    b = Item.objects.extra(select={'x': 'price * ' + request.GET['m']})\n"
               "    c = Item.objects.filter(on=True).extra(tables=[request.GET['t']])\n"
               "    d = Item.objects.extra(where=['name = %s'], params=[q])\n"
               "    e = Item.objects.extra(select={'is_new': 'created > NOW()'}, order_by=['-id'])\n"
               "    return JsonResponse({})\n"
               "def lib(qs, name):\n"
               "    return qs.extra(where=[f\"name = '{name}'\"])\n")
        self.check({"views.py": src}, [("COD001", "views.py", 5, "high"), ("COD001", "views.py", 6, "high"),
                                       ("COD001", "views.py", 7, "high"), ("COD001", "views.py", 12, "medium")])

    def test_cod001_function_argument_in_value_position_is_medium(self):
        src = "def find(conn, name):\n    return conn.execute(f\"SELECT * FROM t WHERE name = '{name}'\")\n"
        f = run({"db.py": src})
        self.assertEqual(got(f), [("COD001", "db.py", 2, "medium")])
        self.assertEqual(f[0].params["source_en"], "a function argument")

    def test_cod001_parameters_orm_and_identifiers_stay_silent(self):
        src = FLASK + ("import sqlite3\n"
                       "TABLE = 'users'\n"
                       "@app.get('/users')\n"
                       "def users():\n"
                       "    cur = sqlite3.connect('db').cursor()\n"
                       "    cur.execute(\"SELECT * FROM users WHERE name = %s\", (request.args['name'],))\n"
                       "    cur.execute(f\"SELECT * FROM {TABLE} WHERE id = ?\", (request.args['id'],))\n"
                       "    return select(User).where(User.name == request.args['name'])\n"
                       "def info(conn, table):\n"
                       "    return conn.execute(f\"PRAGMA table_info('{table}')\")\n"
                       "def count(conn, table):\n"
                       "    return conn.execute(f'SELECT COUNT(*) FROM \"{table}\"')\n")
        self.silent({"app.py": src})

    def test_cod001_js_express(self):
        src = EXPRESS + ("const { Pool } = require('pg')\nconst pool = new Pool()\n"
                         "app.get('/u/:id', async (req, res) => {\n"
                         "  const r = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`)\n"
                         "  const s = await pool.query(\"SELECT * FROM users WHERE name = '\" + req.body.name + \"'\")\n"
                         "  res.json([r.rows, s.rows])\n})\n")
        self.check({"server.js": src}, [("COD001", "server.js", 6, "high"), ("COD001", "server.js", 7, "high")])

    def test_cod001_js_tagged_templates_and_placeholders_stay_silent(self):
        src = ("import { sql } from '@vercel/postgres'\nimport { prisma } from './db'\n"
               "export async function GET(req) {\n"
               "  const id = new URL(req.url).searchParams.get('id')\n"
               "  await sql`SELECT * FROM users WHERE id = ${id}`\n"
               "  await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`\n"
               "  await db.query('SELECT * FROM users WHERE id = $1', [id])\n"
               "  return Response.json({})\n}\n")
        self.silent({"app/api/users/route.ts": src})

    def test_cod001_values_named_like_sql_parts(self):
        """query, count, item.name: entre aspas ou depois de = é valor, não nome de tabela nem pedaço de SQL. Fora dessas
        posições (ORDER BY {order}, FROM {item.model}), vindos de fora, escolhem a coluna ou a tabela (médio)."""
        py = FLASK + ("import sqlite3\ncur = sqlite3.connect('x').cursor()\n"
                      "@app.get('/s')\ndef s():\n"
                      "    query = request.args.get('query', '')\n"
                      "    cur.execute(f\"SELECT * FROM docs WHERE title LIKE '%{query}%'\")\n"
                      "    count = request.args['count']\n"
                      "    cur.execute(f'SELECT * FROM docs WHERE n = {count}')\n"
                      "    order = request.args.get('order', 'id')\n"
                      "    cur.execute(f'SELECT * FROM docs ORDER BY {order}')\n"
                      "    ids = request.json['ids']\n"
                      "    qmarks = ','.join('?' for _ in ids)\n"
                      "    cur.execute(f'SELECT * FROM docs WHERE id IN ({qmarks})', ids)\n"
                      "def lib(conn, query):\n"
                      "    return conn.execute(f\"SELECT * FROM docs WHERE title = '{query}'\")\n")
        api = FASTAPI + ("import sqlite3\nfrom pydantic import BaseModel\ncur = sqlite3.connect('x').cursor()\n"
                         "class Item(BaseModel):\n    name: str\n    model: str\n"
                         "@app.post('/i')\ndef i(item: Item):\n"
                         "    cur.execute(f\"SELECT * FROM t WHERE name = '{item.name}'\")\n"
                         "    cur.execute(f\"SELECT * FROM {item.model}\")\n")
        mcp = ("from mcp.server.fastmcp import FastMCP\nimport sqlite3\nmcp = FastMCP('x')\nconn = sqlite3.connect('d')\n"
               "@mcp.tool()\ndef search(query: str) -> list:\n"
               "    return conn.execute(f\"SELECT * FROM docs WHERE body LIKE '%{query}%'\").fetchall()\n")
        js = EXPRESS + ("const db = require('./db')\n"
                        "app.get('/s', async (req, res) => {\n"
                        "  const query = req.query.q\n"
                        "  const rows = await db.query(`SELECT * FROM docs WHERE title LIKE '%${query}%'`)\n"
                        "  const order = req.query.sort\n"
                        "  const r2 = await db.query(`SELECT * FROM docs ORDER BY ${order}`)\n"
                        "  res.json(rows)\n})\n")
        self.check({"app.py": py, "main.py": api, "server.py": mcp, "server.js": js},
                   [("COD001", "app.py", 8, "high"), ("COD001", "app.py", 10, "high"), ("COD001", "app.py", 12, "medium"),
                    ("COD001", "main.py", 11, "high"), ("COD001", "main.py", 12, "medium"),
                    ("APP014", "server.py", 7, "high"), ("COD001", "server.js", 6, "high"),
                    ("COD001", "server.js", 8, "medium")])

    def test_cod001_names_that_only_end_like_placeholders(self):
        """marks, qmarks, question_marks e questionMarks são placeholders; remarks e bookmarks são o dado do formulário."""
        py = FLASK + ("import sqlite3\nconn = sqlite3.connect('d.db')\n"
                      "@app.post('/n')\ndef n():\n"
                      "    ids = request.json['ids']\n"
                      "    qmarks = ','.join('?' * len(ids))\n"
                      "    question_marks = ','.join(['?'] * len(ids))\n"
                      "    conn.execute(f'SELECT * FROM t WHERE id IN ({qmarks}) OR id IN ({question_marks})', ids + ids)\n"
                      "    remarks = request.form['remarks']\n"
                      "    conn.execute(f\"INSERT INTO notes (remarks) VALUES ('{remarks}')\")\n"
                      "    return 'ok'\n")
        js = EXPRESS + ("const db = require('./db')\n"
                        "app.post('/n', async (req, res) => {\n"
                        "  const questionMarks = req.body.ids.map(() => '?').join(',')\n"
                        "  await db.query(`SELECT * FROM t WHERE id IN (${questionMarks})`, req.body.ids)\n"
                        "  const bookmarks = req.body.bookmarks\n"
                        "  await db.query(`INSERT INTO t (b) VALUES ('${bookmarks}')`)\n"
                        "  res.json({})\n})\n")
        self.check({"app.py": py, "server.js": js}, [("COD001", "app.py", 12, "high"), ("COD001", "server.js", 8, "high")])

    def test_cod001_identifiers_from_outside_are_medium(self):
        """ORDER BY {order}, FROM {table}, LIMIT {limit} com o valor da requisição, do modelo ou da ferramenta: nome de
        coluna ou tabela escolhido de fora (médio). Um pedaço de SQL inteiro (WHERE {where}) é alto. Argumento de função
        com esses nomes, valor conferido numa lista e valor tirado de um dicionário do código continuam quietos."""
        py = FLASK + ("import sqlite3\ncur = sqlite3.connect('x').cursor()\nALLOWED = {'id', 'name'}\n"
                      "SORTS = {'new': 'created_at DESC', 'old': 'created_at'}\n"
                      "@app.get('/s')\ndef s():\n"
                      "    order = request.args.get('order', 'id')\n"
                      "    table = request.args['table']\n"
                      "    cur.execute(f'SELECT * FROM {table} ORDER BY {order}')\n"
                      "    limit = request.args['limit']\n"
                      "    cur.execute('SELECT * FROM t LIMIT ' + limit)\n"
                      "    where = request.args['where']\n"
                      "    cur.execute(f'SELECT * FROM t WHERE {where}')\n"
                      "    sort = request.args.get('sort')\n"
                      "    if sort not in ALLOWED:\n"
                      "        abort(400)\n"
                      "    col = SORTS[request.args['col']]\n"
                      "    c2 = request.args.get('c2')\n"
                      "    columns = c2 if c2 in ALLOWED else 'id'\n"
                      "    cur.execute(f'SELECT {columns} FROM t ORDER BY {sort}, {col}')\n"
                      "    return 'x'\n"
                      "def lib(conn, order, table):\n"
                      "    return conn.execute(f'SELECT * FROM {table} ORDER BY {order}')\n")
        tool = FMCP + ("import sqlite3\nconn = sqlite3.connect('d')\n"
                       "@mcp.tool()\ndef rows(table: str, order: str) -> list:\n"
                       "    return conn.execute(f'SELECT * FROM {table} ORDER BY {order}').fetchall()\n")
        llm = OPENAI_PY + ("import sqlite3\nconn = sqlite3.connect('d')\ndef pick(q):\n"
                           "    r = client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n"
                           "    order = r.choices[0].message.content\n"
                           "    return conn.execute(f'SELECT * FROM t ORDER BY {order}').fetchall()\n")
        js = EXPRESS + ("const db = require('./db')\nconst SORTS = { new: 'created_at DESC', old: 'created_at' }\n"
                        "app.get('/s', async (req, res) => {\n"
                        "  const order = req.query.order\n"
                        "  const table = req.query.table\n"
                        "  await db.query(`SELECT * FROM ${table} ORDER BY ${order}`)\n"
                        "  const where = req.query.where\n"
                        "  await db.query(`SELECT * FROM t WHERE ${where}`)\n"
                        "  const sort = SORTS[req.query.sort] ?? 'id'\n"
                        "  const col = SORTS[req.query.col]\n"
                        "  const dir = req.query.dir\n"
                        "  if (!['asc', 'desc'].includes(dir)) return res.status(400).end()\n"
                        "  await db.query(`SELECT * FROM t ORDER BY ${sort}, ${col} ${dir}`)\n"
                        "  res.json({})\n})\n"
                        "function lib(order, table) {\n  return db.query(`SELECT * FROM ${table} ORDER BY ${order}`)\n}\n")
        jstool = MCPJS + ("const db = require('./db')\n"
                          "server.tool('rows', { table: z.string() }, async ({ table }) => {\n"
                          "  await db.query(`SELECT * FROM ${table}`)\n  return { content: [] }\n})\n")
        self.check({"app.py": py, "tool.py": tool, "llm.py": llm, "server.js": js, "mcp.ts": jstool},
                   [("COD001", "app.py", 11, "medium"), ("COD001", "app.py", 13, "medium"),
                    ("COD001", "app.py", 15, "high"), ("APP014", "tool.py", 7, "medium"),
                    ("APP009", "llm.py", 8, "medium"), ("COD001", "server.js", 8, "medium"),
                    ("COD001", "server.js", 10, "high"), ("APP014", "mcp.ts", 9, "medium")])

    def test_cod001_fix_says_how_to_pick_a_column_or_table_name(self):
        # A column or table name (ORDER BY {order}, medium) cannot be a query parameter: "pass values as parameters"
        # alone does not fix it, so the fix also says to pick the name from a fixed list.
        py = FLASK + ("import sqlite3\ncur = sqlite3.connect('x').cursor()\n@app.get('/s')\ndef s():\n"
                      "    order = request.args.get('order', 'id')\n"
                      "    cur.execute(f'SELECT * FROM docs ORDER BY {order}')\n    return 'x'\n")
        (f,) = [x for x in run({"app.py": py}) if x.rule == "COD001"]
        self.assertEqual(f.severity, "medium")
        pt, en = texts("COD001", "pt", f.params)[2], texts("COD001", "en", f.params)[2]
        self.assertIn("Passe os valores como parâmetros", pt)
        self.assertIn("Pass values as parameters", en)
        self.assertIn("Nome de coluna ou de tabela não pode ser parâmetro: escolha o nome numa lista fixa", pt)
        self.assertIn("A column or table name cannot be a parameter: pick it from a fixed list", en)

    def test_app009_and_app014_fix_says_how_to_pick_a_column_or_table_name(self):
        # The same gap as COD001: a table or column name from a tool argument or from the model (medium) cannot be a
        # query parameter, so the fix also says to pick the name from a fixed list.
        tool = FMCP + ("import sqlite3\nconn = sqlite3.connect('d')\n"
                       "@mcp.tool()\ndef rows(table: str) -> list:\n"
                       "    return conn.execute(f'SELECT * FROM {table}').fetchall()\n")
        llm = OPENAI_PY + ("import sqlite3\nconn = sqlite3.connect('d')\ndef pick(q):\n"
                           "    r = client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n"
                           "    order = r.choices[0].message.content\n"
                           "    return conn.execute(f'SELECT * FROM t ORDER BY {order}').fetchall()\n")
        found = {x.rule: x for x in run({"tool.py": tool, "llm.py": llm}) if x.rule in ("APP009", "APP014")}
        self.assertEqual(sorted(found), ["APP009", "APP014"])
        for rule, f in found.items():
            pt, en = texts(rule, "pt", f.params)[2], texts(rule, "en", f.params)[2]
            self.assertIn("Nome de coluna ou de tabela não pode ser parâmetro: escolha o nome numa lista fixa", pt, rule)
            self.assertIn("A column or table name cannot be a parameter: pick it from a fixed list", en, rule)

    def test_cod001_js_allowlists_before_the_query(self):
        """ALLOWED.includes(x) ? x : 'name', if (!LISTA.includes(x)) return, if (!/^...$/.test(x)) throw: depois disso o
        valor é um dos permitidos. Um if que não sai, uma regex sem âncora ou o outro lado do ? vindo de fora não protegem."""
        src = EXPRESS + ("const db = require('./db')\nconst ALLOWED = ['name', 'date']\nconst SAFE = /^\\w+$/\n"
                         "app.get('/a', async (req, res) => {\n"
                         "  const sort = ALLOWED.includes(req.query.sort) ? req.query.sort : 'name'\n"
                         "  const dir = req.query.dir\n"
                         "  if (!['asc', 'desc'].includes(dir)) return res.status(400).end()\n"
                         "  const col = req.query.col\n"
                         "  if (!/^[a-z_]+$/.test(col)) {\n"
                         "    throw new Error('bad')\n"
                         "  }\n"
                         "  const rows = await db.query(`SELECT ${col} FROM t ORDER BY ${sort} ${dir}`)\n"
                         "  const x = req.query.x\n"
                         "  if (!ALLOWED.includes(x)) console.log('odd')\n"
                         "  const y = req.query.y\n"
                         "  if (!/[a-z]+/.test(y)) return res.end()\n"
                         "  const z = ALLOWED.includes(req.query.z) ? req.query.z : req.query.w\n"
                         "  const k = req.query.k\n"
                         "  if (!SAFE.test(k)) return res.end()\n"
                         "  await db.query(`SELECT * FROM t ORDER BY ${k}`)\n"
                         "  const w = req.query.w\n"
                         "  if (!req.body.allowed.includes(w)) return res.end()\n"
                         "  await db.query(`SELECT * FROM t ORDER BY ${w}`)\n"
                         "  await db.query(`SELECT * FROM t ORDER BY ${x}`)\n"
                         "  await db.query(`SELECT * FROM t ORDER BY ${y}`)\n"
                         "  await db.query(`SELECT * FROM t ORDER BY ${z}`)\n"
                         "  res.json(rows)\n})\n")
        self.check({"server.js": src}, [("COD001", "server.js", 25, "high"), ("COD001", "server.js", 26, "high"),
                                        ("COD001", "server.js", 27, "high"), ("COD001", "server.js", 28, "high")])

    def test_cod001_js_placeholder_lists_stay_silent(self):
        """ids.map(() => '?').join(','): a lista de placeholders herda a origem de ids, mas o texto dela é fixo. O
        JavaScript conhece os mesmos nomes de placeholder que o Python (marks, ph, qs) e olha o valor declarado."""
        src = EXPRESS + ("const db = require('./db')\n"
                         "app.post('/s', async (req, res) => {\n"
                         "  const ids = req.body.ids\n"
                         "  const marks = ids.map(() => '?').join(',')\n"
                         "  await db.query(`SELECT * FROM t WHERE id IN (${marks})`, ids)\n"
                         "  const ph = ids.map((_, i) => `$${i + 1}`).join(', ')\n"
                         "  await db.query(`SELECT * FROM t WHERE id IN (${ph})`, ids)\n"
                         "  const inList = ids.map(() => '?').join(',')\n"
                         "  await db.query('SELECT * FROM t WHERE id IN (' + inList + ')', ids)\n"
                         "  const names = req.body.names.join(\"','\")\n"
                         "  await db.query(`SELECT * FROM t WHERE name IN ('${names}')`)\n"
                         "  await db.query(`SELECT * FROM t WHERE name = '${req.body.bookmarks}'`)\n"
                         "  const quoted = req.body.names.map((n) => `'${n}'`).join(',')\n"
                         "  await db.query(`SELECT * FROM t WHERE name IN (${quoted})`)\n"
                         "  await db.query(`SELECT * FROM t WHERE name IN (${req.body.names.map((n) => `'${n}'`).join(',')})`)\n"
                         "  res.json({})\n})\n")
        self.check({"server.js": src}, [("COD001", "server.js", 13, "high"), ("COD001", "server.js", 14, "high"),
                                        ("COD001", "server.js", 16, "high"), ("COD001", "server.js", 17, "high")])

    # ------------------------------------------------------------------ COD002 comando

    def test_cod002_python_shell_with_request_input(self):
        src = FLASK + ("import os, subprocess\n"
                       "@app.post('/ping')\n"
                       "def ping():\n"
                       "    subprocess.run(f\"ping -c 1 {request.form['host']}\", shell=True)\n"
                       "    os.system('convert ' + request.args['file'])\n")
        self.check({"app.py": src}, [("COD002", "app.py", 6, "critical"), ("COD002", "app.py", 7, "critical")])

    def test_cod002_python_argument_list_and_cli_stay_silent(self):
        src = FLASK + ("import os, subprocess, click\n"
                       "@app.post('/ping')\n"
                       "def ping():\n"
                       "    subprocess.run(['ping', '-c', '1', request.form['host']])\n"
                       "    subprocess.run('git status', shell=True)\n"
                       "@app.cli.command()\n"
                       "@click.argument('lang')\n"
                       "def init(lang):\n"
                       "    os.system('pybabel init -l ' + lang)\n")
        self.silent({"app.py": src})

    def test_cod002_js_exec_with_request_input(self):
        src = EXPRESS + ("const { exec, execFile } = require('child_process')\n"
                         "app.get('/ls', (req, res) => {\n"
                         "  exec(`ls -la ${req.query.dir}`, (e, out) => res.send(out))\n"
                         "})\n")
        self.check({"server.js": src}, [("COD002", "server.js", 5, "critical")])

    def test_cod002_js_execfile_and_fixed_command_stay_silent(self):
        src = EXPRESS + ("import { execFile, exec } from 'node:child_process'\n"
                         "app.get('/ls', (req, res) => {\n"
                         "  execFile('ls', ['-la', req.query.dir], (e, out) => res.send(out))\n"
                         "  exec('git rev-parse HEAD')\n"
                         "  // exec(req.query.cmd)\n"
                         "  const help = 'exec(req.query.cmd)'\n"
                         "})\n")
        self.silent({"server.js": src})

    # ------------------------------------------------------------------ COD003 código

    def test_cod003_eval_and_template_from_request(self):
        src = FLASK + ("@app.get('/calc')\n"
                       "def calc():\n"
                       "    return str(eval(request.args['expr']))\n"
                       "@app.get('/hello')\n"
                       "def hello():\n"
                       "    return render_template_string('<h1>' + request.args['name'] + '</h1>')\n")
        f = run({"app.py": src})
        self.assertEqual(got(f), [("COD003", "app.py", 5, "critical"), ("COD003", "app.py", 8, "critical")])

    def test_cod003_python_repr_quotes_the_value(self):
        """{v!r} e repr(v) escrevem o valor como um literal do Python: exec(f"x = {v!r}") e python -c com ele não rodam o
        texto. Sem o !r o texto vira código; num template (Jinja) o repr não protege."""
        src = FLASK + ("import subprocess, sys\n"
                       "@app.post('/a')\ndef a():\n"
                       "    v = request.json['v']\n"
                       "    exec(f'x = {v!r}')\n"
                       "    exec('x = ' + repr(v))\n"
                       "    subprocess.run([sys.executable, '-c', f'print({v!r})'])\n"
                       "    exec(f'x = {v}')\n"
                       "    exec(f'x = {v!r}; y = {v}')\n"
                       "    return render_template_string(f'<p>{v!r}</p>')\n")
        self.check({"app.py": src}, [("COD003", "app.py", 10, "critical"), ("COD003", "app.py", 11, "critical"),
                                     ("COD003", "app.py", 12, "critical")])

    def test_cod003_js_eval_and_new_function(self):
        src = EXPRESS + ("app.post('/run', (req, res) => {\n"
                         "  const out = eval(req.body.code)\n"
                         "  const fn = new Function('return ' + req.query.expr)\n"
                         "  setTimeout(() => res.json({ out, fn }), 10)\n"
                         "})\n")
        self.check({"server.js": src}, [("COD003", "server.js", 4, "critical"), ("COD003", "server.js", 5, "critical")])

    def test_cod003_literal_eval_and_constants_stay_silent(self):
        src = FLASK + ("import ast\n"
                       "@app.get('/calc')\n"
                       "def calc():\n"
                       "    eval('1 + 1')\n"
                       "    return str(ast.literal_eval(request.args['expr']))\n")
        self.silent({"app.py": src})
        self.silent({"server.js": EXPRESS + "app.post('/x', (req, res) => res.json(JSON.parse(req.body.data)))\n"})

    # ------------------------------------------------------------------ COD004 desserialização

    def test_cod004_pickle_and_yaml(self):
        src = FLASK + ("import pickle, yaml, requests\n"
                       "@app.post('/load')\n"
                       "def load():\n"
                       "    a = pickle.loads(request.data)\n"
                       "    b = yaml.load(request.data, Loader=yaml.Loader)\n"
                       "    c = pickle.loads(requests.get('https://example.com/model').content)\n"
                       "    d = yaml.load(open('config.yml'))\n"
                       "    return 'ok'\n")
        self.check({"app.py": src}, [("COD004", "app.py", 6, "high"), ("COD004", "app.py", 7, "high"),
                                     ("COD004", "app.py", 8, "medium"), ("COD004", "app.py", 9, "low")])

    def test_cod004_safe_loaders_and_local_pickle_stay_silent(self):
        src = FLASK + ("import pickle, yaml\n"
                       "@app.post('/load')\n"
                       "def load():\n"
                       "    a = yaml.safe_load(request.data)\n"
                       "    b = yaml.load(request.data, Loader=yaml.SafeLoader)\n"
                       "    c = pickle.load(open('cache.pkl', 'rb'))\n"
                       "    return 'ok'\n")
        self.silent({"app.py": src})
        ruamel = "from ruamel.yaml import YAML\n\ndef read(path):\n    yaml = YAML()\n    return yaml.load(open(path))\n"
        self.silent({"conf.py": ruamel})

    def test_cod004_safe_loader_subclass_in_the_file(self):
        """class StrictLoader(yaml.SafeLoader): o loader do próprio arquivo herda o modo seguro (também em dois passos).
        Herdar de yaml.Loader continua perigoso."""
        src = ("import yaml\nfrom yaml import CSafeLoader\n"
               "class StrictLoader(yaml.SafeLoader):\n    pass\n"
               "class Strict2Loader(StrictLoader):\n    pass\n"
               "class FastLoader(CSafeLoader):\n    pass\n"
               "class DangerLoader(yaml.Loader):\n    pass\n"
               "def a(text):\n    return yaml.load(text, Loader=StrictLoader)\n"
               "def b(text):\n    return yaml.load(text, Strict2Loader)\n"
               "def c(text):\n    return yaml.load(text, Loader=FastLoader)\n"
               "def d(text):\n    return yaml.load(text, Loader=DangerLoader)\n")
        self.check({"conf.py": src}, [("COD004", "conf.py", 18, "medium")])

    # ------------------------------------------------------------------ COD005 XSS

    def test_cod005_js_request_input_in_html(self):
        page = ("'use client'\nimport { useSearchParams } from 'next/navigation'\n"
                "export default function Page() {\n"
                "  const q = useSearchParams().get('q')\n"
                "  return <div dangerouslySetInnerHTML={{ __html: q }} />\n}\n")
        dom = "const box = document.getElementById('box')\nbox.innerHTML = location.hash.slice(1)\n" \
              "box.innerHTML = `<b>${user.name}</b>`\n"
        self.check({"app/page.tsx": page, "public/app.js": dom},
                   [("COD005", "app/page.tsx", 5, "medium"), ("COD005", "public/app.js", 2, "medium"),
                    ("COD005", "public/app.js", 3, "low")])

    def test_cod005_sanitized_text_and_static_html_stay_silent(self):
        page = ("import DOMPurify from 'dompurify'\n"
                "export default function Page({ html, q }) {\n"
                "  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}>{q}</div>\n}\n")
        dom = ("el.textContent = location.hash\n"
               "el.innerHTML = '<b>loading</b>'\n"
               "el.innerHTML = `<img src=\"${location.origin}/logo.png\">`\n")
        self.silent({"app/page.tsx": page, "public/app.js": dom})

    def test_cod005_markup_words_in_the_html_do_not_hide_input(self):
        """icon, svg, style e css no código dizem "isto monta um ícone ou um estilo"; no HTML fixo (class="icon",
        style="...") não dizem nada sobre o valor que entra."""
        dom = ("const box = document.getElementById('box')\n"
               "box.innerHTML = `<span class=\"icon\">${location.hash.slice(1)}</span>`\n"
               "box.innerHTML = '<div style=\"color:red\">' + location.search + '</div>'\n"
               "box.innerHTML = `<svg viewBox=\"0 0 24 24\">${iconPath}</svg>`\n"
               "box.innerHTML = renderIcon(location.hash)\n"
               "box.innerHTML = DOMPurify.sanitize(`<b class=\"x\">${location.hash}</b>`)\n"
               "box.innerHTML = `<i class=\"icon\"></i>${data.choices[0].message.content}`\n")
        self.check({"public/app.js": dom}, [("COD005", "public/app.js", 2, "medium"),
                                            ("COD005", "public/app.js", 3, "medium"),
                                            ("APP009", "public/app.js", 7, "medium")])

    def test_cod005_python_html_response(self):
        src = FLASK + ("@app.get('/hi')\n"
                       "def hi():\n"
                       "    return f\"<h1>Hello {request.args['name']}</h1>\"\n"
                       "@app.get('/bye')\n"
                       "def bye():\n"
                       "    return Markup(request.args['msg'])\n"
                       "@app.get('/ok')\n"
                       "def ok():\n"
                       "    return render_template('x.html', name=request.args['name'])\n")
        self.check({"app.py": src}, [("COD005", "app.py", 5, "medium"), ("COD005", "app.py", 8, "medium")])

    def test_cod005_svelte_html_block(self):
        src = ("<script>\n  import { page } from '$app/stores'\n  $: q = $page.url.searchParams.get('q')\n</script>\n"
               "{@html q}\n{@html DOMPurify.sanitize(q)}\n<p>{q}</p>\n")
        self.check({"src/routes/+page.svelte": src}, [("COD005", "src/routes/+page.svelte", 5, "medium")])

    # ------------------------------------------------------------------ COD006 TLS

    def test_cod006_python_verify_off(self):
        src = ("import requests, ssl\n"
               "r = requests.get('https://example.com', verify=False)\n"
               "s = requests.Session()\n"
               "s.verify = False\n"
               "ctx = ssl._create_unverified_context()\n"
               "ok = requests.get('https://example.com', verify='/etc/ssl/ca.pem')\n")
        self.check({"fetch.py": src}, [("COD006", "fetch.py", 2, "medium"), ("COD006", "fetch.py", 4, "medium"),
                                       ("COD006", "fetch.py", 5, "medium")])

    def test_cod006_js_and_env(self):
        src = ("const https = require('https')\n"
               "const agent = new https.Agent({ rejectUnauthorized: false })\n"
               "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'\n"
               "const strict = new https.Agent({ rejectUnauthorized: true })\n"
               "if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') console.warn('insecure')\n")
        self.check({"lib/http.js": src, ".env": "NODE_TLS_REJECT_UNAUTHORIZED=0\n", ".env.example": "PYTHONHTTPSVERIFY=1\n"},
                   [("COD006", "lib/http.js", 2, "medium"), ("COD006", "lib/http.js", 3, "medium"),
                    ("COD006", ".env", 1, "medium")])

    # ------------------------------------------------------------------ COD007 caminho

    def test_cod007_python_path_from_request(self):
        src = FASTAPI + ("import os\nfrom fastapi.responses import FileResponse\n"
                         "@app.get('/download')\n"
                         "def download(name: str):\n"
                         "    return FileResponse(os.path.join('files', name))\n"
                         "@app.post('/read')\n"
                         "def read(body: dict):\n"
                         "    with open('uploads/' + body['file']) as f:\n"
                         "        return f.read()\n")
        self.check({"main.py": src}, [("COD007", "main.py", 7, "high"), ("COD007", "main.py", 10, "high")])

    def test_cod007_python_guarded_segment_and_admin_stay_silent(self):
        src = FASTAPI + ("import os\nfrom pathlib import Path\nfrom fastapi.responses import FileResponse\n"
                         "from werkzeug.utils import secure_filename\nBASE = Path('files').resolve()\n"
                         "@app.get('/a')\n"
                         "def a(name: str):\n"
                         "    return FileResponse(os.path.join('files', secure_filename(name)))\n"
                         "@app.get('/b')\n"
                         "def b(name: str):\n"
                         "    p = (BASE / name).resolve()\n"
                         "    if not p.is_relative_to(BASE):\n"
                         "        raise ValueError(name)\n"
                         "    return FileResponse(p)\n"
                         "@app.get('/report/{report_id}')\n"
                         "def c(report_id: str):\n"
                         "    return FileResponse(os.path.join('out', f'{report_id}.pdf'))\n"
                         "@app.get('/admin/logs')\n"
                         "def d(name: str, user=Depends(get_admin_user)):\n"
                         "    return FileResponse(os.path.join('logs', name))\n"
                         "@app.get('/files/{item_id}')\n"
                         "def e(item_id: str, db=Depends(get_db)):\n"
                         "    item = db.get_file_by_id(item_id)\n"
                         "    return FileResponse(item.path)\n")
        self.silent({"main.py": src})

    def test_cod007_extension_of_the_uploaded_name_stays_silent(self):
        """os.path.splitext(file.filename)[1] não tem / nem ..: num nome que o código montou (uuid + extensão), quem manda
        o arquivo só escolhe o .png. O resto do nome (root, split('.')[-1], o nome inteiro) continua alto."""
        src = FASTAPI + ("import os, uuid, subprocess\nfrom fastapi import UploadFile, File\nUPLOAD_DIR = 'uploads'\n"
                         "@app.post('/a')\nasync def a(file: UploadFile = File(...)):\n"
                         "    ext = os.path.splitext(file.filename)[1].lower()\n"
                         "    path = os.path.join(UPLOAD_DIR, f'{uuid.uuid4()}{ext}')\n"
                         "    with open(path, 'wb') as f:\n"
                         "        f.write(await file.read())\n"
                         "    with open(os.path.join(UPLOAD_DIR, str(uuid.uuid4()) + os.path.splitext(file.filename)[-1]), 'wb') as f:\n"
                         "        f.write(b'')\n"
                         "    name = uuid.uuid4().hex\n"
                         "    root, ext2 = os.path.splitext(file.filename)\n"
                         "    name += ext2\n"
                         "    open(os.path.join(UPLOAD_DIR, name), 'wb').close()\n"
                         "    subprocess.run(f'convert in{ext} out.png', shell=True)\n"
                         "@app.post('/b')\nasync def b(file: UploadFile = File(...)):\n"
                         "    root, ext = os.path.splitext(file.filename)\n"
                         "    open(os.path.join(UPLOAD_DIR, root + ext), 'wb').close()\n"
                         "    tail = file.filename.split('.')[-1]\n"
                         "    open(os.path.join(UPLOAD_DIR, f'{uuid.uuid4()}.{tail}'), 'wb').close()\n"
                         "    ext = file.filename\n"
                         "    open(os.path.join(UPLOAD_DIR, ext), 'wb').close()\n")
        self.check({"main.py": src}, [("COD002", "main.py", 18, "critical"), ("COD007", "main.py", 22, "high"),
                                      ("COD007", "main.py", 24, "high"), ("COD007", "main.py", 26, "high")])

    def test_cod007_js_path_from_request(self):
        src = EXPRESS + ("const fs = require('fs')\nconst path = require('path')\n"
                         "app.get('/f', (req, res) => {\n"
                         "  fs.readFile(path.join(__dirname, 'files', req.query.name), (e, d) => res.send(d))\n"
                         "})\n"
                         "app.get('/g/:name', (req, res) => res.sendFile(req.params.name))\n")
        self.check({"server.js": src}, [("COD007", "server.js", 6, "high"), ("COD007", "server.js", 8, "high")])

    def test_cod007_js_named_fs_imports(self):
        """import { writeFile } from 'fs/promises', const { readFileSync } = require('fs'): o "fs" só aparece no texto
        entre aspas, que a máscara apaga; a função chamada sozinha é a mesma do fs."""
        route = ("import { writeFile, readFile } from 'fs/promises'\nimport path from 'path'\n"
                 "export async function POST(request) {\n"
                 "  const data = await request.formData()\n"
                 "  const file = data.get('file')\n"
                 "  await writeFile(path.join(process.cwd(), 'public', 'uploads', file.name), Buffer.from(await file.arrayBuffer()))\n"
                 "  const txt = await readFile(path.join(process.cwd(), 'data', data.get('name')), 'utf8')\n"
                 "  return Response.json({ txt })\n}\n")
        server = EXPRESS + ("const { readFileSync } = require('fs')\n"
                            "app.get('/f', (req, res) => res.send(readFileSync('files/' + req.query.name)))\n")
        self.check({"app/api/upload/route.ts": route, "server.js": server},
                   [("COD007", "app/api/upload/route.ts", 6, "high"), ("COD007", "app/api/upload/route.ts", 7, "high"),
                    ("COD007", "server.js", 4, "high")])

    def test_cod007_js_basename_root_and_upload_path_stay_silent(self):
        src = EXPRESS + ("const fs = require('fs')\nconst path = require('path')\n"
                         "app.get('/f', (req, res) => {\n"
                         "  fs.readFile(path.join('files', path.basename(req.query.name)), (e, d) => res.send(d))\n"
                         "})\n"
                         "app.get('/g/:name', (req, res) => res.sendFile(req.params.name, { root: 'public' }))\n"
                         "app.post('/up', upload.single('f'), async (req, res) => {\n"
                         "  const data = await fs.promises.readFile(req.file.path)\n"
                         "  await fs.promises.unlink(req.file.path)\n"
                         "  res.json({ size: data.length })\n"
                         "})\n")
        self.silent({"server.js": src})

    # ------------------------------------------------------------------ COD008 SSRF

    def test_cod008_server_fetches_request_url(self):
        py = FLASK + "import requests\n@app.get('/proxy')\ndef proxy():\n    return requests.get(request.args['url']).text\n"
        js = ("export async function GET(req) {\n"
              "  const target = new URL(req.url).searchParams.get('url')\n"
              "  const r = await fetch(target)\n"
              "  return new Response(await r.text())\n}\n")
        self.check({"app.py": py, "app/api/proxy/route.ts": js},
                   [("COD008", "app.py", 6, "high"), ("COD008", "app/api/proxy/route.ts", 3, "high")])

    def test_cod008_fixed_host_guard_and_browser_stay_silent(self):
        py = FLASK + ("import requests\nfrom urllib.parse import urlparse\n"
                      "@app.get('/item')\n"
                      "def item():\n"
                      "    return requests.get(f\"https://api.example.com/items/{request.args['id']}\").text\n"
                      "@app.get('/proxy')\n"
                      "def proxy():\n"
                      "    url = request.args['url']\n"
                      "    if urlparse(url).hostname not in ALLOWED_HOSTS:\n"
                      "        return 'no', 400\n"
                      "    return requests.get(url).text\n")
        js = ("'use client'\nexport default function Search() {\n"
              "  const q = useSearchParams().get('url')\n"
              "  useEffect(() => { fetch(q) }, [q])\n  return null\n}\n")
        self.silent({"app.py": py, "app/search/page.tsx": js})

    def test_cod008_base_address_in_a_variable_stays_silent(self):
        """full = BASE + caminho; requests.get(full): o começo do endereço é o do código, como em f"{BASE}/{caminho}".
        Quando o começo vem da requisição (u + '/x'), continua alto."""
        py = FLASK + ("import requests\nBASE = 'https://api.example.com'\n"
                      "@app.get('/a')\ndef a():\n"
                      "    path = request.args['p']\n"
                      "    full = BASE + path\n"
                      "    r = requests.get(full)\n"
                      "    return requests.get(BASE + path).text + r.text\n"
                      "@app.get('/b')\ndef b():\n"
                      "    u = request.args['u']\n"
                      "    full = u + '/x'\n"
                      "    return requests.get(full).text\n")
        js = ("const BASE = 'https://api.example.com'\nconst SUFFIX = '/v1'\n"
              "export async function GET(req) {\n"
              "  const { searchParams } = new URL(req.url)\n"
              "  const p = searchParams.get('p')\n"
              "  const full = BASE + p\n"
              "  const a = await fetch(full)\n"
              "  const target = searchParams.get('url')\n"
              "  const full2 = target + SUFFIX\n"
              "  const b = await fetch(full2)\n"
              "  return new Response((await a.text()) + (await b.text()))\n}\n")
        self.check({"app.py": py, "app/api/proxy/route.ts": js},
                   [("COD008", "app.py", 15, "high"), ("COD008", "app/api/proxy/route.ts", 10, "high")])

    def test_cod008_host_written_into_the_address(self):
        """f"https://{host}/x", "https://" + t + ".example.com": o texto fixo para antes do fim do host, então quem manda o
        valor escolhe o servidor (t = "evil.com/?" ou "@evil.com"). Depois da primeira / é só caminho. No redirect para
        https://{Host}/ (de http para https) o cabeçalho é do próprio navegador: fica quieto."""
        py = FLASK + ("import requests\n"
                      "@app.get('/a')\ndef a():\n"
                      "    host = request.args['h']\n"
                      "    r = requests.get(f'https://{host}/v1/x')\n"
                      "    s = requests.get(f\"http://localhost:{request.args['port']}/x\")\n"
                      "    t = requests.get('https://' + request.args['t'] + '.example.com/x')\n"
                      "    u = requests.get(f'https://api.example.com/{host}?q={host}')\n"
                      "    return r.text + s.text + t.text + u.text\n"
                      "@app.get('/b')\ndef b():\n"
                      "    return redirect(f\"https://{request.headers['Host']}{request.full_path}\")\n")
        express = EXPRESS + ("app.use((req, res, next) => {\n"
                             "  if (!req.secure) return res.redirect('https://' + req.headers.host + req.url)\n"
                             "  next()\n})\n")
        js = ("export async function GET(req) {\n"
              "  const { searchParams } = new URL(req.url)\n"
              "  const host = searchParams.get('h')\n"
              "  const a = await fetch(`https://${host}/v1/x`)\n"
              "  const b = await fetch('https://' + searchParams.get('t') + '.example.com/x')\n"
              "  const c = await fetch(`https://api.example.com/${host}`)\n"
              "  return new Response((await a.text()) + (await b.text()) + (await c.text()))\n}\n")
        mcp = FMCP + ("import httpx\n@mcp.tool()\nasync def get(region: str, path: str) -> str:\n"
                      "    a = httpx.get(f'https://{region}.api.example.com/v1')\n"
                      "    b = httpx.get(f'https://api.example.com/{path}')\n"
                      "    return a.text + b.text\n")
        f = run({"app.py": py, "app/api/proxy/route.ts": js, "server.py": mcp, "web.js": express})
        self.assertEqual(got(f), [("APP014", "server.py", 6, "medium"), ("COD008", "app.py", 7, "high"),
                                  ("COD008", "app.py", 8, "high"), ("COD008", "app.py", 9, "high"),
                                  ("COD008", "app/api/proxy/route.ts", 4, "high"),
                                  ("COD008", "app/api/proxy/route.ts", 5, "high")])
        self.assertEqual([x.params["kind"] for x in f if x.rule == "APP014"], ["url"])

    def test_cod008_host_from_the_host_header_is_medium(self):
        """Host tirado do cabeçalho Host ou X-Forwarded-Host: o navegador de outra pessoa não escolhe esse cabeçalho e
        o proxy na frente costuma conferir, mas quem chama o servidor direto pode trocar (médio). Host vindo da busca,
        do corpo ou de outro cabeçalho continua alto, também quando o cabeçalho Host só é a segunda opção."""
        py = FLASK + ("import requests\n"
                      "@app.get('/a')\ndef a():\n"
                      "    r = requests.get(f\"https://{request.headers['Host']}/api/x\")\n"
                      "    host = request.headers.get('x-forwarded-host') or request.headers.get('host')\n"
                      "    s = requests.get(f'https://{host}/api/y')\n"
                      "    t = requests.get(f\"https://{request.args['h']}/api/z\")\n"
                      "    u = requests.get(f\"https://{request.headers['X-Tenant']}.example.com/\")\n"
                      "    h2 = request.args.get('h') or request.headers.get('host')\n"
                      "    v = requests.get(f'https://{h2}/api/w')\n"
                      "    return r.text + s.text + t.text + u.text + v.text\n")
        js = ("export async function GET(request) {\n"
              "  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host')\n"
              "  const a = await fetch(`https://${host}/api/a`)\n"
              "  const b = await fetch(`https://${request.headers.get('host')}/api/b`)\n"
              "  const { searchParams } = new URL(request.url)\n"
              "  const c = await fetch(`https://${searchParams.get('h')}/api/c`)\n"
              "  return new Response((await a.text()) + (await b.text()) + (await c.text()))\n}\n")
        express = EXPRESS + ("const axios = require('axios')\n"
                             "app.get('/p', async (req, res) => {\n"
                             "  const r = await axios.get('https://' + req.headers.host + '/internal')\n"
                             "  res.json(r.data)\n})\n")
        self.check({"app.py": py, "app/api/proxy/route.ts": js, "web.js": express},
                   [("COD008", "app.py", 6, "medium"), ("COD008", "app.py", 8, "medium"), ("COD008", "app.py", 9, "high"),
                    ("COD008", "app.py", 10, "high"), ("COD008", "app.py", 12, "high"),
                    ("COD008", "app/api/proxy/route.ts", 3, "medium"), ("COD008", "app/api/proxy/route.ts", 4, "medium"),
                    ("COD008", "app/api/proxy/route.ts", 6, "high"), ("COD008", "web.js", 5, "medium")])

    def test_cod008_search_params_held_in_a_variable(self):
        """const sp = new URL(req.url).searchParams; sp.get('url'): a busca da requisição com outro nome. A busca de um
        endereço escrito no código não é da requisição."""
        js = ("export async function GET(req) {\n"
              "  const sp = new URL(req.url).searchParams\n"
              "  const params = req.nextUrl.searchParams\n"
              "  const a = await fetch(sp.get('url'))\n"
              "  const b = await fetch(params.get('next') ?? '/')\n"
              "  const own = new URL('https://api.example.com/x?a=1').searchParams\n"
              "  const c = await fetch(own.get('a'))\n"
              "  return new Response((await a.text()) + (await b.text()) + (await c.text()))\n}\n")
        self.check({"app/api/proxy/route.ts": js},
                   [("COD008", "app/api/proxy/route.ts", 4, "high"), ("COD008", "app/api/proxy/route.ts", 5, "high")])

    # ------------------------------------------------------------------ COD009 redirect

    def test_cod009_redirect_to_request_address(self):
        py = FLASK + "@app.get('/login')\ndef login():\n    return redirect(request.args.get('next'))\n"
        js = EXPRESS + "app.get('/done', (req, res) => res.redirect(req.query.returnTo))\n"
        self.check({"app.py": py, "server.js": js}, [("COD009", "app.py", 5, "medium"), ("COD009", "server.js", 3, "medium")])

    def test_cod009_internal_paths_stay_silent(self):
        py = FLASK + ("@app.get('/login')\ndef login():\n"
                      "    return redirect(url_for('profile', name=request.args['user']))\n"
                      "@app.get('/u')\ndef u():\n"
                      "    return redirect('/users/' + request.args['id'])\n")
        js = EXPRESS + ("app.get('/a', (req, res) => res.redirect('/login'))\n"
                        "app.get('/b/:id', (req, res) => res.redirect(`/items/${req.params.id}`))\n")
        self.silent({"app.py": py, "server.js": js})

    def test_cod009_protocol_relative_redirect(self):
        """redirect("/" + next): com next = "/evil.com", o navegador vai para //evil.com, outro site. Só barras (/, \\, //)
        na frente não prendem o endereço no site; /users/ com mais texto depois da barra prende."""
        py = FLASK + ("@app.get('/a')\ndef a():\n    return redirect(f\"/{request.args['next']}\")\n"
                      "@app.get('/b')\ndef b():\n    return redirect('\\\\' + request.args['next'])\n"
                      "@app.get('/c')\ndef c():\n    return redirect('//' + request.args['host'] + '/home')\n"
                      "@app.get('/d')\ndef d():\n    return redirect(f\"/users/{request.args['id']}\")\n")
        js = EXPRESS + ("app.get('/a', (req, res) => res.redirect(`/${req.query.next}`))\n"
                        "app.get('/b', (req, res) => res.redirect('/' + req.query.next))\n"
                        "app.get('/c', (req, res) => res.redirect(`/items/${req.query.id}`))\n")
        self.check({"app.py": py, "server.js": js},
                   [("COD009", "app.py", 5, "medium"), ("COD009", "app.py", 8, "medium"), ("COD009", "app.py", 11, "medium"),
                    ("COD009", "server.js", 3, "medium"), ("COD009", "server.js", 4, "medium")])

    def test_cod009_host_from_the_request_after_a_fixed_scheme(self):
        """redirect("https://" + request.args["host"]): quem monta o link escolhe o site. O host do cabeçalho Host ou
        X-Forwarded-Host é o do próprio site (o navegador de outra pessoa não escolhe), e um host fixo prende o endereço."""
        py = FLASK + ("@app.get('/a')\ndef a():\n    return redirect('https://' + request.args['host'])\n"
                      "@app.post('/b')\ndef b():\n    return redirect(f\"https://{request.form['host']}/home\")\n"
                      "@app.get('/c')\ndef c():\n    return redirect('https://{}.example.com/'.format(request.args['tenant']))\n"
                      "@app.post('/d')\ndef d():\n    host = request.json.get('host')\n    return redirect('https://' + host + '/x')\n"
                      "@app.get('/e')\ndef e():\n    return redirect('https://' + request.headers['Host'] + '/login')\n"
                      "@app.get('/f')\ndef f():\n    return redirect(f\"https://{request.headers.get('X-Forwarded-Host')}/x\")\n"
                      "@app.get('/g')\ndef g():\n    return redirect('https://example.com/' + request.args['path'])\n"
                      "@app.get('/h')\ndef h():\n    return redirect(f\"https://example.com/{request.args['path']}\")\n")
        js = EXPRESS + ("app.get('/a', (req, res) => res.redirect('https://' + req.query.host))\n"
                        "app.post('/b', (req, res) => res.redirect(`https://${req.body.host}/home`))\n"
                        "app.get('/c', (req, res) => {\n  const host = req.query.host\n  res.redirect(302, `https://${host}/x`)\n})\n"
                        "app.get('/d', (req, res) => res.redirect(`https://${req.headers.host}/login`))\n"
                        "app.get('/e', (req, res) => res.redirect('https://' + req.get('x-forwarded-host') + '/x'))\n"
                        "app.get('/f', (req, res) => res.redirect(`https://${req.headers['x-forwarded-host']}/x`))\n"
                        "app.get('/g', (req, res) => res.redirect('https://example.com/' + req.query.path))\n"
                        "app.get('/h', (req, res) => res.redirect(`https://example.com/${req.query.path}`))\n")
        self.check({"app.py": py, "server.js": js},
                   [("COD009", "app.py", 5, "medium"), ("COD009", "app.py", 8, "medium"), ("COD009", "app.py", 11, "medium"),
                    ("COD009", "app.py", 15, "medium"),
                    ("COD009", "server.js", 3, "medium"), ("COD009", "server.js", 4, "medium"),
                    ("COD009", "server.js", 7, "medium")])

    # ------------------------------------------------------------------ COD010 aleatório

    def test_cod010_weak_random_for_secrets(self):
        py = ("import random, string\n"
              "reset_token = ''.join(random.choices(string.ascii_letters, k=32))\n"
              "def make_api_key():\n"
              "    return str(random.random())\n")
        js = "const apiKey = Math.random().toString(36).slice(2)\nconst password = Math.random().toString(36)\n"
        self.check({"auth.py": py, "lib/keys.js": js},
                   [("COD010", "auth.py", 2, "low"), ("COD010", "auth.py", 4, "low"),
                    ("COD010", "lib/keys.js", 1, "low"), ("COD010", "lib/keys.js", 2, "low")])

    def test_cod010_non_secrets_crypto_and_tests_stay_silent(self):
        py = "import random, secrets\njitter = random.random()\nreset_token = secrets.token_urlsafe(32)\n"
        js = ("const delay = Math.random() * 100\nconst sessionId = Math.random().toString(16)\n"
              "const token = crypto.randomUUID()\nconst tokenCount = Math.floor(Math.random() * 10)\n")
        self.silent({"auth.py": py, "lib/keys.js": js, "tests/test_auth.py": "import random\ntoken = str(random.random())\n"})

    # ------------------------------------------------------------------ COD011 hash de senha

    def test_cod011_fast_hash_for_password(self):
        py = "import hashlib\ndef save(user, password):\n    user.pw = hashlib.md5(password.encode()).hexdigest()\n"
        js = "const crypto = require('crypto')\nconst h = crypto.createHash('sha256').update(password).digest('hex')\n"
        f = run({"users.py": py, "users.js": js})
        self.assertEqual(got(f), [("COD011", "users.js", 2, "medium"), ("COD011", "users.py", 3, "medium")])
        self.assertEqual({x.params["algo"] for x in f}, {"MD5", "SHA-256"})

    def test_cod011_file_hash_and_bcrypt_stay_silent(self):
        py = "import hashlib, bcrypt\ndigest = hashlib.sha256(data).hexdigest()\npw = bcrypt.hashpw(password, bcrypt.gensalt())\n"
        js = "const crypto = require('crypto')\nconst etag = crypto.createHash('sha256').update(body).digest('hex')\n"
        self.silent({"util.py": py, "util.js": js})

    # ------------------------------------------------------------------ APP009 saída do modelo

    def test_app009_portuguese_titles_read_right(self):
        """O lugar vem com a preposição: "chega à página", nunca "chega a a página"."""
        titles = {kind: texts("APP009", "pt", code._llm_params(kind))[0] for kind in code._LLM_SINK}
        self.assertEqual(titles["html"], "Texto escrito pelo modelo chega à página como HTML")
        self.assertEqual(titles["shell"], "Texto escrito pelo modelo chega a um comando de shell")
        for kind, title in titles.items():
            self.assertNotRegex(title, r"\ba a\b|chega (?!à |a )", kind)

    def test_app009_python_model_output_runs(self):
        src = OPENAI_PY + ("import subprocess\n"
                           "def fix():\n"
                           "    resp = client.chat.completions.create(model='m', messages=[])\n"
                           "    code = resp.choices[0].message.content\n"
                           "    exec(code)\n"
                           "    subprocess.run(code, shell=True)\n"
                           "    return code\n")
        f = run({"agent.py": src})
        self.assertEqual(got(f), [("APP009", "agent.py", 7, "critical"), ("APP009", "agent.py", 8, "critical")])
        self.assertIn("exec", f[0].params["sink_en"] + f[0].params["fix_en"])

    # ------------------------------------------------------------------ APP014 argumento de ferramenta

    def test_app014_portuguese_titles_read_right(self):
        """O lugar vem com a preposição: "chega à página", nunca "chega a a página"."""
        titles = {kind: texts("APP014", "pt", code._tool_params(kind.replace("_any", ""), "_any" not in kind))[0]
                  for kind in code._TOOL_SINK}
        self.assertEqual(titles["html"], "Argumento que o modelo escreve na ferramenta chega à página como HTML")
        self.assertEqual(titles["shell_any"], "Argumento que o modelo escreve na ferramenta chega a um comando de shell")
        for kind, title in titles.items():
            self.assertNotRegex(title, r"\ba a\b|chega (?!à |a )", kind)

    def test_app014_tool_argument_runs(self):
        py = ("from mcp.server.fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('x')\n"
              "@mcp.tool()\n"
              "def run(cmd: str) -> str:\n"
              "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n")
        js = ("import { tool } from 'ai'\nimport { exec } from 'child_process'\n"
              "export const shell = tool({\n"
              "  description: 'run',\n"
              "  execute: async ({ command }) => exec(command),\n"
              "})\n"
              "export const calc = tool({ execute: async ({ expression }) => eval(expression) })\n")
        f = run({"server.py": py, "tools.ts": js})
        self.assertEqual(got(f), [("APP014", "server.py", 6, "high"), ("APP014", "tools.ts", 5, "high"),
                                  ("APP014", "tools.ts", 7, "high")])
        for lang in ("pt", "en"):
            title, why, fix = texts("APP014", lang, f[0].params)
            self.assertIn("modelo" if lang == "pt" else "model", why)
            self.assertTrue(title and fix)

    def test_app014_built_command_is_critical_and_quoting_is_silent(self):
        py = ("from mcp.server.fastmcp import FastMCP\nimport os, subprocess, shlex\nmcp = FastMCP('x')\n"
              "@mcp.tool()\n"
              "def log(ref: str) -> str:\n"
              "    os.system('git log ' + ref)\n"
              "    subprocess.run(['sh', '-c', f'ls {ref}'])\n"
              "    os.system('git log ' + shlex.quote(ref))\n"
              "    subprocess.run(['git', 'log', ref])\n"
              "    return ''\n")
        self.check({"server.py": py}, [("APP014", "server.py", 6, "critical"), ("APP014", "server.py", 7, "critical")])

    def test_app009_model_html_and_sql(self):
        js = ("'use client'\nimport { useChat } from '@ai-sdk/react'\n"
              "export default function Chat() {\n"
              "  const { messages } = useChat()\n"
              "  return messages.map(m => <div key={m.id} dangerouslySetInnerHTML={{ __html: m.content }} />)\n}\n")
        py = OPENAI_PY + ("import streamlit as st, sqlite3\n"
                          "resp = client.chat.completions.create(model='m', messages=[])\n"
                          "answer = resp.choices[0].message.content\n"
                          "st.markdown(answer, unsafe_allow_html=True)\n"
                          "sqlite3.connect('db').execute(answer)\n")
        self.check({"app/chat.tsx": js, "app.py": py},
                   [("APP009", "app.py", 6, "medium"), ("APP009", "app.py", 7, "high"), ("APP009", "app/chat.tsx", 5, "medium")])

    def test_app009_parsed_or_sanitized_output_stays_silent(self):
        js = ("'use client'\nimport { useChat } from '@ai-sdk/react'\nimport DOMPurify from 'dompurify'\n"
              "export default function Chat() {\n"
              "  const { messages } = useChat()\n"
              "  return messages.map(m => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(m.content) }} />)\n}\n")
        py = OPENAI_PY + ("import json\nresp = client.chat.completions.create(model='m', messages=[])\n"
                          "data = json.loads(resp.choices[0].message.content)\nexec('print(1)')\n")
        self.silent({"app/chat.tsx": js, "app.py": py})

    # ------------------------------------------------------------------ APP010 prompt de sistema

    def test_app010_request_input_inside_system_prompt(self):
        py = FASTAPI + OPENAI_PY + ("@app.post('/chat')\n"
                                    "def chat(body: dict):\n"
                                    "    return client.chat.completions.create(model='m', messages=[\n"
                                    "        {'role': 'system', 'content': f\"You support {body['company']}. Be brief.\"},\n"
                                    "        {'role': 'user', 'content': body['q']}])\n")
        js = ("import { streamText } from 'ai'\n"
              "export async function POST(req) {\n"
              "  const body = await req.json()\n"
              "  return streamText({ model, system: `You are a tutor. The student is ${body.name}.`, prompt: body.q })\n}\n")
        found = [x for x in got(run({"main.py": py, "app/api/chat/route.ts": js})) if x[0] == "APP010"]
        self.assertEqual(found, [("APP010", "app/api/chat/route.ts", 4, "medium"), ("APP010", "main.py", 8, "medium")])

    def test_app010_user_message_and_whole_custom_prompt_stay_silent(self):
        py = FASTAPI + OPENAI_PY + ("@app.post('/chat')\n"
                                    "def chat(body: dict, user=Depends(get_current_user)):\n"
                                    "    return client.chat.completions.create(model='m', messages=[\n"
                                    "        {'role': 'system', 'content': body['system_prompt']},\n"
                                    "        {'role': 'user', 'content': f\"Question: {body['q']}\"}])\n")
        js = ("import { streamText } from 'ai'\nimport { auth } from '@/auth'\n"
              "export async function POST(req) {\n"
              "  const session = await auth()\n"
              "  const body = await req.json()\n"
              "  const system: string = body.system\n"
              "  return streamText({ model, system, prompt: `Question: ${body.q}` })\n}\n")
        self.silent({"main.py": py, "app/api/chat/route.ts": js})

    # ------------------------------------------------------------------ APP011 rota de IA aberta

    def test_app011_public_llm_route(self):
        js = ("import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
              "export async function POST(req: Request) {\n"
              "  const { prompt } = await req.json()\n"
              "  const r = await openai.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: prompt }] })\n"
              "  return Response.json(r)\n}\n")
        py = FASTAPI + OPENAI_PY + ("@app.post('/ask')\n"
                                    "def ask(q: str):\n"
                                    "    return client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n")
        self.check({"app/api/chat/route.ts": js, "main.py": py},
                   [("APP011", "app/api/chat/route.ts", 3, "medium"), ("APP011", "main.py", 6, "medium")])

    def test_app011_login_rate_limit_or_middleware_stay_silent(self):
        route = ("import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
                 "export async function POST(req: Request) {\n"
                 "  const r = await openai.chat.completions.create({ model: 'm', messages: [] })\n"
                 "  return Response.json(r)\n}\n")
        guarded = route.replace("export async function POST(req: Request) {\n",
                                "export async function POST(req: Request) {\n  const session = await auth()\n"
                                "  if (!session) return new Response('no', { status: 401 })\n")
        limited = route.replace("export async function POST(req: Request) {\n",
                                "export async function POST(req: Request) {\n  await ratelimit.limit(ip)\n")
        self.silent({"app/api/a/route.ts": guarded, "app/api/b/route.ts": limited})
        mw = "import { clerkMiddleware } from '@clerk/nextjs/server'\nexport default clerkMiddleware()\n"
        self.silent({"app/api/chat/route.ts": route, "middleware.ts": mw})
        self.silent({"examples/next/app/api/chat/route.ts": route})
        py = FASTAPI + OPENAI_PY + ("@app.post('/ask')\n"
                                    "def ask(q: str, user=Depends(get_current_user)):\n"
                                    "    return client.chat.completions.create(model='m', messages=[])\n")
        self.silent({"main.py": py})

    # ------------------------------------------------------------------ APP012 carregar modelo

    def test_app012_model_loading_runs_code(self):
        src = ("import torch\nfrom transformers import AutoModel\nfrom langchain_community.vectorstores import FAISS\n"
               "m = AutoModel.from_pretrained('org/model', trust_remote_code=True)\n"
               "db = FAISS.load_local('index', emb, allow_dangerous_deserialization=True)\n"
               "a = torch.load('model.pt', weights_only=False)\n"
               "b = torch.load('model.pt')\n"
               "c = torch.load('model.pt', weights_only=True)\n"
               "d = AutoModel.from_pretrained('org/model', trust_remote_code=False)\n")
        self.check({"load.py": src}, [("APP012", "load.py", 4, "medium"), ("APP012", "load.py", 5, "medium"),
                                      ("APP012", "load.py", 6, "medium"), ("APP012", "load.py", 7, "low")])

    def test_app012_uploaded_checkpoint_is_high(self):
        src = FLASK + "import torch\n@app.post('/m')\ndef m():\n    return str(torch.load(request.files['model']))\n"
        self.check({"app.py": src}, [("APP012", "app.py", 6, "high")])

    # ------------------------------------------------------------------ APP013 agente que roda código

    def test_app013_agents_that_run_model_code(self):
        src = ("from langchain_experimental.tools import PythonREPLTool\n"
               "from langchain_experimental.agents import create_pandas_dataframe_agent\n"
               "from langchain_community.agent_toolkits.load_tools import load_tools\n"
               "from langchain_community.agent_toolkits import create_sql_agent\n"
               "import interpreter\n"
               "tools = [PythonREPLTool()]\n"
               "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)\n"
               "more = load_tools(['terminal'])\n"
               "sql = create_sql_agent(llm, db=db)\n"
               "interpreter.auto_run = True\n"
               "user = UserProxyAgent('u', code_execution_config={'work_dir': 'w', 'use_docker': False})\n")
        self.check({"agent.py": src}, [("APP013", "agent.py", 6, "high"), ("APP013", "agent.py", 7, "high"),
                                       ("APP013", "agent.py", 8, "high"), ("APP013", "agent.py", 9, "medium"),
                                       ("APP013", "agent.py", 10, "high"), ("APP013", "agent.py", 11, "high")])

    def test_app013_sandboxed_or_unrelated_stay_silent(self):
        src = ("from mytools import PythonREPLTool\n"
               "tools = [PythonREPLTool()]\n"
               "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=False)\n"
               "user = UserProxyAgent('u', code_execution_config={'use_docker': True})\n")
        self.silent({"agent.py": src, "build.py": "OPTIONS = {'use_docker': False, 'jobs': 4}\n"})


class PythonFlows(Checks):
    """Como o valor anda dentro da função: atribuição, +=, laço, with, desempacotar, :=, self.x, % e .format()."""

    def test_values_follow_assignments_loops_and_containers(self):
        src = FLASK + ("import os\n"
                       "@app.get('/a')\n"
                       "def a():\n"
                       "    cmd = request.args['a'] if request.args.get('x') else 'ls'\n"
                       "    os.system(cmd)\n"
                       "    names = [n for n in request.args.getlist('n')]\n"
                       "    os.system('rm ' + ' '.join(names))\n"
                       "    q = \"SELECT * FROM t WHERE a = '\"\n"
                       "    q += request.args['a']\n"
                       "    q += \"'\"\n"
                       "    cur.execute(q)\n"
                       "    for name in request.args.getlist('f'):\n"
                       "        open('uploads/' + name)\n"
                       "    x, y = request.args['x'], 1\n"
                       "    os.system(x)\n"
                       "    data = {}\n"
                       "    data['k'] = request.args['k']\n"
                       "    os.system(data['k'])\n"
                       "    if (v := request.args.get('v')):\n"
                       "        os.system(v)\n"
                       "    try:\n"
                       "        os.system('echo ' + request.form['t'])\n"
                       "    except Exception:\n"
                       "        pass\n"
                       "    return 'ok'\n"
                       "class Handler:\n"
                       "    def setup(self):\n"
                       "        self.cmd = request.args['c']\n"
                       "        os.system(self.cmd)\n")
        self.check({"app.py": src}, [("COD002", "app.py", n, "critical") for n in (7, 9, 17, 20, 22, 24, 31)] +
                   [("COD001", "app.py", 13, "high"), ("COD007", "app.py", 15, "high")])

    def test_percent_and_format_sql(self):
        src = FLASK + ("@app.get('/p')\n"
                       "def p():\n"
                       "    cur = db.cursor()\n"
                       "    cur.execute(\"SELECT * FROM t WHERE id = %s\" % request.args['id'])\n"
                       "    cur.execute(\"SELECT * FROM t WHERE a = '{}'\".format(request.args['a']))\n"
                       "    cur.execute(\"SELECT * FROM t WHERE a = '{a}'\".format(a=request.args['a']))\n"
                       "    cur.execute(\"SELECT * FROM t WHERE a = '%(a)s'\" % {'a': request.args['a']})\n"
                       "    cur.execute(\"SELECT * FROM t WHERE a LIKE '%%x'\")\n"
                       "    ids = request.args.getlist('id')\n"
                       "    cur.execute(\"SELECT * FROM t WHERE id IN (%s)\" % ','.join('?' * len(ids)), ids)\n"
                       "    n = int(request.args['n'])\n"
                       "    cur.execute(f'SELECT * FROM t LIMIT {n}')\n"
                       "    return 'x'\n")
        self.check({"app.py": src}, [("COD001", "app.py", n, "high") for n in (6, 7, 8, 9)])

    def test_typed_parameters_cannot_carry_text(self):
        src = ("from fastapi import FastAPI, Depends\nfrom typing import Annotated, Literal, Optional\n"
               "from sqlalchemy import text\napp = FastAPI()\n"
               "@app.get('/items/{item_id}')\n"
               "def item(item_id: int, db: Annotated[Session, Depends(get_db)], q: str = None, n: Optional[int] = None,\n"
               "         f: 'float' = 1.0, ok: bool = False, d: Literal['asc', 'desc'] = 'asc', m: int | None = None):\n"
               "    db.execute(text(f'SELECT * FROM items WHERE id = {item_id} AND n = {n} AND f = {f} AND ok = {ok}'))\n"
               "    db.execute(text(f'SELECT * FROM items ORDER BY id {d} LIMIT {m}'))\n"
               "    db.execute(text(f\"SELECT * FROM items WHERE q = '{q}'\"))\n"
               "    return db\n")
        flask = FLASK + ("@app.route('/u/<int:uid>')\ndef u(uid):\n    cur.execute(f'SELECT * FROM t WHERE id = {uid}')\n"
                         "@app.route('/v/<name>')\ndef v(name):\n    cur.execute(f\"SELECT * FROM t WHERE name = '{name}'\")\n")
        self.check({"main.py": src, "app.py": flask}, [("COD001", "main.py", 10, "high"), ("COD001", "app.py", 8, "high")])

    @unittest.skipIf(sys.version_info < (3, 10), "match chegou no Python 3.10")
    def test_match_statement(self):
        src = FLASK + ("import os\n@app.get('/m')\ndef m():\n"
                       "    match request.args.get('op'):\n"
                       "        case 'ls':\n"
                       "            os.system('ls ' + request.args['d'])\n"
                       "    return 'ok'\n")
        self.check({"app.py": src}, [("COD002", "app.py", 8, "critical")])

    def test_function_argument_only_counts_when_mixed_into_text_in_a_web_app(self):
        src = FLASK + ("import os\n"
                       "def run(cmd):\n    os.system(cmd)\n"
                       "def calc(expr):\n    return eval('1 + ' + expr)\n"
                       "def shell(name):\n    os.system('ls ' + name)\n")
        self.check({"app.py": src}, [("COD003", "app.py", 7, "medium"), ("COD002", "app.py", 9, "medium")])
        self.silent({"tool.py": src.replace(FLASK, "")})

    def test_pathlib_methods(self):
        src = FLASK + ("from pathlib import Path\nBASE = Path('u')\n"
                       "@app.get('/p')\ndef p():\n"
                       "    Path('uploads', request.args['f']).read_text()\n"
                       "    (BASE / request.args['g']).read_bytes()\n"
                       "    q = BASE / request.args['h']\n"
                       "    q.read_text()\n"
                       "    Path(request.args['i']).name\n"
                       "    return 'ok'\n")
        self.check({"app.py": src}, [("COD007", "app.py", n, "high") for n in (7, 8, 10)])

    def test_ssrf_only_when_the_request_decides_the_host(self):
        src = FLASK + ("import requests\n@app.get('/s')\ndef s():\n"
                       "    requests.get(f\"{request.args['base']}/api\")\n"
                       "    requests.get('https://example.com/' + request.args['p'])\n"
                       "    requests.post(request.json['hook'], json={})\n"
                       "    return 'ok'\n")
        self.check({"app.py": src}, [("COD008", "app.py", 6, "high"), ("COD008", "app.py", 8, "high")])

    def test_tls_switches(self):
        src = ("import ssl, requests, httpx\nfrom elasticsearch import Elasticsearch\n"
               "ctx = ssl.create_default_context()\n"
               "ctx.check_hostname = False\n"
               "ctx.verify_mode = ssl.CERT_NONE\n"
               "ssl._create_default_https_context = ssl._create_unverified_context\n"
               "es = Elasticsearch('https://example.com', verify_certs=False)\n"
               "r = requests.get('https://example.com', cert_reqs=ssl.CERT_NONE)\n"
               "with httpx.Client(verify=False) as c:\n"
               "    c.get('https://example.com')\n"
               "token = jwt.decode(t, verify=False)\n")
        self.check({"tls.py": src}, [("COD006", "tls.py", n, "medium") for n in (4, 5, 6, 7, 8, 9)])

    def test_hash_objects(self):
        src = ("import hashlib\n"
               "def a(password):\n    return hashlib.new('md5', password.encode()).hexdigest()\n"
               "def b(password):\n    h = hashlib.sha256()\n    h.update(password.encode())\n    return h.hexdigest()\n"
               "def c(user_password):\n    hashlib.sha1(user_password.encode())\n"
               "def d(data):\n    h = hashlib.new('sha1')\n    h.update(data)\n")
        f = run({"hash.py": src})
        self.assertEqual(got(f), [("COD011", "hash.py", 3, "medium"), ("COD011", "hash.py", 6, "medium"),
                                  ("COD011", "hash.py", 9, "medium")])
        self.assertEqual([x.params["algo"] for x in sorted(f, key=lambda x: x.line)], ["MD5", "SHA-256", "SHA-1"])

    def test_langchain_answers_and_html_sinks(self):
        src = ("from langchain_openai import ChatOpenAI\nfrom fastapi.responses import HTMLResponse\nimport streamlit as st\n"
               "llm = ChatOpenAI()\nchain = prompt | llm\n"
               "code = llm.invoke('write code').content\nexec(code)\n"
               "out = chain.invoke({'q': 'x'})\neval(out)\n"
               "answer = llm.invoke('x').content\nst.html(answer)\n"
               "def page():\n    return HTMLResponse(answer)\n"
               "helper.run('x')\n")
        self.check({"llm.py": src}, [("APP009", "llm.py", 7, "critical"), ("APP009", "llm.py", 9, "critical"),
                                     ("APP009", "llm.py", 11, "medium"), ("APP009", "llm.py", 13, "medium")])

    def test_system_prompt_shapes(self):
        src = ("from fastapi import FastAPI, Depends\nfrom anthropic import Anthropic\n"
               "from langchain_core.messages import SystemMessage\nfrom langchain_core.prompts import ChatPromptTemplate\n"
               "app = FastAPI()\nclient = Anthropic()\n"
               "@app.post('/c')\n"
               "def c(body: dict, user=Depends(get_current_user)):\n"
               "    msgs = [SystemMessage(content=f\"You are a {body['persona']} assistant\")]\n"
               "    client.messages.create(model='m', system=f\"Be {body['tone']} with users\", messages=[], max_tokens=10)\n"
               "    ChatPromptTemplate.from_messages([('system', f\"Act as {body['role']} and help\"), ('user', '{q}')])\n"
               "    client.messages.create(model='m', system='Be brief'.replace('brief', body['w']), messages=[])\n"
               "    SystemMessage(content='You are helpful')\n"
               "    return msgs\n")
        self.check({"chat.py": src}, [("APP010", "chat.py", n, "medium") for n in (9, 10, 11, 12)])

    def test_agent_requests_tool(self):
        src = ("from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit\n"
               "tk = RequestsToolkit(requests_wrapper=w, allow_dangerous_requests=True)\n")
        self.check({"agent.py": src}, [("APP013", "agent.py", 2, "medium")])

    def test_llm_route_guards(self):
        route = ("from fastapi import FastAPI, Depends\nfrom openai import OpenAI\nclient = OpenAI()\napp = FastAPI()\n"
                 "@app.post('/a')\n{deco}def a(q: str):\n"
                 "    return client.chat.completions.create(model='m', messages=[])\n")
        self.silent({"a.py": route.format(deco="@login_required\n")})
        self.silent({"a.py": route.format(deco="@limiter.limit('5/minute')\n")})
        main = "from fastapi import FastAPI, Depends\napp = FastAPI()\napp.include_router(api, dependencies=[Depends(verify_key)])\n"
        self.silent({"routes/a.py": route.format(deco=""), "main.py": main})
        self.check({"routes/a.py": route.format(deco="")}, [("APP011", "routes/a.py", 6, "medium")])


class JsFlows(Checks):
    def test_child_process_shapes(self):
        src = ("const express = require('express')\nconst cp = require('child_process')\n"
               "const { spawn } = require('child_process')\nconst shell = require('shelljs')\nconst app = express()\n"
               "class Runner {\n  start(req) {\n    this.cmd = req.body.cmd\n    cp.exec(this.cmd)\n  }\n}\n"
               "app.get('/a', (req, res) => {\n"
               "  cp.exec(`ls ${req.query.d}`)\n"
               "  require('child_process').exec(req.query.c)\n"
               "  spawn('ls', ['-la', req.query.s])\n"
               "  spawn(req.query.p, { shell: true })\n"
               "  shell.exec('git ' + req.query.g)\n"
               "  res.send('ok')\n})\n")
        esm = ("import * as cp from 'node:child_process'\nimport express from 'express'\nconst app = express()\n"
               "app.post('/b', (req, res) => { cp.execSync(`convert ${req.body.f}`) })\n")
        self.check({"server.js": src, "esm.mjs": esm}, [("COD002", "server.js", n, "critical") for n in (9, 13, 14, 16, 17)] +
                   [("COD002", "esm.mjs", 4, "critical")])

    def test_sql_shapes(self):
        src = ("const express = require('express')\nconst app = express()\n"
               "app.get('/a', async (req, res) => {\n"
               "  let q = \"SELECT * FROM t WHERE a = '\"\n"
               "  q += req.body.a\n"
               "  q += \"'\"\n"
               "  await db.query(q)\n"
               "  await knex('t').whereRaw(`name = '${req.query.n}'`)\n"
               "  await knex('t').whereRaw('name = ?', [req.query.n])\n"
               "  res.json({})\n})\n"
               "function find(name) {\n  return db.query(`SELECT * FROM t WHERE name = '${name}'`)\n}\n"
               "function order(col) {\n  return db.query(`SELECT * FROM t ORDER BY ${col}`)\n}\n")
        self.check({"server.js": src}, [("COD001", "server.js", 7, "high"), ("COD001", "server.js", 8, "high"),
                                        ("COD001", "server.js", 13, "medium")])

    def test_mcp_handler_arguments(self):
        src = ("import { Server } from '@modelcontextprotocol/sdk/server/index.js'\nimport { exec } from 'child_process'\n"
               "const server = new Server({ name: 'x' })\n"
               "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
               "  exec(request.params.arguments.cmd)\n"
               "  const { name, arguments: input = {} } = request.params\n"
               "  exec(`kubectl scale ${input.kind} ${input.name}`)\n})\n")
        self.check({"mcp.js": src}, [("APP014", "mcp.js", 5, "high"), ("APP014", "mcp.js", 7, "critical")])

    def test_dom_sinks_and_redirect_guard(self):
        src = ("const box = document.getElementById('b')\n"
               "box.insertAdjacentHTML('beforeend', location.hash.slice(1))\n"
               "document.write(new URLSearchParams(location.search).get('m'))\n"
               "location.href = new URLSearchParams(location.search).get('r')\n"
               "const r2 = new URLSearchParams(location.search).get('r2')\n"
               "if (r2.startsWith('/') && !r2.startsWith('//')) location.assign(r2)\n")
        self.check({"public/dom.js": src}, [("COD005", "public/dom.js", 2, "medium"), ("COD005", "public/dom.js", 3, "medium"),
                                            ("COD009", "public/dom.js", 4, "medium")])

    def test_path_guard_reads_the_string(self):
        src = ("const fs = require('fs')\nconst express = require('express')\nconst app = express()\n"
               "app.get('/f', (req, res) => {\n"
               "  if (req.query.name.includes('..')) return res.sendStatus(400)\n"
               "  fs.readFile('files/' + req.query.name, (e, d) => res.send(d))\n})\n")
        self.silent({"server.js": src})

    def test_model_answer_as_sql_and_server_fetch(self):
        src = ("import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
               "export async function POST(req: Request) {\n"
               "  const body = await req.json()\n"
               "  const completion = await openai.chat.completions.create({ model: 'm', messages: [] })\n"
               "  await db.query(completion.choices[0].message.content)\n"
               "  const target = body.url\n"
               "  const r = await axios.get(target)\n"
               "  await fetch(`https://api.example.com/items/${body.id}`)\n"
               "  return Response.json(r.data)\n}\n")
        self.check({"app/api/ai/route.ts": src}, [("APP011", "app/api/ai/route.ts", 3, "medium"),
                                                  ("APP009", "app/api/ai/route.ts", 6, "high"),
                                                  ("COD008", "app/api/ai/route.ts", 8, "high")])

    def test_langchain_system_messages(self):
        src = ("import { SystemMessage } from '@langchain/core/messages'\n"
               "import { ChatPromptTemplate } from '@langchain/core/prompts'\nimport OpenAI from 'openai'\n"
               "export async function POST(req) {\n"
               "  const body = await req.json()\n"
               "  const m = new SystemMessage(`You are a ${body.role} helper`)\n"
               "  const p = ChatPromptTemplate.fromMessages([[\"system\", `Act as ${body.role} and help`], [\"user\", \"{q}\"]])\n"
               "  const n = new SystemMessage('You are helpful')\n"
               "  return Response.json({ m, p, n })\n}\n")
        self.check({"lib/lc.ts": src}, [("APP010", "lib/lc.ts", 6, "medium"), ("APP010", "lib/lc.ts", 7, "medium")])

    def test_component_templates(self):
        vue = ("<template>\n  <div v-html=\"q\"></div>\n  <div v-html=\"answer\"></div>\n</template>\n"
               "<script setup>\nimport OpenAI from 'openai'\n"
               "const q = new URLSearchParams(location.search).get('q')\n"
               "const answer = (await openai.chat.completions.create({ model: 'm', messages: [] })).choices[0].message.content\n"
               "</script>\n")
        astro = "---\nconst q = Astro.url.searchParams.get('q')\n---\n<div set:html={q} />\n<div set:html={'<b>x</b>'} />\n"
        self.check({"src/App.vue": vue, "src/pages/x.astro": astro},
                   [("COD005", "src/App.vue", 2, "medium"), ("APP009", "src/App.vue", 3, "medium"),
                    ("COD005", "src/pages/x.astro", 4, "medium")])

    def test_weak_token_function_and_cryptojs(self):
        src = "function makeToken() {\n  return Math.random().toString(36)\n}\nconst h = CryptoJS.MD5(password).toString()\n"
        self.check({"lib/tok.js": src}, [("COD010", "lib/tok.js", 2, "low"), ("COD011", "lib/tok.js", 4, "medium")])

    def test_llm_routes_in_pages_api_server_actions_and_express(self):
        pages = ("import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
                 "export default async function handler(req, res) {\n"
                 "  res.json(await openai.chat.completions.create({ model: 'm', messages: [] }))\n}\n")
        action = ("'use server'\nimport OpenAI from 'openai'\nconst openai = new OpenAI()\n"
                  "export async function ask(q: string) {\n"
                  "  return openai.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: q }] })\n}\n")
        express = ("const express = require('express')\nconst OpenAI = require('openai')\nconst app = express()\n"
                   "const openai = new OpenAI()\n"
                   "app.post('/chat', async (req, res) => res.json(await openai.chat.completions.create({ model: 'm', messages: [] })))\n")
        self.check({"pages/api/chat.ts": pages, "app/actions.ts": action, "server.js": express},
                   [("APP011", "pages/api/chat.ts", 4, "medium"), ("APP011", "app/actions.ts", 5, "medium"),
                    ("APP011", "server.js", 5, "medium")])
        self.silent({"server.js": express, "src/app.js": "app.use(passport.authenticate('jwt', { session: false }))\n"})


FMCP = "from mcp.server.fastmcp import FastMCP, Context\nmcp = FastMCP('x')\n"
MCPJS = ("import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'\nimport { z } from 'zod'\n"
         "import { exec, execFile } from 'child_process'\nimport fs from 'fs'\nimport path from 'path'\n"
         "const server = new McpServer({ name: 'x', version: '1' })\n")


class ToolArguments(Checks):
    """APP014: quem escreve os argumentos de uma ferramenta (MCP, LangChain, tool calling, AI SDK) é o modelo."""

    def test_typed_enum_pattern_and_injected_params_stay_silent(self):
        src = FMCP + ("import os, enum\nfrom typing import Literal, Annotated\nfrom pydantic import Field\n"
                      "class Mode(enum.Enum):\n    A = 'a'\n"
                      "@mcp.tool()\n"
                      "def t(n: int, flag: bool, kind: Literal['a', 'b'], mode: Mode,\n"
                      "      ref: Annotated[str, Field(pattern=r'^[a-z]+$')], ctx: Context) -> str:\n"
                      "    os.system(f'ls {n} {flag} {kind} {mode} {ref}')\n"
                      "    os.system('ls ' + ctx.request_id)\n"
                      "    return ''\n")
        self.silent({"server.py": src})

    def test_code_and_deserialization(self):
        src = FMCP + ("import pickle, base64\n"
                      "@mcp.tool()\ndef calc(expression: str) -> str:\n    return str(eval(expression))\n"
                      "@mcp.tool()\ndef calc2(a: str) -> str:\n    return str(eval('1 + ' + a))\n"
                      "@mcp.tool()\ndef load(data: str):\n    return pickle.loads(base64.b64decode(data))\n")
        f = run({"server.py": src})
        self.assertEqual(got(f), [("APP014", "server.py", 6, "high"), ("APP014", "server.py", 9, "critical"),
                                  ("APP014", "server.py", 12, "high")])
        self.assertEqual([x.params["kind"] for x in sorted(f, key=lambda x: x.line)], ["code", "code", "deserialize"])

    def test_sql_built_from_argument_but_not_parameters_or_whole_query(self):
        src = FMCP + ("import sqlite3\nconn = sqlite3.connect('d.db')\n"
                      "@mcp.tool()\ndef find(name: str):\n"
                      "    a = conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\").fetchall()\n"
                      "    b = conn.execute('SELECT * FROM users WHERE name = ?', (name,)).fetchall()\n"
                      "    return a + b\n"
                      "@mcp.tool()\ndef read_query(query: str):\n"
                      "    return conn.execute(query).fetchall()\n")
        self.check({"server.py": src}, [("APP014", "server.py", 7, "high")])

    def test_paths(self):
        """Pasta do código + nome do modelo é alto (../ sai dela); caminho inteiro é médio; resolve + checagem, basename
        e nome de arquivo fixo ficam quietos."""
        src = FMCP + ("import os\nfrom pathlib import Path\nBASE = Path('/srv/notes')\n"
                      "@mcp.tool()\ndef read(name: str) -> str:\n    return open(os.path.join(BASE, name)).read()\n"
                      "@mcp.tool()\ndef cat(path: str) -> str:\n    return open(path).read()\n"
                      "@mcp.tool()\ndef safe(name: str) -> str:\n"
                      "    p = (BASE / name).resolve()\n"
                      "    if not p.is_relative_to(BASE):\n        raise ValueError('outside')\n"
                      "    return p.read_text()\n"
                      "@mcp.tool()\ndef base(name: str) -> str:\n"
                      "    return open(os.path.join(BASE, os.path.basename(name))).read()\n"
                      "@mcp.tool()\ndef save(workspace_dir: str, body: str) -> str:\n"
                      "    with open(os.path.join(workspace_dir, 'model.json'), 'w') as f:\n"
                      "        f.write(body)\n"
                      "    open(f'{workspace_dir}/notes.txt').read()\n"
                      "    return 'ok'\n")
        self.check({"server.py": src}, [("APP014", "server.py", 8, "high"), ("APP014", "server.py", 11, "medium")])

    def test_urls_fixed_host_and_guard(self):
        src = FMCP + ("import requests\nfrom urllib.parse import urlparse\n"
                      "@mcp.tool()\ndef get(url: str) -> str:\n    return requests.get(url).text\n"
                      "@mcp.tool()\ndef search(q: str) -> str:\n"
                      "    return requests.get(f'https://api.example.com/search?q={q}').text\n"
                      "@mcp.tool()\ndef guarded(url: str) -> str:\n"
                      "    if urlparse(url).hostname not in ALLOWED_HOSTS:\n        raise ValueError('host')\n"
                      "    return requests.get(url).text\n")
        self.check({"server.py": src}, [("APP014", "server.py", 7, "medium")])

    def test_low_level_server_dispatch_and_helpers(self):
        low = ("from mcp.server import Server\nimport subprocess\nserver = Server('x')\n"
               "def run_cmd(cmd):\n    return subprocess.run(cmd, shell=True).stdout\n"
               "def read_file(path, encoding='utf-8'):\n    return open(path, encoding=encoding).read()\n"
               "TOOLS = {'run': run_cmd, 'read': read_file}\n"
               "@server.call_tool()\nasync def call(name: str, arguments: dict):\n"
               "    if name == 'sh':\n        return subprocess.run(arguments['cmd'], shell=True).stdout\n"
               "    return TOOLS[name](**arguments)\n")
        helper = FMCP + ("def _read(p):\n    return open(p).read()\n"
                         "@mcp.tool()\ndef read(path: str) -> str:\n    return _read(path)\n")
        plain = "import subprocess\ndef run(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True).stdout\n"
        self.check({"low.py": low, "helper.py": helper, "util.py": plain},
                   [("APP014", "helper.py", 4, "medium"), ("APP014", "low.py", 5, "high"), ("APP014", "low.py", 7, "medium"),
                    ("APP014", "low.py", 12, "high")])

    def test_agent_frameworks_and_api_tool_calls(self):
        lc = ("from langchain_core.tools import tool, BaseTool\nimport subprocess\n"
              "@tool\ndef shell(command: str) -> str:\n    '''Run a command.'''\n"
              "    return subprocess.check_output(command, shell=True).decode()\n"
              "class Reader(BaseTool):\n    name: str = 'reader'\n"
              "    def _run(self, path: str) -> str:\n        return open(path).read()\n")
        oa = ("import json, subprocess\nfrom openai import OpenAI\nclient = OpenAI()\n"
              "resp = client.chat.completions.create(model='m', messages=[], tools=[])\n"
              "for tool_call in resp.choices[0].message.tool_calls:\n"
              "    args = json.loads(tool_call.function.arguments)\n"
              "    subprocess.run(args['cmd'], shell=True)\n")
        an = ("import anthropic\nclient = anthropic.Anthropic()\n"
              "msg = client.messages.create(model='m', max_tokens=10, messages=[], tools=[])\n"
              "for block in msg.content:\n"
              "    if block.type == 'tool_use':\n        data = open(block.input['path']).read()\n")
        reg = FMCP + "import subprocess\ndef run(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True).stdout\nmcp.add_tool(run)\n"
        sdk = ("from agents import Agent\nimport subprocess\n"
               "def sh(cmd: str) -> str:\n    return subprocess.run(cmd, shell=True).stdout\n"
               "agent = Agent(name='a', tools=[sh])\n")
        self.check({"lc.py": lc, "oa.py": oa, "an.py": an, "reg.py": reg, "sdk.py": sdk},
                   [("APP014", "an.py", 6, "medium"), ("APP014", "lc.py", 6, "high"), ("APP014", "lc.py", 10, "medium"),
                    ("APP014", "oa.py", 7, "high"), ("APP014", "reg.py", 5, "high"), ("APP014", "sdk.py", 4, "high")])

    def test_js_mcp_server_tool_and_zod_types(self):
        src = MCPJS + ("server.tool('run', { cmd: z.string() }, async ({ cmd }) => {\n"
                       "  exec(cmd)\n  exec(`git log ${cmd}`)\n  execFile('git', ['log', cmd])\n"
                       "  return { content: [] }\n})\n"
                       "server.tool('n', { n: z.number(), mode: z.enum(['a', 'b']) }, async ({ n, mode }) => {\n"
                       "  exec(`ls ${n} ${mode}`)\n  return { content: [] }\n})\n")
        self.check({"server.ts": src}, [("APP014", "server.ts", 8, "high"), ("APP014", "server.ts", 9, "critical")])

    def test_interpreter_with_inline_code(self):
        """[sys.executable, "-c", código], spawn("node", ["-e", código]): o interpretador roda o texto como código, como
        exec(). Um arquivo de script do projeto com o valor como argumento continua quieto."""
        py = FMCP + ("import subprocess, sys\n@mcp.tool()\ndef run_python(code: str) -> str:\n"
                     "    a = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True).stdout\n"
                     "    b = subprocess.run(['node', '-e', 'console.log(' + code + ')'], capture_output=True).stdout\n"
                     "    c = subprocess.run([sys.executable, 'scripts/report.py', code], capture_output=True).stdout\n"
                     "    return a + b + c\n")
        flask = FLASK + ("import subprocess\n@app.post('/run')\ndef run():\n"
                         "    return subprocess.run(['python3', '-c', request.json['code']], capture_output=True).stdout\n")
        llm = OPENAI_PY + ("import subprocess, sys\ndef go(q):\n"
                           "    r = client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n"
                           "    subprocess.run([sys.executable, '-c', r.choices[0].message.content])\n")
        js = MCPJS + ("server.tool('py', { code: z.string() }, async ({ code }) => {\n"
                      "  execFile('python3', ['-c', code])\n"
                      "  execFile(process.execPath, ['-e', code])\n"
                      "  execFile('python3', ['main.py', code])\n"
                      "  return { content: [] }\n})\n")
        f = run({"server.py": py, "app.py": flask, "agent.py": llm, "server.ts": js})
        self.assertEqual(got(f), [("APP009", "agent.py", 6, "critical"), ("APP014", "server.py", 6, "high"),
                                  ("APP014", "server.py", 7, "critical"), ("APP014", "server.ts", 8, "high"),
                                  ("APP014", "server.ts", 9, "high"), ("COD003", "app.py", 6, "critical")])
        self.assertEqual({x.params.get("kind") for x in f if x.rule == "APP014"}, {"code"})

    def test_js_register_tool_paths_and_guards(self):
        src = MCPJS + ("const ROOT = '/srv/notes'\n"
                       "server.registerTool('read', { inputSchema: { p: z.string() } }, async ({ p }) => {\n"
                       "  const a = fs.readFileSync(p, 'utf8')\n"
                       "  const b = fs.readFileSync(path.join(ROOT, p), 'utf8')\n"
                       "  const c = fs.readFileSync(path.join(ROOT, path.basename(p)), 'utf8')\n"
                       "  fs.writeFileSync(path.join(p, 'config.json'), '{}')\n"
                       "  const full = path.resolve(ROOT, p)\n"
                       "  if (!full.startsWith(ROOT + path.sep)) throw new Error('outside')\n"
                       "  const d = fs.readFileSync(full, 'utf8')\n"
                       "  return { content: [{ type: 'text', text: a + b + c + d }] }\n})\n")
        self.check({"server.ts": src}, [("APP014", "server.ts", 9, "medium"), ("APP014", "server.ts", 10, "high")])

    def test_js_call_tool_handler_and_fixed_hosts(self):
        src = ("import { Server } from '@modelcontextprotocol/sdk/server/index.js'\n"
               "import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'\n"
               "const server = new Server({ name: 'x' })\nconst apiUrl = 'https://api.example.com'\n"
               "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
               "  const { url, q } = request.params.arguments\n"
               "  const r = await fetch(url)\n"
               "  const s = await fetch(`https://api.example.com/search?q=${q}`)\n"
               "  const u = new URL(`${apiUrl}/items/${q}`)\n"
               "  const t = await fetch(u)\n"
               "  return { content: [] }\n})\n")
        self.check({"server.js": src}, [("APP014", "server.js", 7, "medium")])

    def test_js_ai_sdk_openai_helpers_and_callbacks(self):
        ai = ("import { tool } from 'ai'\nimport { z } from 'zod'\nimport { db } from './db'\n"
              "export const search = tool({\n  description: 'search',\n  parameters: z.object({ name: z.string() }),\n"
              "  execute: async ({ name }) => db.query(`SELECT * FROM users WHERE name = '${name}'`),\n})\n"
              "export const safe = tool({\n  parameters: z.object({ name: z.string() }),\n"
              "  execute: async ({ name }) => db.query('SELECT * FROM users WHERE name = $1', [name]),\n})\n")
        oa = ("import OpenAI from 'openai'\nimport { exec } from 'child_process'\nconst openai = new OpenAI()\n"
              "const r = await openai.chat.completions.create({ model: 'm', messages: [], tools: [] })\n"
              "for (const toolCall of r.choices[0].message.tool_calls ?? []) {\n"
              "  const args = JSON.parse(toolCall.function.arguments)\n  exec(args.cmd)\n}\n")
        helper = MCPJS + ("async function readNote(p: string) {\n  return fs.promises.readFile(p, 'utf8')\n}\n"
                          "server.tool('read', { p: z.string() }, async ({ p }) => {\n"
                          "  return { content: [{ type: 'text', text: await readNote(p) }] }\n})\n")
        callback = MCPJS + ("server.tool('ls', { dir: z.string() }, async ({ dir }) => {\n"
                            "  const names = ['a.md', 'b.md']\n  names.forEach((name) => exec('wc -l ' + name))\n"
                            "  return { content: [] }\n})\n")
        browser = ("'use client'\nimport { tool } from 'ai'\n"
                   "export const f = tool({ parameters: {}, execute: async ({ url }) => fetch(url) })\n")
        self.check({"tools.ts": ai, "agent.ts": oa, "helper.ts": helper, "callback.ts": callback, "app/page.tsx": browser},
                   [("APP014", "agent.ts", 7, "high"), ("APP014", "helper.ts", 8, "medium"), ("APP014", "tools.ts", 7, "high")])

    def test_python_helpers_in_other_files_of_the_project(self):
        server = ("from mcp.server.fastmcp import FastMCP\nfrom .db import run_query, by_id\nfrom pkg.shell import sh\n"
                  "mcp = FastMCP('x')\n"
                  "@mcp.tool()\ndef find(name: str, cmd: str, n: int):\n"
                  "    sh(cmd)\n    by_id(n)\n    return run_query(name)\n")
        db = ("import sqlite3\nconn = sqlite3.connect('d')\n"
              "def run_query(name):\n    return conn.execute(f\"SELECT * FROM t WHERE name = '{name}'\").fetchall()\n"
              "def by_id(n):\n    return conn.execute(f\"SELECT * FROM t WHERE id = {n}\").fetchall()\n")
        shell = ("import subprocess\nfrom .util import log_run\n"
                 "def sh(cmd):\n    log_run(cmd)\n    return subprocess.run('git ' + cmd, shell=True)\n")
        util = "import os\ndef log_run(c):\n    os.system('echo ' + c)\n"
        other = "import subprocess\ndef sh2(cmd):\n    return subprocess.run('git ' + cmd, shell=True)\n"
        self.check({"pkg/server.py": server, "pkg/db.py": db, "pkg/shell.py": shell, "pkg/util.py": util, "pkg/other.py": other},
                   [("APP014", "pkg/db.py", 4, "high"), ("APP014", "pkg/shell.py", 5, "critical"),
                    ("APP014", "pkg/util.py", 3, "critical")])

    def test_js_handlers_in_other_files_of_the_project(self):
        index = ("import { Server } from '@modelcontextprotocol/sdk/server/index.js'\n"
                 "import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'\n"
                 "import { kubectlScale, other } from './tools/kubectl-scale.js'\n"
                 "const { readIt } = require('./tools/read')\n"
                 "const server = new Server({ name: 'x' })\n"
                 "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
                 "  const { name, arguments: input = {} } = request.params\n"
                 "  if (name === 'kubectl_scale') return await kubectlScale(k8sManager, input as { name: string })\n"
                 "  if (name === 'read') return readIt(input.path)\n"
                 "  return other(k8sManager)\n})\n")
        scale = ("import { execSync } from 'child_process'\n"
                 "export const kubectlScaleSchema = { name: 'kubectl_scale', inputSchema: { type: 'object' } }\n"
                 "export async function kubectlScale(k8sManager: any, input: { name: string; replicas: number }) {\n"
                 "  const command = `kubectl scale deployment ${input.name} --replicas=${input.replicas}`\n"
                 "  return execSync(command).toString()\n}\n"
                 "export async function other(k8sManager: any, input?: any) {\n"
                 "  return execSync(`kubectl get ${input}`).toString()\n}\n")
        read = "const fs = require('fs')\nconst readIt = async (p) => fs.readFileSync(p, 'utf8')\nmodule.exports = { readIt }\n"
        self.check({"src/index.ts": index, "src/tools/kubectl-scale.ts": scale, "src/tools/read.js": read},
                   [("APP014", "src/tools/kubectl-scale.ts", 5, "critical"), ("APP014", "src/tools/read.js", 2, "medium")])

    def test_validation_calls_and_fixed_programs(self):
        """validate_app_name(x) antes do uso, validatePath(p) no JS e uma lista de argumentos com o programa escrito no
        código, passada a um helper que roda o comando: nada disso é reportado."""
        py = FMCP + ("import os, subprocess\nBASE = '/srv'\n"
                     "@mcp.tool()\ndef w(app_name: str, other: str, ctx_dir: str):\n"
                     "    validate_app_name(app_name)\n"
                     "    open(os.path.join(BASE, f'{app_name}-x.json'), 'w').write('x')\n"
                     "    open(os.path.join(BASE, f'{other}-x.json'), 'w').write('x')\n"
                     "    run(['docker', 'build', ctx_dir])\n"
                     "    cmd = ['docker', 'build']\n    cmd.append(ctx_dir)\n    run(cmd)\n"
                     "    run([ctx_dir])\n"
                     "    return 'ok'\n"
                     "def run(command):\n    return subprocess.run(command, capture_output=True)\n")
        js = MCPJS + ("function run(argv: string[]) { return execFile(argv[0], argv.slice(1)) }\n"
                      "server.tool('r', { p: z.string() }, async ({ p }) => {\n"
                      "  await validatePath(p)\n  const t = fs.readFileSync(p, 'utf8')\n  run(['git', 'log', p])\n"
                      "  return { content: [] }\n})\n")
        self.check({"server.py": py, "server.ts": js}, [("APP014", "server.py", 9, "high"), ("APP014", "server.py", 17, "high")])

    def test_helpers_that_create_folders_are_not_checks(self):
        """ensure_dir(x), fse.ensureDir(x) e revalidatePath('/') não conferem o valor: o caminho continua do modelo."""
        py = FMCP + ("import os\nBASE = '/srv'\n"
                     "@mcp.tool()\ndef save(name: str, text: str):\n"
                     "    ensure_dir(name)\n    check_file_exists(name)\n"
                     "    open(os.path.join(BASE, name), 'w').write(text)\n    return 'ok'\n")
        js = MCPJS + ("import fse from 'fs-extra'\n"
                      "server.tool('w', { p: z.string() }, async ({ p }) => {\n"
                      "  await fse.ensureDir(path.dirname(p))\n  revalidatePath('/')\n  fs.writeFileSync(p, 'x')\n"
                      "  return { content: [] }\n})\n")
        self.check({"server.py": py, "server.ts": js}, [("APP014", "server.py", 9, "high"), ("APP014", "server.ts", 11, "medium")])

    def test_skill_mode_keeps_full_severity(self):
        src = FMCP + ("import os, requests\n"
                      "@mcp.tool()\ndef t(cmd: str, url: str) -> str:\n"
                      "    os.system('git log ' + cmd)\n    return requests.get(url).text\n")
        want = [("APP014", "server.py", 6, "critical"), ("APP014", "server.py", 7, "medium")]
        self.check({"server.py": src}, want, mode="skill")
        self.check({"server.py": src}, want)

    def test_standards_follow_the_sink(self):
        src = FMCP + ("import os\n"
                      "@mcp.tool()\ndef t(cmd: str, path: str) -> str:\n"
                      "    os.system(cmd)\n    return open(path).read()\n")
        d = tempfile.TemporaryDirectory()
        _DIRS.append(d)
        with open(os.path.join(d.name, "server.py"), "w", encoding="utf-8") as fh:
            fh.write(src)
        ctx, findings = scan.run(d.name, offline=True, only={"code", "app"})
        findings = [f for f in findings if f.rule == "APP014"]
        data = json.loads(report.as_json(ctx, findings, "en"))
        std = {x["line"]: x["standards"] for x in data["findings"]}
        self.assertEqual(std, {6: ["CWE-78", "LLM03:2026", "ASI05"], 7: ["CWE-22", "LLM03:2026", "ASI02"]})
        tags = {r["locations"][0]["physicalLocation"]["region"]["startLine"]: r["properties"]["tags"]
                for r in json.loads(report.sarif(ctx, findings, "en"))["runs"][0]["results"]}
        self.assertIn("CWE-78", tags[6])
        self.assertIn("ASI02", tags[7])
        self.assertIn("CWE-78 · LLM03:2026 · ASI05", report.text(ctx, findings, "en"))


class ServerOutputShellAndRandom(Checks):
    """HTML montado com a requisição na resposta, comando que passa por um shell, aleatório de módulo e de cookie."""

    def test_request_data_in_query_helpers_promise_fs_and_private_fields(self):
        """execute_query(f"...") com a requisição, fsp.readFile(req.query.p) e fetch(req.query.url) numa classe com campo
        private: o private do TypeScript não é checagem de endereço."""
        py = ("from flask import Flask, request\napp = Flask(__name__)\n@app.route('/u')\ndef u():\n"
              "    return execute_query(f\"SELECT * FROM t WHERE name = '{request.args['n']}'\")\n"
              "@app.route('/v')\ndef v():\n    return execute_query('SELECT * FROM t WHERE name = ?', (request.args['n'],))\n")
        js = ("const express = require('express')\nconst fsp = require('fs/promises')\nconst app = express()\n"
              "class Api { private base = 'x' }\n"
              "app.get('/f', async (req, res) => res.send(await fsp.readFile(req.query.p, 'utf8')))\n"
              "app.get('/g', async (req, res) => { const r = await fetch(req.query.url); res.json(await r.json()) })\n")
        self.check({"app.py": py, "srv.ts": js}, [("COD001", "app.py", 5, "high"), ("COD007", "srv.ts", 5, "high"),
                                                   ("COD008", "srv.ts", 6, "high")])

    def test_express_and_hono_html_responses(self):
        src = EXPRESS + ("const escapeHtml = require('escape-html')\n"
                         "app.get('/a', (req, res) => res.send(`<h1>Hello ${req.query.name}</h1>`))\n"
                         "app.get('/b', (req, res) => { res.write('<p>' + req.query.q + '</p>'); res.end() })\n"
                         "app.get('/c', (req, res) => res.status(200).end(`<div>${req.params.id}</div>`))\n"
                         "app.get('/d', (req, res) => res.send(`<h1>${escapeHtml(req.query.name)}</h1>`))\n"
                         "app.get('/e', (req, res) => res.send(`Hello ${req.query.name}`))\n"
                         "app.get('/f', (req, res) => res.json({ html: `<b>${req.query.name}</b>` }))\n")
        hono = ("import { Hono } from 'hono'\nconst app = new Hono()\n"
                "app.get('/a', (c) => c.html(`<h1>${c.req.query('name')}</h1>`))\n")
        self.check({"server.js": src, "hono.ts": hono},
                   [("COD005", "hono.ts", 3, "medium"), ("COD005", "server.js", 4, "medium"), ("COD005", "server.js", 5, "medium"),
                    ("COD005", "server.js", 6, "medium")])

    def test_flask_and_fastapi_html_returns(self):
        flask = FLASK + ("@app.get('/a')\ndef a():\n    return f\"<h1>Hello {request.args['name']}</h1>\"\n"
                         "@app.get('/b')\ndef b():\n    html = '<ul>'\n    html += '<li>' + request.args['q'] + '</li>'\n"
                         "    return html, 200\n"
                         "@app.get('/c')\ndef c():\n    return f\"Hello {request.args['name']}\"\n")
        fast = ("from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\napp = FastAPI()\n"
                "@app.get('/a', response_class=HTMLResponse)\ndef a(name: str):\n    return f'<h1>Hello {name}</h1>'\n"
                "@app.get('/b')\ndef b(name: str):\n    return f'<h1>Hello {name}</h1>'\n")
        self.check({"app.py": flask, "main.py": fast},
                   [("COD005", "app.py", 5, "medium"), ("COD005", "app.py", 10, "medium"), ("COD005", "main.py", 6, "medium")])

    def test_spawn_through_a_shell(self):
        src = EXPRESS + ("const { spawn } = require('child_process')\nconst { execa } = require('execa')\n"
                         "app.get('/a', (req, res) => { spawn('sh', ['-c', req.query.cmd]) })\n"
                         "app.get('/b', (req, res) => { spawn(req.query.cmd, { shell: true }) })\n"
                         "app.get('/c', (req, res) => { spawn('ls', [req.query.dir], { shell: true }) })\n"
                         "app.get('/d', async (req, res) => { await execa(req.query.cmd, { shell: true }) })\n"
                         "app.get('/e', (req, res) => { spawn('ls', [req.query.dir]) })\n"
                         "app.get('/f', async (req, res) => { await execa('ls', [req.query.dir]) })\n")
        py = FLASK + ("import subprocess\n"
                      "@app.get('/a')\ndef a():\n    return subprocess.run(['bash', '-c', request.args['cmd']]).stdout\n"
                      "@app.get('/b')\ndef b():\n    return subprocess.run(['ls', request.args['d']]).stdout\n")
        self.check({"server.js": src, "app.py": py}, [("COD002", "app.py", 6, "critical")] +
                   [("COD002", "server.js", n, "critical") for n in (5, 6, 7, 8)])

    def test_weak_random_in_module_values_and_session_cookies(self):
        js = ("const sessionToken = Math.random().toString(36).slice(2)\n"
              "const apiKey = [...Array(32)].map(() => chars[Math.floor(Math.random() * chars.length)]).join('')\n"
              "const resetToken =\n  Math.random().toString(36).slice(2)\n"
              "module.exports = { sessionToken, apiKey, resetToken }\n")
        cookie = EXPRESS + ("app.post('/login', (req, res) => {\n  const sessionId = Math.random().toString(36).slice(2)\n"
                            "  res.cookie('sid', sessionId, { httpOnly: true })\n  res.end()\n})\n")
        quiet = ("const sessionId = Math.random().toString(36).slice(2)\nconsole.log(sessionId)\n"
                 "async function fetchToken() {\n  await sleep(Math.random() * 1000)\n  return fetch('/token')\n}\n")
        py = FLASK + ("import random\nfrom flask import make_response\n"
                      "@app.post('/login')\ndef login():\n    session_id = str(random.random())\n"
                      "    r = make_response('ok')\n    r.set_cookie('session', session_id)\n    return r\n"
                      "def log():\n    session_id = str(random.random())\n    print(session_id)\n")
        self.check({"lib/session.js": js, "cookie.js": cookie, "quiet.js": quiet, "app.py": py},
                   [("COD010", "app.py", 7, "low"), ("COD010", "cookie.js", 4, "low"), ("COD010", "lib/session.js", 1, "low"),
                    ("COD010", "lib/session.js", 2, "low"), ("COD010", "lib/session.js", 4, "low")])


class CodeEngine(unittest.TestCase):
    SQLI = FLASK + "@app.get('/u')\ndef u():\n    return db.execute(f\"SELECT * FROM users WHERE id = '{request.args['id']}'\")\n"

    def test_only_code_and_only_app(self):
        files = {"app.py": self.SQLI, "agent.py": "from langchain_experimental.tools import PythonREPLTool\nt = PythonREPLTool()\n"}
        self.assertEqual({f.rule for f in run(files, only=("code",))}, {"COD001"})
        self.assertEqual({f.rule for f in run(files, only=("app",)) if f.rule.startswith(NEW)}, {"APP013"})
        self.assertIn("code", scan.CHECKS)

    def test_test_and_example_paths_drop_to_low(self):
        for path in ("tests/test_app.py", "examples/app.py", "src/app_test.py", "e2e/app.py", "test_app.py"):
            with self.subTest(path=path):
                self.assertEqual(got(run({path: self.SQLI})), [("COD001", path, 5, "low")])
        self.assertEqual(got(run({"skill/tests/app.py": self.SQLI}, mode="skill")), [("COD001", "skill/tests/app.py", 5, "low")])

    def test_skill_mode_keeps_code_flaws_and_drops_route_rules(self):
        route = ("import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
                 "export async function POST(req) {\n  const b = await req.json()\n"
                 "  return Response.json(await openai.chat.completions.create({ model: 'm', messages: [\n"
                 "    { role: 'system', content: `Talk like ${b.style} and stay polite` }] }))\n}\n")
        files = {"app.py": self.SQLI, "app/api/chat/route.ts": route}
        self.assertEqual({f.rule for f in run(files)} & {"APP010", "APP011", "COD001"}, {"APP010", "APP011", "COD001"})
        self.assertEqual({f.rule for f in run(files, mode="skill") if f.rule.startswith(NEW)}, {"COD001"})

    def test_agents_mode_skips_code(self):
        self.assertEqual(got(run({"app.py": self.SQLI}, mode="agents", only=None)), [])

    def test_inline_ignore(self):
        src = self.SQLI.rstrip("\n") + "  # stingward:ignore\n"
        self.assertEqual(got(run({"app.py": src})), [])

    def test_broken_huge_and_minified_files_do_not_break_the_scan(self):
        files = {"bad.py": "def f(:\n    pass\n", "old.py": "print 'hi'\n", "deep.py": "x = " + "(" * 400 + "1" + ")" * 400 + "\n",
                 "app.min.js": "eval(req.body.x);" * 10, "bundle.js": "var a=1;" * 5000 + "\neval(req.body.x)\n",
                 "nested.js": "const x = " + "[" * 3000 + "]" * 3000 + "\n", "huge.js": "// x\n" * 200_000}
        self.assertEqual(got(run(files)), [])

    def test_many_short_declarations_fit_in_the_budget(self):
        """Cada declaração era cobrada como 400 caracteres lidos, mesmo terminando no ; logo depois: um arquivo com
        muitas declarações curtas (código gerado, var a=1;var b=2;...) esgotava o teto e o resto do arquivo não era lido."""
        src = EXPRESS + ("var a=1;var b=2;" * 100 + "\n") * 300 + "app.post('/x', (req, res) => { eval(req.body.code) })\n"
        self.assertFalse(code._minified(src))
        self.assertEqual(got(run({"server.js": src})), [("COD003", "server.js", 303, "critical")])

    def test_skill_mode_reads_minified_and_vendored_files(self):
        """Numa skill, o bundle minificado, o .min.js e a pasta vendor/ são o código que vai rodar: uma linha longa não
        esconde o eval. Num projeto, continuam de fora (bundle gerado e biblioteca de terceiros)."""
        server = "const express=require('express');const app=express();app.post('/x',(req,res)=>{eval(req.body.code)});"
        files = {"dist/server.min.js": "var a=1;" * 3000 + server + "\n",
                 "bundle.js": "var a=1;" * 5000 + "\n" + server + "\n",
                 "vendor/lib.js": EXPRESS + "app.post('/x', (req, res) => { eval(req.body.code) })\n"}
        self.assertEqual(got(run(files, mode="skill")), [("COD003", "bundle.js", 2, "critical"),
                                                         ("COD003", "dist/server.min.js", 1, "critical"),
                                                         ("COD003", "vendor/lib.js", 3, "critical")])
        self.assertEqual(got(run(files)), [])

    def test_vendored_libraries_are_skipped_in_a_project(self):
        """Biblioteca copiada para o projeto (cabeçalho /*! nome vX.Y ou @license, pastas third_party/ e static/js/lib/)
        não é código do projeto e fica de fora num projeto. O cabeçalho de copyright do próprio projeto não tira o
        arquivo. Numa skill, tudo é lido."""
        sink = "document.getElementById('x').innerHTML = location.hash\n"
        files = {"static/js/materialize.js": "/*!\n * Materialize v0.100.1 (http://materializecss.com)\n * MIT License\n */\n" + sink,
                 "public/react-dom.js": "/** @license React v16.13.1\n * react-dom.development.js\n */\n" + sink,
                 "web/purify.js": "/*! @license DOMPurify 3.0.6 | (c) Cure53 */\n" + sink,
                 "third_party/widget/w.js": sink, "app/static/js/lib/chart.js": sink,
                 "src/app.js": "/*!\n * Copyright (c) 2014-2026 Example Corp.\n * SPDX-License-Identifier: MIT\n */\n" + sink,
                 "src/panel.js": "/**\n * Panel v2.0 layout: draws the side panel.\n */\n" + sink}
        own = [("COD005", "src/app.js", 5, "medium"), ("COD005", "src/panel.js", 4, "medium")]
        self.assertEqual(got(run(files)), own)
        self.assertEqual(got(run(files, mode="skill")), sorted(own + [
            ("COD005", "static/js/materialize.js", 5, "medium"), ("COD005", "public/react-dom.js", 4, "medium"),
            ("COD005", "web/purify.js", 2, "medium"), ("COD005", "third_party/widget/w.js", 1, "medium"),
            ("COD005", "app/static/js/lib/chart.js", 1, "medium")]))

    def test_long_files_are_not_taken_for_minified(self):
        """Um arquivo comum de 4000 linhas é lido até o fim; só linhas realmente longas indicam bundle minificado."""
        src = EXPRESS + "const a = 1 // filler line here\n" * 4000 + "app.post('/x', (req, res) => { eval(req.body.code) })\n"
        self.assertEqual(got(run({"server.js": src})), [("COD003", "server.js", 4003, "critical")])
        self.assertFalse(code._minified(src))
        self.assertTrue(code._minified("const a = 1\n" * 3000 + "var a=1;" * 3000 + "\n"))

    def test_pathological_files_stay_fast(self):
        """Milhares de começos sem fim, com uma origem e um sink para a análise toda rodar: cada arquivo tem um teto."""
        head = "const cp = require('child_process')\nconst q = req.query.x\neval(q)\ncp.exec(q)\n"
        n = 8000
        blobs = {"a.js": "(" * 50_000, "b.js": "`${" * 20_000, "c.ts": "a = b + " * 20_000 + "c\n",
                 "d.js": head + "x.query(\n" * n, "e.js": head + "eval(\n" * n, "f.js": head + "x = \n" * n,
                 "g.js": head + "function<\n" * n, "h.js": head + "const {\n" * n, "i.ts": head + "  public static \n" * n,
                 "j.js": head + "`${\n" * n, "k.js": "let s = 'SELECT * FROM t WHERE a = '\n" + "s += req.query.a\n" * n +
                 "db.query(s)\n" * n, "l.vue": "<script>\n" * n, "m.svelte": "<script>let a</script>\n" + "{@html \n" * n,
                 "n.py": "include_router(\n" * n, "o.py": "from flask import request\nq = 'SELECT * FROM t WHERE a = '\n" +
                 "q += request.args['a']\n" * n + "cur.execute(q)\n" * n}
        t = time.time()
        run(blobs)
        self.assertLess(time.time() - t, 15)

    def test_text_built_from_texts_built_from_texts_stays_fast(self):
        """a2 += a1 trinta vezes, a3 += a2 trinta vezes: remontar cada pedaço cresce exponencialmente (2 KB travavam a
        auditoria). O achado continua saindo."""
        py = ("from flask import request\nimport sqlite3\ncur = sqlite3.connect('x').cursor()\n"
              "a1 = 'SELECT * FROM t WHERE a = '\n" + "a1 += request.args['a']\n" * 30)
        js = "const q = req.query.a\nlet a1 = 'SELECT * FROM t WHERE a = '\n" + "a1 += q\n" * 30
        for k in (2, 3):
            py += f"a{k} = ''\n" + f"a{k} += a{k - 1}\n" * 30
            js += f"let a{k} = ''\n" + f"a{k} += a{k - 1}\n" * 30
        for scan_fn, rel, src in ((code.scan_python, "app.py", py + "cur.execute(a3)\n"),
                                  (code.scan_js, "server.js", js + "db.query(a3)\n")):
            with self.subTest(rel=rel):
                t = time.time()
                found = scan_fn(rel, src)
                self.assertLess(time.time() - t, 1)
                self.assertEqual([(f.rule, f.severity) for f in found], [("COD001", "high")])

    def test_long_line_before_math_random_stays_fast(self):
        """O nome que recebe o Math.random() é procurado na linha: espaços longos ali faziam a busca cúbica."""
        src = "const resetToken = Math.random().toString(36)\nx:" + " " * 1200 + "b Math.random()\n"
        t = time.time()
        found = code.scan_js("a.js", src)
        self.assertLess(time.time() - t, 1)
        self.assertEqual([(f.rule, f.line) for f in found], [("COD010", 1)])

    def test_percent_format_with_long_flags_stays_fast(self):
        """"%" seguido de milhares de zeros (flags e largura casavam os mesmos zeros de vários jeitos) e milhares de
        "%(" sem ")" (cada um lia o resto do texto)."""
        fmt = "SELECT * FROM t WHERE a = '%s'" + (" %" + "0" * 3000 + "!") * 30 + " %(" * 20000
        src = (FLASK + "import sqlite3\ncur = sqlite3.connect('x').cursor()\n@app.get('/a')\ndef a():\n"
               f"    cur.execute(\"{fmt}\" % request.args['a'])\n")
        t = time.time()
        found = code.scan_python("app.py", src)
        self.assertLess(time.time() - t, 1)
        self.assertEqual([(f.rule, f.severity) for f in found], [("COD001", "high")])

    def test_whole_file_searches_stay_linear(self):
        """'use server' depois de espaços e export const GET: sem "=": cada começo de linha lia o resto do arquivo."""
        blobs = {"lib/a.js": "const u = req.query.u\nfetch(u)\n" + (" " * 240 + "\n") * 1990,
                 "lib/b.ts": "import OpenAI from 'openai'\n" + ("export const GET:" + " " * 200 + "\n") * 1990}
        for rel, src in blobs.items():
            with self.subTest(rel=rel):
                t = time.time()
                code.scan_js(rel, src)
                self.assertLess(time.time() - t, 1)
        js = code._Js("app/actions.ts", "// x\n  'use server'\nexport async function a() {}\n", {})
        self.assertTrue(js.server_side())
        self.assertTrue(code._JS_ROUTE_FN.search("export const GET: RequestHandler = async (req) => {}"))

    def test_arrows_without_their_parenthesis_stay_fast(self):
        """") =>" sem o "(" que o abre: cada seta voltava até 2000 caracteres, um por um, sem teto no arquivo."""
        src = "const q = req.query.a\neval(q)\n" + (") => " * 500 + "\n") * 200
        t = time.time()
        found = code.scan_js("a.js", src)
        self.assertLess(time.time() - t, 2)
        self.assertEqual([(f.rule, f.line) for f in found], [("COD003", 2)])
        js = code._Js("a.js", "f((a, [b]) => { g(c) }, (d) => d)", {})
        self.assertEqual([js.open_before(i) for i in (9, 19, 21, 26, 32)], [2, 17, 14, 24, 1])
        self.assertEqual(js.open_before(0), -1)

    def test_regex_literal_ends_its_declaration(self):
        """const SAFE = /^\\w+$/ no fim da linha: a / que fecha a regex não é uma divisão que continua na linha de baixo
        (o valor declarado engolia o handler inteiro, com a origem dele)."""
        src = "const SAFE = /^\\w+$/\napp.get('/a', (req, res) => res.send(req.query.k))\nconst D = a /\n  b\nfoo()\n"
        js = code._Js("a.js", src, {})
        start = src.index("=") + 1
        self.assertEqual(src[start:js.expr_end(start)], " /^\\w+$/")
        start = src.index("= a") + 1
        self.assertEqual(src[start:js.expr_end(start)], " a /\n  b")

    def test_long_names_in_expressions_stay_fast(self):
        """Um nome de 2900 letras numa expressão com chamada: a busca de chamadas tentava começar em cada letra dele."""
        src = "const q = req.query.a\neval(q)\n" + ("x = q + " + "a" * 2900 + " + f()\n") * 50
        t = time.time()
        found = code.scan_js("a.js", src)
        self.assertLess(time.time() - t, 2)
        self.assertEqual([(f.rule, f.line) for f in found], [("COD003", 2)])
        self.assertEqual(code._opaque_calls("a(b) + c.d(e, f(g)) + h"), "a( ) + c.d(       ) + h")

    def test_return_math_random_finds_its_function_fast(self):
        """return Math.random(): o nome da função vem de um índice do arquivo, não de uma busca nos 1500 caracteres antes
        de cada return (com milhares deles, segundos por arquivo)."""
        src = ("function makeToken() {\n  return Math.random().toString(36)\n}\n"
               "const makeSecret = async () => {\n  return Math.random().toString(36)\n}\n"
               "class K {\n  generateApiKey(): string {\n    return Math.random().toString(36)\n  }\n}\n"
               "function delay() {\n  return Math.random() * 100\n}\n")
        self.assertEqual([(f.rule, f.line) for f in code.scan_js("lib/k.ts", src)], [("COD010", 2), ("COD010", 5), ("COD010", 9)])
        js = code._Js("a.js", "a():\nreturn Math.random()\n" * 6000, {})
        t = time.time()
        js.run()
        self.assertLess(time.time() - t, 1)

    def test_line_numbers_follow_comments_and_strings(self):
        src = EXPRESS + ("/* a comment\n   eval(req.body.a)\n*/\n"
                         "const s = `multi\nline ${1}\ntext`\n"
                         "app.post('/x', (req, res) => { eval(req.body.code) })\n")
        self.assertEqual(got(run({"server.js": src})), [("COD003", "server.js", 9, "critical")])

    def test_vue_script_only(self):
        src = ("<template>\n  <div v-html=\"$route.query.q\"></div>\n  <p>eval(req.body.x)</p>\n</template>\n"
               "<script setup>\nconst q = new URLSearchParams(location.search).get('q')\n</script>\n")
        self.assertEqual(got(run({"src/App.vue": src})), [])

    def test_report_shows_no_source_code_or_secret(self):
        key = "sk-" + "proj-" + "N4bV7cX1zL9kJ3hG6fD2sA8qW5eR0tY"
        src = FLASK + ("import os\n@app.get('/x')\ndef x():\n"
                       f"    os.system('curl -H \"Authorization: Bearer {key}\" ' + request.args['u'])\n")
        d = tempfile.TemporaryDirectory()
        _DIRS.append(d)
        with open(os.path.join(d.name, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(src)
        ctx, findings = scan.run(d.name, offline=True, only={"code"})
        self.assertEqual([f.rule for f in findings], ["COD002"])
        for out in (report.text(ctx, findings, "en"), report.markdown(ctx, findings, "en"),
                    report.as_json(ctx, findings, "en"), report.sarif(ctx, findings, "en")):
            self.assertNotIn(key, out)
            self.assertNotIn("N4bV7cX1", out)

    def test_every_placeholder_gets_a_value(self):
        """Os textos das regras novas usam {sink}, {source}, {what}...: cada achado precisa trazer todos."""
        py = FLASK + ("import os, pickle, yaml, hashlib, random, requests, subprocess, sqlite3\n"
                      "@app.get('/a')\ndef a():\n"
                      "    sqlite3.connect('d').execute(f\"SELECT * FROM t WHERE id = '{request.args['id']}'\")\n"
                      "    os.system('ls ' + request.args['d'])\n"
                      "    eval(request.args['e'])\n"
                      "    pickle.loads(request.data)\n"
                      "    yaml.load(open('c.yml'))\n"
                      "    requests.get(request.args['url'], verify=False)\n"
                      "    open('f/' + request.args['p'])\n"
                      "    return redirect(request.args['next'])\n"
                      "reset_token = str(random.random())\n"
                      "pw = hashlib.md5(password.encode()).hexdigest()\n")
        js = ("import OpenAI from 'openai'\nconst openai = new OpenAI()\n"
              "export async function POST(req) {\n  const b = await req.json()\n"
              "  const r = await openai.chat.completions.create({ model: 'm', messages: [\n"
              "    { role: 'system', content: `Talk like ${b.style} and stay polite` }] })\n"
              "  eval(r.choices[0].message.content)\n  document.body.innerHTML = b.html\n"
              "  return Response.json(r)\n}\n")
        agent = ("from langchain_experimental.tools import PythonREPLTool\nimport torch\n"
                 "t = PythonREPLTool()\nm = torch.load('m.pt', weights_only=False)\n")
        tools = ("from mcp.server.fastmcp import FastMCP\nimport os, requests\nmcp = FastMCP('x')\n"
                 "@mcp.tool()\ndef t(cmd: str, path: str, url: str) -> str:\n"
                 "    os.system(cmd)\n    open(path).read()\n    return requests.get(url).text\n")
        found = run({"app.py": py, "app/api/chat/route.ts": js, "agent.py": agent, "server.py": tools})
        rules = {f.rule for f in found}
        self.assertTrue({"COD001", "COD002", "COD003", "COD004", "COD006", "COD007", "COD009", "COD010", "COD011",
                         "APP009", "APP010", "APP011", "APP012", "APP013", "APP014", "COD005"} <= rules, rules)
        self.assertEqual({f.params["kind"] for f in found if f.rule == "APP014"}, {"shell", "path", "url"})
        fmt = __import__("string").Formatter()
        for f in found:
            for lang in ("pt", "en"):
                for template in RULES[f.rule][lang]:
                    for _, field, _, _ in fmt.parse(template):
                        if field:
                            self.assertTrue(field in f.params or field + "_" + lang in f.params, (f.rule, lang, field))
                title, why, fix = texts(f.rule, lang, f.params)
                self.assertTrue(title and why and fix)


class Helpers(unittest.TestCase):
    def test_secret_and_password_names(self):
        for name in ("reset_token", "apiKey", "API_KEY", "client_secret", "otp", "verification_code", "csrfToken"):
            self.assertTrue(code.secret_name(name), name)
        for name in ("token_count", "keyboard", "monkey", "session_id", "zip_code", "pin_count", "max_tokens", "key"):
            self.assertFalse(code.secret_name(name), name)
        self.assertTrue(code.password_name("new_password"))
        self.assertFalse(code.password_name("password_reset_url"))

    def test_sql_shape(self):
        for text in ("SELECT * FROM t", "  select id, name from users", "INSERT INTO t (a) VALUES (1)", "update users set a = 1",
                     "DELETE FROM t", "WITH x AS (SELECT 1) SELECT * FROM x", "create table t (id int)"):
            self.assertTrue(code.looks_sql(text), text)
        for text in ("Select an option from the list", "Please update your profile", "delete this chat?", ""):
            self.assertFalse(code.looks_sql(text), text)

    def test_js_mask_blanks_comments_strings_and_regex(self):
        text = "const a = 'x(' // c(\nconst r = /[(]/g; const t = `a ${b(1)} c`\n<div>Don't</div>\n"
        c, m, lits = code._js_mask(text)
        self.assertEqual((len(c), len(m)), (len(text), len(text)))
        self.assertEqual(m.count("("), 1)  # só o b( de dentro do ${...}
        self.assertNotIn("//", c)
        self.assertTrue(lits)


if __name__ == "__main__":
    unittest.main()
