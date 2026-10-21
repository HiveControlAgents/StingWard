"""De ponta a ponta, do jeito que as pessoas usam: a skill do Claude Code, o lançador do npm, os passos da Action,
o site e os pacotes publicados. Nada aqui usa a rede; os segredos de teste são falsos e montados por concatenação.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from stingward import cli, report, vulndb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_DIR = os.path.join(ROOT, "skills", "stingward")
# Onde o Claude Code costuma instalar a skill do plugin: é o valor de ${CLAUDE_SKILL_DIR} nos testes de permissão.
INSTALLED = "/home/ana/.claude/plugins/cache/stingward/stingward/0.1.5/skills/stingward"


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- a skill do Claude Code

def _skill():
    text = _read("skills", "stingward", "SKILL.md")
    front, _, body = text[4:].partition("\n---\n")
    tools = re.search(r"^allowed-tools: (.+)$", front, re.M).group(1)
    return tools, body


def _bash_rules(skill_dir=INSTALLED):
    """As regras Bash(...) de allowed-tools, com ${CLAUDE_SKILL_DIR} trocado como o Claude Code troca."""
    tools, _ = _skill()
    return [r.replace("${CLAUDE_SKILL_DIR}", skill_dir) for r in re.findall(r"Bash\(([^)]*)\)", tools)]


def _allowed(rule, command):
    """Como o Claude Code compara uma regra Bash com o texto do comando: `*` vale qualquer texto, espaços inclusive;
    `:*` no fim é o mesmo que ` *`; e um ` *` final, quando é o único curinga, também aceita o comando sem nada depois."""
    if rule.endswith(":*"):
        rule = rule[:-2] + " *"
    if "*" not in rule:
        return command == rule
    if rule.endswith(" *") and rule.count("*") == 1 and command == rule[:-2]:
        return True
    return re.fullmatch(".*".join(re.escape(part) for part in rule.split("*")), command, re.S) is not None


def _skill_commands(skill_dir=INSTALLED, target="owner/repo"):
    """Os comandos da tabela "Run it", como o modelo os digita."""
    _, body = _skill()
    commands = re.findall(r"`(python3 [^`]+)`", body.split("## Run it", 1)[1].split("\n## ", 1)[0])
    commands = [c.replace("${CLAUDE_SKILL_DIR}", skill_dir).replace("<skill-dir>", skill_dir) for c in commands]
    return [re.sub(r"<[^>]+>", lambda _: target, c) for c in commands]  # um caminho do Windows tem \\ que re.sub leria


class SkillPermissions(unittest.TestCase):
    """allowed-tools aprova comandos sem perguntar enquanto a skill lê arquivos de terceiros, que podem trazer
    instruções escondidas. Só o que a skill manda rodar pode passar, e nada além disso."""

    def test_every_command_the_skill_gives_is_pre_approved(self):
        commands = _skill_commands()
        self.assertEqual(len(commands), 3, commands)
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(any(_allowed(rule, command) for rule in _bash_rules()), _bash_rules())

    def test_no_other_program_or_file_write_is_pre_approved(self):
        d = INSTALLED
        hostile = [
            f"python3 /tmp/evil.py {d}/scripts/run.py .",
            f"python3 -c 'import os; os.system(\"id\")' {d}/scripts/run.py .",
            f"python3 {d}/../../evil/scripts/run.py .",
            "stingward . --json /home/ana/.bashrc",
            f"python3 -I {d}/scripts/run.py . --format json --fail-on never --json /home/ana/.bashrc",
            f"python3 -I {d}/scripts/run.py agents --html /home/ana/.bashrc --format json --fail-on never",
            f"python3 -I {d}/scripts/run.py . --review-template /home/ana/.profile --format json --fail-on never",
        ]
        for command in hostile:
            with self.subTest(command=command):
                self.assertFalse(any(_allowed(rule, command) for rule in _bash_rules()), _bash_rules())

    def test_what_the_wildcard_takes_cannot_become_an_option(self):
        """A regra de `skill` deixa o alvo livre; depois de `--` ele não vira --json, --html nem --review-template."""
        with tempfile.TemporaryDirectory() as tmp:
            target, out = os.path.join(tmp, "a-skill"), os.path.join(tmp, "written.txt")
            os.makedirs(target)
            command = next(c for c in _skill_commands(target=target) if " skill " in c)
            argv = command.split(f"{INSTALLED}/scripts/run.py ", 1)[1].split(" ")
            self.assertTrue(any(_allowed(rule, command + " --json " + out) for rule in _bash_rules()))
            code, _, err = _cli(argv + ["--json", out, "--offline"])
            self.assertEqual(code, 2, err)
            self.assertFalse(os.path.exists(out))
            # Como a skill manda: outras opções logo depois de run.py.
            code, stdout, err = _cli(["--offline"] + argv)
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(stdout)["tool"], "stingward")

    def test_the_skill_command_runs_on_python_3_9_to_3_12(self):
        """Até o Python 3.12, o argparse não aceita `skill --opção -- alvo`: os dois posicionais opcionais já foram
        consumidos quando o `--` chega, e sai "unrecognized arguments" (código 2). As opções vão antes de `skill`."""
        for command in _skill_commands(target="x"):
            args = command.split("/scripts/run.py ", 1)[1].split(" ")
            if "skill" in args:
                with self.subTest(command=command):
                    self.assertEqual(args[args.index("skill") + 1:], ["--", "x"])
        self.assertIn("right after `run.py`", _skill()[1])

    def test_the_launcher_never_imports_code_from_the_checked_folder(self):
        """`export PYTHONPATH=$PYTHONPATH:/x` com PYTHONPATH vazio deixa um item vazio, que o Python lê como a pasta atual."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "imported")
            for name in ("json.py", "shutil.py"):
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                    fh.write(f"open({marker!r}, 'w').close()\nraise SystemExit(7)\n")
            env = {**os.environ, "PYTHONPATH": os.pathsep + os.path.join(tmp, "nothing-here"), "STINGWARD_CACHE": tmp}
            command = next(c for c in _skill_commands(skill_dir=SKILL_DIR) if " agents " in c)
            argv = [sys.executable] + command.split(" ")[1:]
            run = subprocess.run(argv, cwd=tmp, env={**env, "HOME": tmp, "USERPROFILE": tmp}, capture_output=True, text=True,
                                 encoding="utf-8", timeout=120)
            self.assertFalse(os.path.exists(marker), "the launcher imported a module from the checked folder")
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["tool"], "stingward")


    def test_the_launcher_is_safe_even_without_isolated_mode(self):
        """Quem roda run.py sem -I (outro agente, um script, o CI) também não pode importar o json.py da pasta checada."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "imported")
            for name in ("json.py", "shutil.py", "subprocess.py"):
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                    fh.write(f"open({marker!r}, 'w').close()\nraise SystemExit(7)\n")
            env = {**os.environ, "PYTHONPATH": os.pathsep + os.path.join(tmp, "nothing-here"), "STINGWARD_CACHE": tmp,
                   "HOME": tmp, "USERPROFILE": tmp}
            for argv in (["--version"], ["agents", "--format", "json", "--fail-on", "never"]):
                with self.subTest(argv=argv):
                    run = subprocess.run([sys.executable, os.path.join(SKILL_DIR, "scripts", "run.py")] + argv, cwd=tmp,
                                         env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
                    self.assertFalse(os.path.exists(marker), "run.py imported a module from the checked folder")
                    self.assertEqual(run.returncode, 0, run.stderr)


class SkillReportBack(unittest.TestCase):
    """O modelo lê o JSON e responde ao usuário. A skill tem de dizer o que o JSON não diz sozinho."""

    def test_the_skill_gives_the_verdict_the_command_line_prints(self):
        """O JSON não traz o veredito de `skill`: a skill diz a regra e as mesmas palavras do relatório em texto."""
        _, body = _skill()
        for key in ("verdict_bad", "verdict_mid", "verdict_ok"):
            with self.subTest(key=key):
                self.assertIn(report.T["en"][key].split(" ", 1)[1], body)
        # Arquivo que a varredura não leu: o veredito de "incompleta", com as mesmas palavras fixas.
        for piece in report.T["en"]["verdict_incomplete"].split(" ", 1)[1].split("{why}"):
            self.assertIn(piece.strip(" ,.:"), body)
        self.assertIn("`not_read.too_big`", body)
        self.assertIn("`not_read.truncated`", body)

    def test_the_skill_says_when_dependencies_were_not_checked(self):
        """Com --fail-on never o código de saída 3 some; só `sources` mostra que o OSV.dev não respondeu."""
        _, body = _skill()
        self.assertIn("`sources.osv`", body)
        self.assertIn("`sources.osv_error`", body)
        self.assertIn("If both `sources.osv` and `sources.osv_error` are set", body)  # resposta parcial (checks/deps.py)
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as fh:
                json.dump({"lockfileVersion": 3, "packages": {"node_modules/left-pad": {"version": "1.3.0"}}}, fh)
            sources = {}
            _, out, _ = _cli([tmp, "--offline", "--format", "json", "--fail-on", "never"])
            sources["offline"] = json.loads(out)["sources"]
            with mock.patch.object(vulndb, "osv_query", side_effect=vulndb.NetError("timed out")):
                _, out, _ = _cli([tmp, "--format", "json", "--fail-on", "never"])
            sources["down"] = json.loads(out)["sources"]
            with mock.patch.object(vulndb, "osv_query", return_value=[[]]):
                _, out, _ = _cli([tmp, "--format", "json", "--fail-on", "never"])
            sources["checked"] = json.loads(out)["sources"]
        self.assertEqual([s.get("osv") for s in sources.values()], [None, None, True], sources)
        self.assertIn("osv_error", sources["down"])
        self.assertEqual({s["packages"] for s in sources.values()}, {1})

    def test_options_the_skill_mentions_exist(self):
        known = {o for a in cli._parser()._actions for o in a.option_strings}
        _, body = _skill()
        for opt in set(re.findall(r"(--[a-z][a-z-]+)", body)):
            with self.subTest(option=opt):
                self.assertIn(opt, known)

    def test_the_skill_offers_the_html_report(self):
        _, body = _skill()
        self.assertIn("--html", body)


# --------------------------------------------------------------------------- o lançador do npm (npx stingward)

NODE = shutil.which("node")
POSIX = os.name == "posix"


def _sh(path, body):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)


@unittest.skipUnless(NODE, "needs Node.js, like npx")
class NpmLauncher(unittest.TestCase):
    """npm/bin/stingward.js como o npm instala: bin/ e a cópia do pacote Python lado a lado, numa pasta com espaço."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pkg = os.path.join(cls.tmp.name, "node modules", "stingward")
        os.makedirs(os.path.join(cls.pkg, "bin"))
        shutil.copy(os.path.join(ROOT, "npm", "bin", "stingward.js"), os.path.join(cls.pkg, "bin"))
        shutil.copytree(os.path.join(ROOT, "stingward"), os.path.join(cls.pkg, "stingward"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        cls.launcher = os.path.join(cls.pkg, "bin", "stingward.js")
        cls.work = os.path.join(cls.tmp.name, "work")
        os.makedirs(cls.work)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def bin_dir(self, **shims):
        """Uma pasta só com estes "Pythons": good repassa ao Python dos testes; old diz 3.8 e quebra com -I, como um
        Python velho quebra no código do pacote; killed responde a versão e morre com SIGTERM ao rodar o pacote."""
        d = tempfile.mkdtemp(dir=self.tmp.name)
        real = sys.executable
        bodies = {"good": f'exec "{real}" "$@"\n',
                  "old": "case \"$*\" in *-I*) echo 'SyntaxError: future feature annotations is not defined' >&2; exit 1;; esac\n"
                         "printf 3.8\n",
                  "killed": f'case "$*" in *-I*) kill -TERM $$;; esac\nexec "{real}" "$@"\n'}
        for name, kind in shims.items():
            _sh(os.path.join(d, name), bodies[kind])
        return d

    def run_launcher(self, args, path_dir, cwd=None):
        env = {k: v for k, v in os.environ.items() if k.upper() not in ("PATH", "PYTHONPATH")}
        env.update({"PATH": path_dir, "STINGWARD_CACHE": self.tmp.name})
        return subprocess.run([NODE, self.launcher] + args, cwd=cwd or self.work, env=env, capture_output=True, text=True,
                              encoding="utf-8", timeout=180)

    def test_without_python_it_says_what_it_needs(self):
        run = self.run_launcher(["--version"], tempfile.mkdtemp(dir=self.tmp.name))
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("Python 3.9", run.stderr)

    @unittest.skipUnless(POSIX, "the fake Pythons are shell scripts")
    def test_a_python_older_than_3_9_is_not_run(self):
        """Antes, o Python 3.8 rodava o pacote, quebrava e o código de saída era 1, o mesmo de "achou problema"."""
        run = self.run_launcher(["--version"], self.bin_dir(python3="old"))
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("Python 3.9", run.stderr)
        self.assertIn("3.8", run.stderr)
        self.assertNotIn("SyntaxError", run.stderr)

    @unittest.skipUnless(POSIX, "the fake Pythons are shell scripts")
    def test_an_old_python3_falls_back_to_python(self):
        run = self.run_launcher(["--version"], self.bin_dir(python3="old", python="good"))
        self.assertEqual((run.returncode, run.stdout.strip()), (0, f"stingward {cli.__version__}"), run.stderr)

    @unittest.skipUnless(POSIX, "the fake Pythons are shell scripts")
    def test_exit_codes_and_arguments_pass_through_unchanged(self):
        project = os.path.join(self.work, "my app; touch pwned $(touch pwned2)")
        os.makedirs(project, exist_ok=True)
        with open(os.path.join(project, "config.js"), "w", encoding="utf-8") as fh:
            fh.write('const key = "' + "sk-ant-" + "api03-" + "Q7wErTy8UiOp2AsDfGh5JkLzXcVbNm1234567890abcd" + '";\n')
        bins = self.bin_dir(python3="good")
        run = self.run_launcher([project, "--offline", "--format", "json"], bins)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("SEC001", {f["rule"] for f in json.loads(run.stdout)["findings"]})
        self.assertEqual(self.run_launcher([project, "--offline", "--fail-on", "never"], bins).returncode, 0)
        self.assertEqual(self.run_launcher([project, "--format", "xml"], bins).returncode, 2)
        self.assertEqual([f for f in os.listdir(self.work) if f.startswith("pwned")], [])

    @unittest.skipUnless(POSIX, "signals")
    def test_a_python_killed_by_a_signal_is_not_reported_as_findings(self):
        """Código 1 quer dizer "achou problema". Um Python morto por sinal sai com o mesmo sinal."""
        run = self.run_launcher(["--version"], self.bin_dir(python3="killed"))
        self.assertIn(run.returncode, (-15, 143), run.stderr)

    def test_on_windows_it_asks_the_py_launcher_for_python_3(self):
        code = "const w = require(process.argv[1]); console.log(JSON.stringify(w.candidates('win32')))"
        run = subprocess.run([NODE, "-e", code, self.launcher], cwd=self.work, capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(run.stdout.strip() or "null"), [["py", "-3"], ["python"], ["python3"]], run.stderr)


# --------------------------------------------------------------------------- os passos da GitHub Action

BASH = shutil.which("bash")


def _action_step(marker):
    """O script `run:` do passo de action.yml que contém `marker`, sem a indentação do YAML."""
    for step in re.split(r"\n(?=    - )", _read("action.yml").split("\n  steps:\n", 1)[1]):
        if marker in step:
            lines = step.split("\n")
            i = next(n for n, line in enumerate(lines) if line.strip() == "run: |")
            pad = len(lines[i]) - len(lines[i].lstrip()) + 2
            return "\n".join(line[pad:] for line in lines[i + 1:] if line[:pad].strip() == "").rstrip("\n") + "\n"
    raise AssertionError(f"no step with {marker!r} in action.yml")


@unittest.skipUnless(BASH and POSIX, "the Action runs its steps with bash; the fake gh is a shell script")
class ActionSteps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(os.path.join(self.tmp, "runner", "stingward"))
        with open(os.path.join(self.tmp, "runner", "stingward", "stingward.md"), "w", encoding="utf-8") as fh:
            fh.write("<!-- stingward-report -->\n### report\n")
        self.calls = os.path.join(self.tmp, "gh-calls")

    def run_step(self, marker, env, gh=None, cwd=None):
        bins = os.path.join(self.tmp, "bin")
        os.makedirs(bins, exist_ok=True)
        if gh is not None:
            _sh(os.path.join(bins, "gh"), f'echo "$*" >> "{self.calls}"\n' + gh)
        script = os.path.join(self.tmp, "step.sh")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(_action_step(marker))
        base = {"PATH": bins + os.pathsep + os.environ["PATH"], "HOME": self.tmp, "RUNNER_TEMP": os.path.join(self.tmp, "runner"),
                "GITHUB_OUTPUT": os.path.join(self.tmp, "output"), "GITHUB_STEP_SUMMARY": os.path.join(self.tmp, "summary")}
        # Como o runner: bash --noprofile --norc -eo pipefail {0}
        return subprocess.run([BASH, "--noprofile", "--norc", "-eo", "pipefail", script], cwd=cwd or self.tmp,
                              env=dict(base, **env), capture_output=True, text=True, timeout=180)

    def gh_calls(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls, encoding="utf-8") as fh:
            return fh.read().splitlines()

    PR = {"GH_TOKEN": "x", "PR": "7", "REPO": "ana/app", "HEAD_REPO": "ana/app"}

    def test_the_comment_is_updated_not_posted_again(self):
        run = self.run_step("GH_TOKEN", self.PR, gh='case "$*" in *--paginate*) echo 991; echo 992;; esac\n')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual([c.split()[:3] for c in self.gh_calls()[1:]], [["api", "-X", "PATCH"]])
        self.assertIn("repos/ana/app/issues/comments/991", self.gh_calls()[1])

    def test_the_first_run_posts_one_comment(self):
        run = self.run_step("GH_TOKEN", self.PR, gh="")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual([c.split()[:4] for c in self.gh_calls()[1:]], [["api", "-X", "POST", "repos/ana/app/issues/7/comments"]])

    def test_a_read_only_token_leaves_a_note_not_a_failed_step(self):
        """Num PR de fork (ou do Dependabot) o token só lê: antes o passo falhava com um 403 sem explicação."""
        deny = 'case "$*" in *-X*) echo "HTTP 403: Resource not accessible by integration" >&2; exit 1;; esac\n'
        fork = self.run_step("GH_TOKEN", dict(self.PR, HEAD_REPO="someone/app"), gh=deny)
        self.assertEqual(fork.returncode, 0, fork.stderr)
        self.assertIn("::notice::", fork.stdout)
        self.assertIn("fork", fork.stdout)
        own = self.run_step("GH_TOKEN", self.PR, gh=deny)
        self.assertEqual(own.returncode, 0, own.stderr)
        self.assertIn("::warning::", own.stdout)
        self.assertIn("pull-requests: write", own.stdout)

    def test_the_scan_step_takes_the_path_as_data(self):
        project = os.path.join(self.tmp, "my app $(touch pwned); `touch pwned2`")
        os.makedirs(project)
        with open(os.path.join(project, "app.py"), "w", encoding="utf-8") as fh:
            fh.write('print("hello")\n')
        env = {"PY": sys.executable, "STINGWARD_HOME": ROOT, "STINGWARD_PATH": project, "STINGWARD_FAIL_ON": "high",
               "STINGWARD_LANG": "en", "STINGWARD_CACHE": self.tmp,
               # Sem dependências não há o que perguntar ao OSV.dev; o proxy morto garante que nada sai para a rede.
               "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}
        run = self.run_step("id: scan", env)
        self.assertEqual(run.returncode, 0, run.stderr)
        with open(os.path.join(self.tmp, "output"), encoding="utf-8") as fh:
            out = dict(line.split("=", 1) for line in fh.read().splitlines())
        self.assertEqual(out["grade"], "A")
        self.assertEqual(out["exit_code"], "0")
        with open(os.path.join(self.tmp, "summary"), encoding="utf-8") as fh:
            self.assertIn("<!-- stingward-report -->", fh.read())
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith("pwned")], [])


    def test_an_empty_folder_gives_no_grade_and_fails_the_job(self):
        """Nada lido: a saída grade não pode virar o texto "None" do Python, e o job não passa (código 4)."""
        project = os.path.join(self.tmp, "empty")
        os.makedirs(project)
        env = {"PY": sys.executable, "STINGWARD_HOME": ROOT, "STINGWARD_PATH": project, "STINGWARD_FAIL_ON": "high",
               "STINGWARD_LANG": "en", "STINGWARD_CACHE": self.tmp,
               "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}
        run = self.run_step("id: scan", env)
        self.assertEqual(run.returncode, 0, run.stderr)
        with open(os.path.join(self.tmp, "output"), encoding="utf-8") as fh:
            out = dict(line.split("=", 1) for line in fh.read().splitlines())
        self.assertEqual(out["grade"], "none")
        self.assertEqual(out["exit_code"], "4")


class ActionPermissions(unittest.TestCase):
    def test_two_runs_in_one_workflow_can_keep_their_own_sarif(self):
        """Com uma categoria fixa, duas pastas auditadas no mesmo workflow (um monorepo) apagam o SARIF uma da outra."""
        action = _read("action.yml")
        self.assertRegex(action, r"\n  category:\n    description: .+\n    default: stingward\n")
        sarif_step = next(step for step in re.split(r"\n(?=    - )", action) if "upload-sarif" in step)
        self.assertIn("category: ${{ inputs.category }}", sarif_step)

    def test_the_sarif_input_names_every_permission_the_upload_needs(self):
        """O upload-sarif pergunta à API qual workflow está rodando: num repositório privado isso pede actions: read, e
        sem ela o envio falha calado (o passo tem continue-on-error)."""
        sarif = re.search(r"^  sarif:\n    description: (.+)$", _read("action.yml"), re.M).group(1)
        self.assertIn("actions read", sarif)
        for doc in ("README.md", "README.pt-BR.md", "README.es.md"):
            row = re.search(r"^\| `sarif` \|.+$", _read(doc), re.M).group(0)
            with self.subTest(doc=doc):
                self.assertIn("`security-events: write`", row)
                self.assertIn("`actions: read`", row)
        self.assertRegex(_read("examples", "stingward.yml"), r"\n  # actions: read +# .*private")


# --------------------------------------------------------------------------- o site

class SiteFocus(unittest.TestCase):
    def test_nothing_that_takes_keyboard_focus_is_clipped(self):
        """clip-path recorta também o contorno de foco: numa versão anterior do site, a aba "Instalar" focada pelo
        teclado não mostrava nada. Os fundos cor de mel, com o canto cortado, são recortados; nada que recebe foco pode
        ser, e todo foco de teclado tem contorno."""
        css = re.sub(r"/\*.*?\*/", "", _read("site", "style.css"), flags=re.S)
        rules = {}
        for sels, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
            for sel in sels.split(","):
                rules[sel.strip()] = rules.get(sel.strip(), "") + body
        markup = _read("site", "page.html") + _read("site", "build.py")
        focusable = {"button"}  # offer() e copy_button() recebem a classe como argumento
        for classes in re.findall(r'<(?:a|button|input|summary|select|textarea)\b[^>]*?class="([^"{}]+)"', markup):
            focusable |= set(classes.split())
        clipped = [sel for sel, body in rules.items() if "clip-path" in body]
        self.assertTrue(clipped)
        for sel in clipped:
            target = re.split(r"[\s>+~]+", sel)[-1]  # o elemento que a regra desenha
            if "::" in target:  # um pseudo-elemento fica dentro do elemento; o contorno do elemento não é recortado
                continue
            with self.subTest(selector=sel):
                self.assertFalse(set(re.findall(r"\.([\w-]+)", target)) & focusable)
        self.assertRegex(rules[":focus-visible"], r"outline:\s*3px solid")
        for sel, body in rules.items():
            if ":focus" in sel:
                with self.subTest(selector=sel):
                    self.assertNotRegex(body, r"outline:\s*(?:none|0)")


# --------------------------------------------------------------------------- os pacotes do PyPI

DIST = os.environ.get("STINGWARD_DIST")


def _package_files():
    """Os arquivos .py do pacote, como caminhos do pacote publicado (stingward/checks/x.py)."""
    out = set()
    for folder, dirs, files in os.walk(os.path.join(ROOT, "stingward")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        out |= {os.path.relpath(os.path.join(folder, f), ROOT).replace(os.sep, "/") for f in files if f.endswith(".py")}
    return out


@unittest.skipUnless(DIST, "set STINGWARD_DIST to the folder `python -m build` wrote (the CI package job does)")
class Packaging(unittest.TestCase):
    def _one(self, suffix):
        found = [os.path.join(DIST, f) for f in os.listdir(DIST) if f.endswith(suffix)]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_the_sdist_holds_the_package_and_its_metadata_only(self):
        """Os testes não rodam a partir do sdist (faltam os arquivos que eles leem): ficam no repositório."""
        with tarfile.open(self._one(".tar.gz")) as tar:
            names = {n.split("/", 1)[1] for n in tar.getnames() if "/" in n}
        meta = {"PKG-INFO", "README.md", "LICENSE", "NOTICE", "pyproject.toml", "setup.cfg", "MANIFEST.in"}
        files = {n for n in names if not n.endswith("/") and n not in {"stingward", "stingward/checks", "stingward.egg-info"}}
        extra = {n for n in files - meta - _package_files() if not n.startswith("stingward.egg-info/")}
        self.assertEqual(extra, set())
        self.assertLessEqual(_package_files() | {"LICENSE", "NOTICE", "README.md", "pyproject.toml"}, files)

    def test_the_wheel_holds_the_package_and_its_licenses_only(self):
        with zipfile.ZipFile(self._one(".whl")) as whl:
            names = set(whl.namelist())
        info = f"stingward-{cli.__version__}.dist-info/"
        self.assertEqual({n for n in names if not n.startswith(info)}, _package_files())
        self.assertLessEqual({info + "licenses/LICENSE", info + "licenses/NOTICE"}, names)



# --------------------------------------------------------------------------- o CI e o que os documentos dizem dele

def _ci_jobs():
    """Cada job de ci.yml com o número de execuções que a matriz dele gera, e as versões de Python dos testes."""
    jobs = re.split(r"^  ([a-z][a-z-]*):\n", _read(".github", "workflows", "ci.yml").split("\njobs:\n", 1)[1], flags=re.M)[1:]
    runs, pythons = {}, []
    for name, body in zip(jobs[::2], jobs[1::2]):
        n = 1
        matrix = body.split("matrix:", 1)[1].split("steps:", 1)[0] if "matrix:" in body else ""
        for key, values in re.findall(r"([a-z]+): \[([^\]]*)\]", matrix):
            items = [v.strip().strip('"') for v in values.split(",")]
            n *= len(items)
            if key == "python":
                pythons = items
        runs[name] = n
    return runs, pythons


class SupportedPythons(unittest.TestCase):
    def test_the_classifiers_name_the_pythons_ci_tests(self):
        _, pythons = _ci_jobs()
        pyproject = _read("pyproject.toml")
        classifiers = re.findall(r'"Programming Language :: Python :: (3\.\d+)"', pyproject)
        self.assertEqual(classifiers, pythons)
        self.assertIn(f'requires-python = ">={pythons[0]}"', pyproject)

    def test_the_readmes_count_the_ci_jobs_and_pythons_right(self):
        runs, pythons = _ci_jobs()
        for doc, pattern in (("README.md", r"runs (\d+) CI jobs.+?Python ([\d.]+) to ([\d.]+)"),
                             ("README.pt-BR.md", r"roda (\d+) jobs de CI.+?Python ([\d.]+) a ([\d.]+)"),
                             ("README.es.md", r"ejecuta (\d+) jobs de CI.+?Python ([\d.]+) a ([\d.]+)")):
            with self.subTest(doc=doc):
                said = re.search(pattern, _read(doc)).groups()
                self.assertEqual(said, (str(sum(runs.values())), pythons[0], pythons[-1]))


class PinnedTools(unittest.TestCase):
    def test_workflows_run_exact_npm_versions(self):
        """`npm@latest` roda no job que publica com id-token, e o `npx` do CI baixa o que saiu por último: uma versão
        comprometida rodaria aqui no mesmo dia. Pacote do registro só com versão exata."""
        workflows = os.path.join(ROOT, ".github", "workflows")
        seen = []
        for name in sorted(os.listdir(workflows)):
            text = _read(".github", "workflows", name)
            for spec in re.findall(r"\b(?:npm install -g|npm i -g|npx -y|npx --yes) (\S+)", text):
                if spec.startswith((".", "/")):
                    continue  # o pacote recém-montado, do disco
                seen.append(spec)
                with self.subTest(workflow=name, package=spec):
                    self.assertRegex(spec, r"^(@[a-z0-9-]+/)?[a-z0-9.-]+@\d+\.\d+\.\d+$")
        self.assertGreaterEqual(len(seen), 2, seen)


BLOB = "https://github.com/HiveControlAgents/StingWard/blob/main/"


class ReadmeOnPyPI(unittest.TestCase):
    def test_readme_links_work_outside_github(self):
        """O PyPI mostra o README.md fora do GitHub: um link relativo (docs/rules.md, LICENSE) vira 404 lá. Os links
        apontam para o GitHub, e cada um para um arquivo que existe."""
        for doc in ("README.md", "README.pt-BR.md", "README.es.md"):
            text = _read(doc)
            targets = re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'(?:href|src)="([^"]+)"', text)
            for t in targets:
                with self.subTest(doc=doc, link=t):
                    self.assertRegex(t, r"^(https?:|mailto:|#)")
                    if t.startswith(BLOB):
                        self.assertTrue(os.path.exists(os.path.join(ROOT, t[len(BLOB):].split("#", 1)[0])), t)
