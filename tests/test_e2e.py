"""De ponta a ponta, do jeito que as pessoas usam: a skill do Claude Code, o lançador do npm, os passos da Action
e os pacotes publicados. Nada aqui usa a rede; os segredos de teste são falsos e montados por concatenação.
"""
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
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
    return [re.sub(r"<[^>]+>", target, c) for c in commands]


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
            cut = argv.index("--") if "--" in argv else len(argv)
            code, stdout, _ = _cli(argv[:cut] + ["--offline"] + argv[cut:])
            self.assertEqual((code, json.loads(stdout)["tool"]), (0, "stingward"))

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


class SkillReportBack(unittest.TestCase):
    """O modelo lê o JSON e responde ao usuário. A skill tem de dizer o que o JSON não diz sozinho."""

    def test_the_skill_gives_the_verdict_the_command_line_prints(self):
        """O JSON não traz o veredito de `skill`: a skill diz a regra e as mesmas palavras do relatório em texto."""
        _, body = _skill()
        for key in ("verdict_bad", "verdict_mid", "verdict_ok"):
            with self.subTest(key=key):
                self.assertIn(report.T["en"][key].split(" ", 1)[1], body)

    def test_the_skill_says_when_dependencies_were_not_checked(self):
        """Com --fail-on never o código de saída 3 some; só `sources` mostra que o OSV.dev não respondeu."""
        _, body = _skill()
        self.assertIn("`sources.osv`", body)
        self.assertIn("`sources.osv_error`", body)
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
