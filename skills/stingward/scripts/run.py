#!/usr/bin/env python3
"""Roda o stingward que vem junto com o plugin; sem ele, usa o instalado no sistema."""
import os
import shutil
import subprocess
import sys

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if os.path.isfile(os.path.join(root, "stingward", "cli.py")):
    sys.path.insert(0, root)
    from stingward.cli import main
    sys.exit(main())
exe = shutil.which("stingward")
if exe:
    sys.exit(subprocess.call([exe] + sys.argv[1:]))
sys.exit("stingward não encontrado. Instale com: pipx install git+https://github.com/HiveControlAgents/StingWard "
         "(ou uvx --from git+https://github.com/HiveControlAgents/StingWard stingward)")
