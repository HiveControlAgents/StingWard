#!/usr/bin/env python3
"""Roda o stingward que vem junto com o plugin; sem ele, usa o instalado no sistema."""
import os
import sys

# Antes de qualquer outro import: sem -I, um PYTHONPATH com item vazio põe a pasta atual (a que está sendo checada)
# no sys.path, e o json.py ou o shutil.py dela rodaria no lugar do da biblioteca padrão.
try:
    _cwd = os.path.realpath(os.getcwd())
except OSError:
    _cwd = None
sys.path[:] = [p for p in sys.path if p and os.path.realpath(p) != _cwd]

import shutil
import subprocess

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if os.path.isfile(os.path.join(root, "stingward", "cli.py")):
    sys.path.insert(0, root)
    from stingward.cli import main
    sys.exit(main())
exe = shutil.which("stingward")
if exe:
    sys.exit(subprocess.call([exe] + sys.argv[1:]))
sys.exit("stingward não encontrado / not found. Instale / install: pipx install stingward (ou / or: uvx stingward, npx stingward)")
