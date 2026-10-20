#!/bin/sh
# Copia o pacote Python para dentro de npm/ antes de `npm publish`.
set -e
cd "$(dirname "$0")/.."
rm -rf npm/stingward
cp -r stingward npm/stingward
find npm/stingward -name __pycache__ -prune -exec rm -rf {} +
cp README.md LICENSE NOTICE npm/
echo "pronto: cd npm && npm publish"
