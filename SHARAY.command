#!/bin/zsh
set -e
cd "${0:A:h}"
if [[ ! -x .venv/bin/python ]]; then
  print "Install SHARAY first using the README instructions."
  read -r "?Press Return to close."
  exit 1
fi
.venv/bin/python -m sharay desktop
