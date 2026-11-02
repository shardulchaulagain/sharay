#!/usr/bin/env bash
# SHARAY installer: sets up a self-contained local install with its OWN fresh database.
# Safe to re-run. The database (aegis.db in the data dir) is created per-install and is gitignored,
# so it never ships with the source.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3.13}"
DATA_DIR="${SHARAY_DATA_DIR:-.aegis}"   # gitignored; override with SHARAY_DATA_DIR=...

command -v "$PYTHON" >/dev/null 2>&1 || { echo "Need $PYTHON on PATH (set PYTHON=... to override)."; exit 1; }

echo "[1/4] Creating virtualenv (.venv)…"
[ -d .venv ] || "$PYTHON" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/4] Installing dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "[3/4] Creating this install's database (migrations applied automatically)…"
python -m aegis --data-dir "$DATA_DIR" migrate

echo "[4/4] Checking tooling (Podman is needed for the egress-isolated scanners)…"
python -m aegis --data-dir "$DATA_DIR" preflight || true

cat <<EOF

SHARAY is installed. Its database lives in '$DATA_DIR/aegis.db' (gitignored — never committed).

Next steps:
  source .venv/bin/activate
  python -m aegis --data-dir "$DATA_DIR" init-owner     # create your operator account (no default credentials)
  python -m aegis --data-dir "$DATA_DIR" serve          # start the API + web UI (http://127.0.0.1:8765)

For Podman on macOS, first run: podman machine init && podman machine start
EOF
