#!/usr/bin/env bash
# Install Blindspot dependencies on Debian/Ubuntu.
# System packages need sudo; everything else installs into backend/.venv.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"

echo "==> system packages (WeasyPrint needs libpango)"
if command -v apt-get >/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq python3-venv libpango-1.0-0 libpangocairo-1.0-0
else
  echo "no apt-get found; install python3-venv and libpango manually" >&2
fi

echo "==> python virtualenv"
python3 -m venv "$BACKEND/.venv"
# shellcheck disable=SC1091
source "$BACKEND/.venv/bin/activate"
pip install -q --upgrade pip
pip install -q -e "$BACKEND"

echo "==> frontend"
if command -v npm >/dev/null; then
  (cd "$ROOT/frontend" && npm install && npm run build)
else
  echo "npm not found; skipping frontend build (console will be API-only)" >&2
fi

echo
echo "Done. Start with:  (cd $BACKEND && .venv/bin/blindspot serve)"
echo
echo "Optional tools (graceful when missing):"
echo "  JADX   https://github.com/skylot/jadx        # Java/Kotlin decompilation"
echo "  apktool https://apktool.org                   # resource/smali decoding"
echo "  Ollama  https://ollama.com/download           # local AI review (see docs/MODEL_SETUP.md)"
