#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -z "${LAB:-}" ]]; then
  echo 'Run inside the initialized 2026f-v1 course container (LAB is missing).' >&2
  exit 1
fi
if [[ -x "$LAB/.venv/bin/python3" ]]; then
  exec "$LAB/.venv/bin/python3" run_all.py "$@"
else
  exec python3 run_all.py "$@"
fi
