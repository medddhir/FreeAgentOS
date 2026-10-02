#!/bin/sh
# Run only reviewed checkout code; no downloads or privileged commands here.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
  echo 'MISSING_PYTHON: Install Python 3.12+ and its venv support manually.' >&2
  exit 4
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' ; then
  echo 'PYTHON_UNSUPPORTED: Python 3.12+ is required.' >&2
  exit 4
fi
if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
  echo 'VENV_SUPPORT_MISSING: Install Python venv support manually (Ubuntu: python3.12-venv).' >&2
  exit 4
fi
exec python3 "$(dirname "$0")/orchestrator/bootstrap.py" "$@"
