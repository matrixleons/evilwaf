#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
  exec python3 /app/evilwaf.py -h
fi

exec python3 /app/evilwaf.py "$@"
