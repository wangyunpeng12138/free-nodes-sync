#!/usr/bin/env bash
# 拉取上游 txt 订阅并转换为 Clash 配置
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python

echo "=== 拉取上游 txt 订阅并转换为 Clash 配置 ==="
"$PY" src/txt2clash.py "$@"
echo "[ok] 完成，输出目录：$(pwd)/output"
