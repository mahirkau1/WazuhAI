#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== AegisAI Agent setup ==="

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 bulunamadi. Debian/Ubuntu icin python3, python3-venv ve python3-pip kurun."
  exit 1
fi

python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env olusturuldu. Calistirmadan once kendi degerlerinizi girin."
else
  echo ".env zaten mevcut; degistirilmedi."
fi

echo "Kurulum tamamlandi."
echo "Agent:     source venv/bin/activate && cd app && python agent.py"
echo "Dashboard: source venv/bin/activate && cd app && python dashboard.py"
