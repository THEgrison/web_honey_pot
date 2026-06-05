#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/crawler-honeypot"
PY_BIN="python3"

sudo mkdir -p "$APP_DIR"
sudo rsync -a --delete ./ "$APP_DIR"/

cd "$APP_DIR"

$PY_BIN -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

mkdir -p data logs exports reports
cp -n .env.example .env || true

cat <<'EOF'
Installation terminee.

Etapes suivantes:
1. Editer $APP_DIR/.env
2. Lancer: source $APP_DIR/.venv/bin/activate && gunicorn -w 2 -b 127.0.0.1:8000 wsgi:app
3. Configurer Nginx avec deploy/nginx.conf
EOF
