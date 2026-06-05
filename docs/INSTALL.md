# Installation Linux + Nginx

## 1. Copier le projet

```bash
git clone <repo> crawler-honeypot
cd crawler-honeypot
chmod +x scripts/install_linux.sh
./scripts/install_linux.sh
```

## 2. Configurer variables

Editer `/opt/crawler-honeypot/.env`:

- `SECRET_KEY`
- `DASHBOARD_USERNAME`
- `DASHBOARD_PASSWORD`
- `IP_ANONYMIZATION_MODE` (`none`, `truncate`, `hash`)
- `IP_HASH_SALT`

## 3. Lancer Gunicorn

```bash
cd /opt/crawler-honeypot
source .venv/bin/activate
gunicorn -w 2 -b 127.0.0.1:8000 wsgi:app
```

## 4. Configurer Nginx

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/crawler-honeypot
sudo ln -s /etc/nginx/sites-available/crawler-honeypot /etc/nginx/sites-enabled/crawler-honeypot
sudo nginx -t
sudo systemctl reload nginx
```

## 5. (Optionnel) cron rapport quotidien

```bash
0 1 * * * cd /opt/crawler-honeypot && .venv/bin/python scripts/generate_daily_report.py
```

## 6. (Optionnel) service systemd

```bash
sudo cp deploy/crawler-honeypot.service /etc/systemd/system/crawler-honeypot.service
sudo systemctl daemon-reload
sudo systemctl enable --now crawler-honeypot
sudo systemctl status crawler-honeypot
```
