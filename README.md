# Crawler Honeypot Web (Flask + SQLite)

Projet complet d'observation passive et defensive des crawlers web.

## Fonctionnalites

- Reseaux de pages de test: circulaire, arborescent, profond (1..100), aleatoire.
- Journalisation complete des requetes HTTP.
- Tests capacites: JavaScript, cookies, images, CSS, redirections, liens relatifs/absolus.
- robots.txt et sitemap.xml experimentaux, mesure de consultation et respect.
- Analyse des parcours, comportements recurrents, comparaison par familles de crawlers.
- Classification automatique: moteurs de recherche, bots IA, scrapers, navigateurs humains, bots inconnus.
- Dashboard protege par mot de passe.
- Export CSV/JSON.
- Rapport quotidien automatique + API REST de statistiques.
- Metriques avancees: revisite, ordre d'exploration, support cookies, taux JS.
- Vue temps reel: nombre de bots actifs et detection d'acces suspects (admin/scripts).
- Behavioural Fingerprinting: score de sophistication, strategie, vitesse, profondeur, conventions web, JS, revisite.
- Filtrage dashboard/API des profils fingerprinting (categorie, strategie, score, JS, cookies, profondeur, RPM).
- Seuils de scoring fingerprinting configurables via variables `FP_*` dans `.env`.
- Presets de filtres fingerprinting sauvegardables (ex: Bots IA agressifs).
- Export CSV/JSON des resultats fingerprinting filtres.
- Sessionisation automatique des visiteurs + KPIs journaliers V3.
- Detection de derive (drift) et anomalies de trafic/crawling.
- Pipeline d'alertes webhook configurable.
- Export dataset analytique (ML) en CSV/JSON.
- Export inventaire IP bots (anonymise par defaut, brut optionnel).

## Demarrage rapide (local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python wsgi.py
```

Application: http://127.0.0.1:8000

Dashboard: http://127.0.0.1:8000/dashboard/login

## Commandes utiles

```bash
python scripts/init_db.py
python scripts/generate_daily_report.py
python scripts/export_daily_archive.py
gunicorn -w 2 -b 127.0.0.1:8000 wsgi:app
```

Archive sur N jours (exemple 30 jours):

```bash
EXPORT_DAYS=30 python scripts/export_daily_archive.py
```

## Automatisation GitHub (release quotidienne)

Script: `scripts/publish_daily_release.py`

- Tag: `data-YYYY-MM-DD`
- Titre release: `Data YYYY-MM-DD`
- Archive publiee: `reports/daily_reports_*d_*.zip`

Variables requises:

- `GITHUB_REPOSITORY=owner/repo`
- `RELEASE_TOKEN` ou la variable definie via `--token-env`

Exemple:

```bash
export GITHUB_REPOSITORY=owner/repo
export RELEASE_TOKEN=ghp_xxx
python scripts/publish_daily_release.py --days 30
```

Le script genere d'abord l'archive puis cree ou met a jour la release GitHub avec le meme tag et le meme titre que la date UTC du jour.

## Documentation

- docs/INSTALL.md
- docs/USAGE.md
- docs/SCHEMA.md
- docs/TREE.md

## Privacy IP

- Par defaut, seules les IP anonymisees sont exploitables/exportees.
- Pour autoriser l'export IP brute (usage defensif interne), configurer:
	- `STORE_RAW_IP=true`
	- `ALLOW_RAW_IP_EXPORT=true`

## Identifiants par défaut :

- ```/honeypot/config.py```
- admin
- change-me
