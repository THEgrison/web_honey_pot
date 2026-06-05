# Handoff conversation (pour prochain agent)

Date: 2026-06-05
Projet: Flask honeypot web
Workspace: /Users/a.esnault/Documents/test_honey_pot_web

## Demande utilisateur globale
Construire et enrichir un honeypot crawler passif/defensif complet (Flask + SQLite + dashboard + exports + automatisations), puis ajouter une couche V3 d'intelligence et exporter toutes les IP bots potentiellement indesirables.

## Ce qui est deja fait (etat actuel)
- Base app complete: pages de test, graph navigation, robots/sitemap, dashboard protege, API stats, exports CSV/JSON.
- Fingerprinting comportemental: scoring, filtres, presets sauvegardes, exports filtres JSON/CSV.
- Rapports quotidiens + archive ZIP.
- Workflow GitHub daily release: tag date, titre date, ZIP + SHA256 uploades dans la meme release.
- Docs locales et site docs separe (hors ce workspace) deja prepares.

## Travail recentement termine (V3)
- Module V3 consolide dans honeypot/intelligence_v3.py.
- Endpoints V3 branches dans honeypot/app.py:
  - GET /api/stats/sessions
  - GET /api/stats/kpi-v3
  - GET /api/stats/drift
  - GET /api/stats/anomalies
  - POST /api/alerts/run
  - GET /api/export/ml-dataset/json
  - GET /api/export/ml-dataset/csv
  - GET /api/export/bot-ips/json
  - GET /api/export/bot-ips/csv
- Logging enrichi dans _log_request:
  - network_scope renseigne
  - ip_raw stockee seulement si STORE_RAW_IP=true
- Variables V3 ajoutees dans .env.example:
  - STORE_RAW_IP, ALLOW_RAW_IP_EXPORT
  - SESSION_IDLE_SECONDS, KPI_DEFAULT_WINDOW_DAYS
  - ALERT_WEBHOOK_URL, ALERT_SPIKE_MULTIPLIER, ALERT_MIN_BOT_HITS_PER_HOUR, ALERT_SUSPICIOUS_HITS_PER_HOUR
- Documentation mise a jour:
  - docs/USAGE.md (nouveaux endpoints)
  - README.md (features V3 + privacy IP)

## Validation deja executee
- Lint/erreurs IDE: OK sur app.py, db.py, intelligence_v3.py, config.py.
- Compilation: python -m compileall honeypot scripts wsgi.py -> OK.
- Smoke tests Flask test_client (session dashboard simulee):
  - Tous les endpoints V3 ci-dessus repondent 200.
  - Test mode raw bot IP export: 200, avec fallback anonymized si raw non autorise.

## Comportement export IP bots
- Mode par defaut: anonymized.
- Mode raw autorise seulement si:
  - STORE_RAW_IP=true
  - ALLOW_RAW_IP_EXPORT=true

## Point important de reprise
Le module duplique intel_v3.py a ete supprime. Utiliser uniquement:
- honeypot/intelligence_v3.py

## Prochaine etape logique (si utilisateur confirme)
- Brancher les endpoints V3 dans le dashboard frontend (UI cartes sessions/drift/anomalies + boutons export ML/IP bots).

## Source complete de contexte conversation
Transcript complet disponible ici:
/Users/a.esnault/Library/Application Support/Code/User/workspaceStorage/af5c9802a3d13c555da01bea6b169a67/GitHub.copilot-chat/transcripts/2d11c76b-1a1b-4f10-b6e5-e894e62c58a0.jsonl
