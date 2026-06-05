# Utilisation

## URLs principales

- `/` : accueil et liens reseaux de test
- `/reseau/circulaire/A` : reseau circulaire
- `/reseau/arbre/root` : reseau arborescent
- `/reseau/profondeur/1` : reseau profond
- `/reseau/aleatoire/1` : reseau aleatoire
- `/cap/tests` : detection capacites
- `/robots.txt` et `/sitemap.xml`
- `/dashboard/login` : connexion dashboard

## Dashboard

Le dashboard affiche:

- Vue generale (visites, visiteurs, UA uniques)
- Repartition par categorie
- Top user-agent
- Statistiques comportementales
- Compliance robots/sitemap
- Comparaison familles de crawlers
- Comportements recurrents
- Graphe interactif des parcours
- Metriques avancees: profondeur max, temps moyen entre requetes, ordre des liens explores, frequence de revisite
- Temps reel: bots actifs, visiteurs actifs, JS execute dans la fenetre, tentatives suspectes admin/scripts

## API REST

Endpoints proteges (session dashboard):

- `GET /api/stats/overview`
- `GET /api/stats/top-user-agents?limit=20`
- `GET /api/stats/path-map`
- `GET /api/stats/behavior`
- `GET /api/stats/advanced`
- `GET /api/stats/robots`
- `GET /api/stats/families`
- `GET /api/stats/recurring`
- `GET /api/stats/realtime?window=300`
- `GET /api/stats/fingerprinting?limit=200&days=30`
- `GET /api/stats/sessions?day=YYYY-MM-DD&limit=2000`
- `GET /api/stats/kpi-v3?day=YYYY-MM-DD`
- `GET /api/stats/drift?recent_days=7&baseline_days=30`
- `GET /api/stats/anomalies?window_minutes=60`
- `POST /api/alerts/run?window_minutes=60`
- `GET /api/fingerprinting/presets`
- `POST /api/fingerprinting/presets`
- `DELETE /api/fingerprinting/presets/<id>`
- `GET /api/fingerprinting/export/json?...filtres...`
- `GET /api/fingerprinting/export/csv?...filtres...`
- `GET /api/export/ml-dataset/json?days=60&limit_sessions=100000`
- `GET /api/export/ml-dataset/csv?days=60&limit_sessions=100000`
- `GET /api/export/bot-ips/json?mode=anonymized|raw&limit=500000`
- `GET /api/export/bot-ips/csv?mode=anonymized|raw&limit=500000`
- `POST /api/reports/daily`
- `POST /api/reports/daily-archive?days=7`

Exemple filtrage fingerprinting:

- `GET /api/stats/fingerprinting?limit=200&days=14&category=ai_bot&strategy=depth_first&min_score=55&js=true&cookies=true&min_depth=6&max_rpm=120`

Filtres supportes:

- `category` (`search_engine|ai_bot|scraper|human_browser|unknown_bot`)
- `strategy` (`depth_first|breadth_first|iterative_revisit|high_speed_scan|mixed_walk|insufficient_data`)
- `min_score`, `max_score`
- `min_depth`
- `min_rpm`, `max_rpm`
- `js` (`true|false`)
- `cookies` (`true|false`)

## Exports

- `GET /export/json`
- `GET /export/csv`
- `GET /api/export/ml-dataset/json?...`
- `GET /api/export/ml-dataset/csv?...`
- `GET /api/export/bot-ips/json?...`
- `GET /api/export/bot-ips/csv?...`

Les fichiers sont generes dans `exports/`.

Note IP bots:

- Mode par defaut: `anonymized`.
- Mode `raw` disponible uniquement si `ALLOW_RAW_IP_EXPORT=true` et si `STORE_RAW_IP=true`.

## Rapports quotidiens

- Rapport du jour: `python scripts/generate_daily_report.py`
- Rapports N jours + ZIP: `python scripts/export_daily_archive.py`

Les rapports JSON et les archives ZIP sont generes dans `reports/`.
