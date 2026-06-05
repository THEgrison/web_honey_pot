# Arborescence du projet

```text
.
├── honeypot
│   ├── app.py
│   ├── analytics.py
│   ├── classifiers.py
│   ├── config.py
│   ├── db.py
│   ├── page_graph.py
│   ├── security.py
│   ├── static
│   │   ├── css/styles.css
│   │   └── js/{capabilities.js,dashboard.js}
│   └── templates
│       ├── base.html
│       ├── index.html
│       ├── network_page.html
│       ├── capability_tests.html
│       ├── cookie_check.html
│       ├── redirect_target.html
│       ├── relative_links.html
│       ├── login.html
│       └── dashboard.html
├── scripts
│   ├── init_db.py
│   ├── generate_daily_report.py
│   └── install_linux.sh
├── deploy/nginx.conf
├── docs/{INSTALL.md,USAGE.md,SCHEMA.md,TREE.md}
├── data/
├── logs/
├── exports/
├── reports/
├── requirements.txt
├── .env.example
├── wsgi.py
└── README.md
```
