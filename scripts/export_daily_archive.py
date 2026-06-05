from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from honeypot.analytics import export_daily_reports_zip
from honeypot.app import create_app


def parse_days(default=7):
    cli_value = sys.argv[1] if len(sys.argv) > 1 else None
    raw = cli_value or os.environ.get("EXPORT_DAYS") or str(default)
    try:
        days = int(raw)
    except ValueError:
        days = default
    return max(1, min(days, 365))


DAYS = parse_days(default=7)

app = create_app()
with app.app_context():
    zip_path, files = export_daily_reports_zip(app.config["REPORT_DIR"], days=DAYS)

print("ZIP archive:", zip_path)
print("Generated reports:", len(files))
for item in files:
    print(" -", item)
