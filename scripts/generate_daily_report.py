from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from honeypot.app import create_app
from honeypot.analytics import generate_daily_report


app = create_app()
with app.app_context():
    out, report = generate_daily_report(app.config["REPORT_DIR"])

print("Report written:", out)
print("Summary total visits:", report["overview"]["total_visits"])
