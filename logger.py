# logger.py
import csv
import os
from datetime import datetime

CSV_FILE = "security_analysis.csv"


def ensure_csv_header():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "node_role", "role", "access_level", "score", "risk"])


def log_to_csv(node_role, role, access_level, score, risk):
    ensure_csv_header()
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(), node_role, role, access_level, score, risk])