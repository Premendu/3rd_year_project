# logger_csv.py
import csv
import os
from datetime import datetime

CSV_FILE = os.environ.get("CSV_FILE", "security_analysis.csv")
CSV_HEADER = ["timestamp", "node_role", "role", "access_level", "score", "risk", "breach_flag", "sha256", "crack_time_seconds"]

def ensure_csv_exists():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)

def log_entry(node_role, role, access_level, score, risk, breach_flag, sha256, crack_time_seconds):
    ensure_csv_exists()
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            node_role,
            role,
            access_level,
            score,
            risk,
            "YES" if breach_flag else "NO",
            sha256,
            "" if crack_time_seconds is None else f"{crack_time_seconds:.6g}"
        ])

def read_all():
    ensure_csv_exists()
    rows = []
    with open(CSV_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows
