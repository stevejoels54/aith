"""
Honeypot dataset analysis for Chapter 4 (Data Analysis, Results, Interpretation).

Two public datasets are analysed (descriptive statistics only - no model
training, per the project rules):

1. dionaeaClean2.csv          - Dionaea honeypot logs
                                (SMB/MSSQL/HTTP/FTP/MongoDB/MQTT scans).
2. AWS_Honeypot_marx-geo.csv  - AWS Honeypot Attack Data (Jacobs & Rudis, 2013),
                                with geolocation fields for country statistics.

Where the data lives:
  The CSV files are read from a data directory, resolved in this order:
    1. the HONEYPOT_DATA_DIR environment variable, if set;
    2. otherwise the project's top-level "data/" folder (../data from here).
  The large CSVs are NOT committed to git (see .gitignore and data/README.md);
  place them in the data/ folder before running this script.

Run:
  cd scripts
  python3 analyze_honeypot_data.py
  # or point at a different folder:
  HONEYPOT_DATA_DIR=/path/to/data python3 analyze_honeypot_data.py
"""

import csv
import os
import sys
from pathlib import Path

import pandas as pd

# ---- Resolve the data directory robustly (no hard-coded absolute paths) ----
# __file__ is .../scripts/analyze_honeypot_data.py, so parents[1] is the project
# root, and the default data folder is <project-root>/data.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("HONEYPOT_DATA_DIR", PROJECT_ROOT / "data"))

DIONAEA_CSV = DATA_DIR / "dionaeaClean2.csv"
AWS_CSV = DATA_DIR / "AWS_Honeypot_marx-geo.csv"


def require(path: Path) -> Path:
    """Exit with a clear message if a dataset file is missing."""
    if not path.exists():
        sys.exit(
            f"Dataset not found: {path}\n"
            f"Place the CSV files in {DATA_DIR} (see data/README.md for sources), "
            f"or set HONEYPOT_DATA_DIR to the folder that contains them."
        )
    return path


# ---- 1. Dionaea dataset ----------------------------------------------------
# Some rows have an extra trailing field with credential info (mssqld logins,
# ftpd AUTH attempts) which makes the CSV "ragged". We parse with the csv module
# directly to preserve that extra info rather than letting pandas silently
# misalign columns.
rows = []
with open(require(DIONAEA_CSV), newline="") as f:
    reader = csv.reader(f)
    header = [h.strip() for h in next(reader)]
    for line in reader:
        fixed = [v.strip() for v in line[:7]]
        extra = ",".join(line[7:]).strip() if len(line) > 7 else ""
        rows.append(fixed + [extra])

dionaea = pd.DataFrame(rows, columns=header + ["extra"])
dionaea["timestamp"] = pd.to_datetime(dionaea["timestamp"], format="mixed")

print("=" * 70)
print("DIONAEA HONEYPOT DATASET")
print("=" * 70)
print(f"Total events (N):           {len(dionaea)}")
print(f"Unique source IPs (M):      {dionaea['src_ip'].nunique()}")
print(f"Observation window:         {dionaea['timestamp'].min()} to {dionaea['timestamp'].max()}")
print(f"Window duration:            {dionaea['timestamp'].max() - dionaea['timestamp'].min()}")
print()
print("Service / protocol targeted (top hits):")
print(dionaea["protocol"].value_counts())
print()
print("Destination port targeted:")
print(dionaea["dst_port"].value_counts())
print()
cred_rows = dionaea[dionaea["extra"] != ""]
print(f"Events with captured credential/command data: {len(cred_rows)}")
print(f"  -> {len(cred_rows) / len(dionaea) * 100:.2f}% of all events")
print()

# ---- 2. AWS Honeypot Attack Data -------------------------------------------
aws = pd.read_csv(
    require(AWS_CSV),
    usecols=["datetime", "host", "src", "proto", "type", "spt", "dpt", "srcstr", "cc", "country", "locale"],
)
aws["datetime"] = pd.to_datetime(aws["datetime"], format="mixed")

print("=" * 70)
print("AWS HONEYPOT ATTACK DATA (Jacobs & Rudis, 2013)")
print("=" * 70)
print(f"Total events (N):           {len(aws)}")
print(f"Unique source IPs (M):      {aws['srcstr'].nunique()}")
print(f"Observation window:         {aws['datetime'].min()} to {aws['datetime'].max()}")
print(f"Window duration (days):     {(aws['datetime'].max() - aws['datetime'].min()).days}")
print()
print("Top 10 source countries (% of events with known country):")
print((aws["country"].value_counts(normalize=True).head(10) * 100).round(1))
print()
print("Protocol breakdown:")
print(aws["proto"].value_counts())
print()
print("Top destination ports:")
print(aws["dpt"].value_counts().head(10))
print()
print("Destination honeypot hosts (sensor locations):")
print(aws["host"].value_counts())
