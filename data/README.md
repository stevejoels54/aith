# Datasets

This folder holds the public honeypot datasets used by
`scripts/analyze_honeypot_data.py` for the Chapter 4 data analysis.

The CSV files themselves are **not committed to git** (one is ~47 MB). They are
ignored via `data/*.csv` in the project `.gitignore`. Place the files here
before running the analysis script, or point the script at another folder with
the `HONEYPOT_DATA_DIR` environment variable.

## Expected files

| File                          | Size   | Description                                                                 |
|-------------------------------|--------|-----------------------------------------------------------------------------|
| `dionaeaClean2.csv`           | ~2 MB  | Dionaea honeypot logs (SMB/MSSQL/HTTP/FTP/MongoDB/MQTT scans). Some rows carry an extra trailing field with captured credential/command data. |
| `AWS_Honeypot_marx-geo.csv`   | ~47 MB | AWS Honeypot Attack Data (Jacobs & Rudis, 2013), with geolocation fields (country, locale) used for the source-country statistics. |

## Sources

- **AWS Honeypot Attack Data** accompanies *Data-Driven Security* (Jay Jacobs &
  Bob Rudis, 2013) and is published on public dataset sites (for example
  data.world / Kaggle, searching for "AWS Honeypot Attack Data"). It is the
  `marx-geo` variant, which adds geolocation columns.
- **Dionaea logs** are capture logs from the Dionaea low-interaction honeypot.

## Why these are separate from the live pipeline

These are large, pre-existing public captures used only for offline statistical
analysis in the written report. They are independent of the live pipeline
(ESP32 -> FastAPI backend -> AI analysis -> dashboard), which generates its own
data in `backend/honeypot.db`.
