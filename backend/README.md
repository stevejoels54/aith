# Honeypot Backend (FastAPI)

Receives attack events from the ESP32 honeypot and stores them in SQLite.
This is the data-collection layer. AI threat analysis comes in a later phase.

## What's here

| File               | Job                                                        |
|--------------------|------------------------------------------------------------|
| `app/main.py`      | The FastAPI app and the API endpoints.                     |
| `app/models.py`    | The data shapes: `EventIn` (incoming) and `Event` (stored).|
| `app/database.py`  | SQLite engine + per-request session setup.                 |
| `requirements.txt` | The 3 libraries the backend needs.                         |

## Setup (one time)

```bash
cd backend
python3 -m venv .venv          # create an isolated environment
source .venv/bin/activate      # turn it on (your prompt shows (.venv))
pip install -r requirements.txt
```

## Run it

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- `app.main:app` = "in the file app/main.py, run the variable named `app`".
- `--reload` restarts the server automatically when you edit the code.
- `--host 0.0.0.0` makes it reachable from the ESP32 on your network (not just
  from this computer). Use your laptop's LAN IP in the firmware later.

## Try it

Interactive API docs (FastAPI generates these for free):
- http://localhost:8000/docs

Send a fake attack (the same JSON shape the ESP32 produces):

```bash
curl -X POST http://localhost:8000/events \
  -H "Content-Type: application/json" \
  -d '{"timestamp_ms": 12345, "src_ip": "1.2.3.4", "port": 23, "data": "root\nadmin\n"}'
```

List stored attacks:

```bash
curl http://localhost:8000/events
```
