# IoT Honeypot with Agentic AI Threat Analysis

Final-year BCA (Cloud and Security) project, Amity University Online.

An ESP32 low-interaction honeypot emulates a vulnerable IoT service (a fake
Telnet server) and records every connection attempt. Each captured event is sent
to a Python/FastAPI backend, which stores it and can run an agentic AI pipeline
that classifies the attack. The AI step uses retrieval-augmented generation
(RAG): it retrieves relevant threat-intelligence notes (MITRE ATT&CK techniques
and CVE summaries) from a Chroma vector store and feeds them to a Claude model,
which returns a structured classification plus a plain-English report. A
Streamlit dashboard shows the captured attacks, their analysis, and recommended
mitigations.

This is a DEFENSIVE tool. The honeypot only records what connects to it; it never
attacks anything. No machine-learning model is trained or fine-tuned anywhere in
this project: it uses a pre-trained large language model plus RAG only.

## Architecture

```
  +----------------+     HTTP POST /events       +---------------------+      +---------------+
  |  ESP32         |   (one JSON per attack)      |   FastAPI backend   | ---> |  SQLite       |
  |  honeypot      | --------------------------->  |   ingest + REST API |      |  honeypot.db  |
  |  (fake Telnet, |                              |                     |      +---------------+
  |   TCP port 23) |                              |  POST /events/{id}/ |
  +----------------+                              |       analyze       |
                                                  +----------+----------+
                                                             |
                                  1. retrieve MITRE/CVE notes | (RAG)        +-------------------+
                                                             +------------->  |  Chroma vector    |
                                                             |               |  store (knowledge)|
                                                             |               +-------------------+
                                  2. send notes + attack to  |
                                     the model               v
                                                  +---------------------+
                                                  |  Claude (Anthropic) |
                                                  |  structured output  |
                                                  +----------+----------+
                                                             | classification, severity,
                                                             | MITRE technique, report, fixes
                                                             v
                                                  +---------------------+
                                                  |  Streamlit dashboard|
                                                  |  (reads backend API)|
                                                  +---------------------+
```

The single JSON message the device sends per attack:

```json
{ "timestamp_ms": 48213, "src_ip": "45.155.205.99", "port": 23, "data": "root\r\nadmin\r\n" }
```

## Repository layout

```
aith/
  firmware/
    esp32_honeypot/
      esp32_honeypot.ino     ESP32 Arduino sketch: fake Telnet + POST to backend
  backend/
    app/
      main.py                FastAPI app and endpoints
      models.py              data shapes: EventIn, Event, Analysis
      database.py            SQLite engine and per-request session
      agent.py               AI analysis (retrieve + Claude structured output)
      knowledge.py           Chroma knowledge base (MITRE/CVE notes) + retrieval
    requirements.txt         backend dependencies
    .env.example             template for the ANTHROPIC_API_KEY (copy to .env)
    README.md                backend-only details
  dashboard/
    app.py                   Streamlit dashboard (client of the backend API)
    requirements.txt         dashboard dependencies
  scripts/
    analyze_honeypot_data.py offline descriptive statistics over public datasets
    requirements.txt         pandas
  data/
    README.md                describes the datasets (large CSVs are not in git)
  README.md                  this file
```

Not committed to git: the Python virtual environment (`.venv/`), the SQLite
database (`*.db`), the Chroma store (`chroma_db/`), the API key file (`.env`),
and the large dataset CSVs (`data/*.csv`).

## Prerequisites

- Python 3.11 or newer.
- An Anthropic API key (from https://console.anthropic.com) for the AI analysis.
- For the device: an ESP32 board, the Arduino IDE with ESP32 board support, and a
  2.4 GHz Wi-Fi network (the ESP32 does not support 5 GHz).

## 1. Backend

### Setup (one time)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure the API key

The backend reads `ANTHROPIC_API_KEY` from a local `.env` file (loaded
automatically at startup). Create it from the template:

```bash
cd backend
cp .env.example .env
# then edit .env and paste your real key:
# ANTHROPIC_API_KEY=sk-ant-...
```

The `.env` file is git-ignored, so the key never enters version control. As an
alternative you can `export ANTHROPIC_API_KEY=sk-ant-...` in your shell.

### Run

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- `--host 0.0.0.0` makes the server reachable from the ESP32 (a separate device)
  on the same network, not just from this computer.
- On the first run the AI knowledge base is built; this downloads a small local
  embedding model (about 80 MB) once and caches it.

Confirm it is up:

```bash
curl http://localhost:8000/          # {"status":"ok","service":"honeypot-backend"}
```

Interactive API docs: http://localhost:8000/docs

## 2. Dashboard

In a second terminal (the same virtual environment is fine):

```bash
source backend/.venv/bin/activate    # from the project root
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py       # opens http://localhost:8501
```

The dashboard lists captured attacks with summary metrics. Expand an attack to
see the raw capture and, on the right, the AI analysis (severity, classification,
MITRE technique, report, mitigations, and the RAG references used). Un-analyzed
attacks show an "Analyze with AI" button that calls the backend.

## 3. Firmware (ESP32)

Edit `firmware/esp32_honeypot/esp32_honeypot.ino` and set three values:

```cpp
const char* WIFI_SSID  = "YOUR_WIFI_NAME";       // a 2.4 GHz network
const char* WIFI_PASS  = "YOUR_WIFI_PASSWORD";
const char* BACKEND_URL = "http://<laptop-ip>:8000/events";
```

Find your laptop's LAN IP (the backend host):

```bash
ipconfig getifaddr en0     # macOS Wi-Fi
# hostname -I              # Linux
```

The laptop and the ESP32 must be on the same network, and that network must allow
devices to talk to each other (many campus and guest networks block this; a phone
hotspot or a home network is the easy option). Flash the sketch from the Arduino
IDE, open the Serial Monitor at 115200 baud, and you should see the honeypot's IP
and "Honeypot listening on port 23".

Note for ESP32-S3 boards: enable Tools -> "USB CDC On Boot" and re-upload, or the
Serial Monitor stays blank.

Simulate an attacker from the laptop:

```bash
nc <honeypot-ip-from-serial> 23      # type something, then Ctrl-C
```

The Serial Monitor prints the JSON event and "POST -> HTTP 200", and the event
appears via `curl http://localhost:8000/events`.

## 4. Offline dataset analysis (for the written report)

`scripts/analyze_honeypot_data.py` computes descriptive statistics over two
public honeypot datasets (no model training). The large CSVs are not stored in
git; place them in `data/` (see `data/README.md` for the expected files and
sources), then:

```bash
source backend/.venv/bin/activate
pip install -r scripts/requirements.txt
cd scripts
python3 analyze_honeypot_data.py
# or read the CSVs from elsewhere:
# HONEYPOT_DATA_DIR=/path/to/folder python3 analyze_honeypot_data.py
```

## How the AI analysis (RAG) works

1. Retrieval: a short query is built from the captured attack (the target port
   and the bytes the attacker sent). `knowledge.py` embeds it with a local model
   and asks the Chroma vector store for the most similar threat-intel notes
   (curated MITRE ATT&CK techniques, CVE summaries, and a Mirai botnet note).
2. Generation: those notes are added to the prompt as reference material, and the
   Claude model is asked to return a structured result using the Anthropic SDK's
   structured-outputs feature, so the reply always has the same typed fields.
3. Storage: the result is saved in the `Analysis` table, linked to the event,
   together with the list of references that grounded it.

Building retrieval first and generation second is what makes this RAG: the answer
is grounded in retrieved references rather than only the model's own memory.

## API reference

| Method | Path                        | Purpose                                              |
|--------|-----------------------------|------------------------------------------------------|
| GET    | `/`                         | Health check.                                        |
| POST   | `/events`                   | Receive and store one captured attack.               |
| GET    | `/events`                   | List stored attacks, newest first.                   |
| POST   | `/events/{id}/analyze`      | Run the RAG analysis on one attack and store it.     |
| GET    | `/events/{id}/analysis`     | List saved analyses for one attack.                  |

## End-to-end demo

1. Start the backend (Part 1) and the dashboard (Part 2).
2. Create a sample attack:
   ```bash
   curl -X POST http://localhost:8000/events -H "Content-Type: application/json" \
     -d '{"timestamp_ms":1,"src_ip":"45.155.205.99","port":23,"data":"root\r\nadmin\r\n"}'
   ```
3. In the dashboard, expand the attack and click "Analyze with AI". The
   classification, severity, MITRE technique, report, mitigations, and the RAG
   references appear.

## Tech stack

- Firmware: ESP32 / Arduino C++.
- Backend: Python 3.11+, FastAPI, SQLModel over SQLite.
- AI: Anthropic Claude via the official SDK, structured outputs; RAG with a Chroma
  vector store and a local embedding model.
- Dashboard: Streamlit.
- Analysis script: pandas.

## Project constraints

- No machine-learning model is trained or fine-tuned; the project uses a
  pre-trained LLM plus RAG only.
- Dependencies are kept minimal and widely used.
- The honeypot is defensive and should be run on an isolated network.
