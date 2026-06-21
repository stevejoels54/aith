"""
main.py — the FastAPI application: the "front door" of the backend.

For now it does just three things (the smallest useful version):
  1. On startup, make sure the database file and tables exist.
  2. POST /events  — receive ONE attack from the honeypot and save it.
  3. GET  /events  — list the saved attacks, so we can confirm it works
                     (and, later, so the Streamlit dashboard can show them).

We deliberately do NOT do any AI analysis yet. First we make sure events flow
in and out reliably. The RAG / LLM agent is a later phase that will read these
stored events and add a classification + report to each one.
"""

from contextlib import asynccontextmanager

import anthropic
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Session, select

from .agent import ANALYSIS_MODEL, analyze_attack
from .database import create_db_and_tables, get_session
from .knowledge import build_knowledge_base
from .models import Analysis, Event, EventIn

# Load variables from a local .env file (e.g. ANTHROPIC_API_KEY) into the
# environment as soon as the app starts, so the Anthropic SDK can read the key.
# Does nothing if there's no .env file. The .env file is git-ignored.
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Code that runs once when the server starts and once when it stops.

    Everything before `yield` runs at startup; everything after runs at
    shutdown. We use it to create the database and tables on startup. (This is
    FastAPI's current, recommended way to do startup/shutdown work.)
    """
    create_db_and_tables()   # startup: make the database + tables
    # Load the threat-intel knowledge base into the Chroma vector store. The very
    # first run downloads the local embedding model (~80 MB), so it may take a
    # few extra seconds; later runs are fast.
    count = build_knowledge_base()
    print(f"[startup] knowledge base ready: {count} notes")
    yield
    # (nothing to clean up on shutdown yet)


# The `app` object is what the uvicorn server runs.
app = FastAPI(title="IoT Honeypot Backend", lifespan=lifespan)


@app.get("/")
def health_check() -> dict:
    """A tiny endpoint to quickly confirm the server is alive (open in a browser)."""
    return {"status": "ok", "service": "honeypot-backend"}


@app.post("/events", response_model=Event)
def create_event(
    event_in: EventIn,
    session: Session = Depends(get_session),
) -> Event:
    """Receive one attack from the honeypot and store it.

    FastAPI does the hard parts for us automatically:
      - reads the request body as JSON,
      - validates it against EventIn (bad/missing fields -> 422 error),
      - hands us a ready-to-use EventIn object.

    We then copy those fields into a database Event and save it. We don't copy
    `id` or `received_at` — the database and the model fill those in.
    """
    event = Event(
        timestamp_ms=event_in.timestamp_ms,
        src_ip=event_in.src_ip,
        port=event_in.port,
        data=event_in.data,
    )
    session.add(event)       # stage the new row
    session.commit()         # actually write it to disk
    session.refresh(event)   # reload it so we get the generated id back
    return event             # FastAPI sends this back as JSON


@app.get("/events", response_model=list[Event])
def list_events(session: Session = Depends(get_session)) -> list[Event]:
    """Return all stored attacks, newest first."""
    statement = select(Event).order_by(Event.id.desc())
    return list(session.exec(statement).all())


@app.post("/events/{event_id}/analyze", response_model=Analysis)
def analyze_event(
    event_id: int,
    session: Session = Depends(get_session),
) -> Analysis:
    """Run the AI analysis on one stored attack and save the result.

    Steps:
      1. Look up the captured attack by id (404 if it doesn't exist).
      2. Ask Claude to analyse it (this calls the Anthropic API — costs money).
      3. Save the structured result in the Analysis table and return it.
    """
    # 1. Find the captured attack.
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"No event with id {event_id}")

    # 2. Ask Claude (with RAG). analyze_attack retrieves relevant knowledge-base
    #    notes, feeds them to the model, and returns the analysis plus the list
    #    of references it used. We translate failures into clear HTTP responses.
    try:
        result, sources = analyze_attack(event)
    except anthropic.AuthenticationError:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY is invalid.")
    except anthropic.APIError as exc:
        raise HTTPException(status_code=502, detail=f"Claude API error: {exc}")
    except RuntimeError as exc:
        # Missing API key, or the model returned nothing usable.
        raise HTTPException(status_code=503, detail=str(exc))

    # 3. Save the analysis, linked to its event. We join the lists (mitigation
    #    tips and RAG sources) into text blocks so each fits one database column.
    analysis = Analysis(
        event_id=event.id,
        classification=result.classification,
        severity=result.severity,
        mitre_technique=result.mitre_technique,
        report=result.report,
        recommended_mitigations="\n".join(result.recommended_mitigations),
        model=ANALYSIS_MODEL,
        sources="\n".join(sources),
    )
    session.add(analysis)
    session.commit()
    session.refresh(analysis)
    return analysis


@app.get("/events/{event_id}/analysis", response_model=list[Analysis])
def get_event_analysis(
    event_id: int,
    session: Session = Depends(get_session),
) -> list[Analysis]:
    """Return any saved analyses for one attack, newest first."""
    statement = (
        select(Analysis)
        .where(Analysis.event_id == event_id)
        .order_by(Analysis.id.desc())
    )
    return list(session.exec(statement).all())
