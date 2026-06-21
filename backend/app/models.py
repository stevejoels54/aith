"""
models.py — describes the *shape* of our data.

There are two models here, and the difference between them is a great viva point:

  1. EventIn  — what the ESP32 honeypot SENDS US (the request body). It is used
     only to validate incoming JSON. It is NOT a database table.

  2. Event    — how we STORE an attack in the database. It is marked
     `table=True`, so SQLModel turns it into a real SQLite table. It adds two
     fields the device cannot know: a database `id`, and `received_at`
     (the real server-side time the event arrived).

Why keep them separate?
  - The device only knows its own uptime (`timestamp_ms`), not the real
    date/time. The server fills in the real time.
  - The device must NOT be allowed to choose our database `id`.
  Splitting "what comes in" from "what we store" is a clean, common API pattern.
"""

from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class EventIn(SQLModel):
    """The JSON the honeypot firmware POSTs for each connection attempt.

    This must match exactly what the ESP32 sends. See the firmware's logEvent():
        { "timestamp_ms": 12345, "src_ip": "1.2.3.4", "port": 23, "data": "..." }
    """
    timestamp_ms: int   # milliseconds since the ESP32 booted (device uptime)
    src_ip: str         # IP address the attacker connected from
    port: int           # port that was hit (23 = our fake Telnet)
    data: str           # raw bytes the attacker sent (e.g. login attempts)


class Event(SQLModel, table=True):
    """One captured attack, exactly as stored in the database."""

    # Auto-incrementing row number. None before saving; SQLite fills it in.
    id: int | None = Field(default=None, primary_key=True)

    # --- These come straight from the device (copied from EventIn) ---
    timestamp_ms: int
    src_ip: str
    port: int
    data: str

    # --- This is added by the SERVER when the event arrives ---
    # The real wall-clock time in UTC. The device cannot provide this yet,
    # so the backend stamps it. default_factory runs this function at the
    # moment a new Event is created.
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class Analysis(SQLModel, table=True):
    """The AI's analysis of ONE captured attack, stored in its own table.

    We keep this separate from Event on purpose: Event is the *raw* thing the
    honeypot saw, and Analysis is what our AI pipeline *derived* from it. Each
    Analysis row points back to its Event via event_id. (Storing this in a new
    table also means we don't have to alter the existing events table.)
    """

    id: int | None = Field(default=None, primary_key=True)

    # Links this analysis to the attack it describes. "event.id" is the column
    # in the Event table (SQLModel names the table after the class, lowercased).
    event_id: int = Field(foreign_key="event.id", index=True)

    # --- Fields the AI fills in (mirrors AttackAnalysis in agent.py) ---
    classification: str          # short label, e.g. "Telnet brute-force attempt"
    severity: str                # low | medium | high | critical
    mitre_technique: str         # e.g. "T1110 Brute Force" (or "Unknown")
    report: str                  # plain-English explanation
    recommended_mitigations: str # the list of tips, joined into one text block
    model: str                   # which Claude model produced this analysis
    sources: str = ""            # RAG references the AI used, joined by newlines

    # When the analysis was produced (real server time, UTC).
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
