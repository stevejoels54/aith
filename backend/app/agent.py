"""
agent.py — the AI threat-analysis step.

What this file does:
  Given one captured attack (an Event), it asks Claude to act as a security
  analyst and return a STRUCTURED classification plus a plain-English report.

How it stays reliable (good viva point):
  We use the Anthropic SDK's "structured outputs" feature (messages.parse).
  We hand Claude a schema — the AttackAnalysis model below — and the SDK
  guarantees the reply matches it. So we get clean, typed fields instead of
  free text we'd have to parse by hand.

RAG step:
  Before calling the model, we RETRIEVE the most relevant notes (MITRE ATT&CK
  techniques / CVE summaries) from the Chroma knowledge base in knowledge.py and
  put them in the prompt as reference material. This grounds the answer in real
  references — especially the mitre_technique field — instead of relying only on
  the model's memory. That retrieve-then-generate flow is what makes this RAG.
"""

import os
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

from .knowledge import retrieve_context
from .models import Event

# Which Claude model to use for the analysis.
#   "claude-opus-4-8"  -> most capable (default).
#   "claude-haiku-4-5" -> ~5x cheaper and plenty for this task.
# COST TIP: change this ONE line to switch models.
ANALYSIS_MODEL = "claude-haiku-4-5"


class AttackAnalysis(BaseModel):
    """The structured result we ask Claude to produce for each attack.

    Each field becomes part of a JSON schema the model is forced to fill in,
    so the reply is always machine-readable.
    """

    classification: str = Field(
        description="Short label for the attack type, "
        "e.g. 'Telnet brute-force login attempt'."
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="How serious this attack attempt is."
    )
    mitre_technique: str = Field(
        description="Best-guess MITRE ATT&CK technique ID and name, "
        "e.g. 'T1110 Brute Force'. Use 'Unknown' if unclear."
    )
    report: str = Field(
        description="A clear, plain-English paragraph explaining what the "
        "attacker appears to be doing and why it matters."
    )
    recommended_mitigations: list[str] = Field(
        description="A few concrete, practical defensive recommendations."
    )


# We reuse a single Anthropic client. It is created lazily (only when first
# needed) so the web server can still start even if the API key isn't set yet —
# in that case only the analyze endpoint fails, with a clear message, instead of
# the whole server refusing to boot.
_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        # Check the key ourselves first so we can give a clear message. (Without
        # this, the SDK raises a confusing low-level TypeError when the key is
        # missing.) We never hard-code the key — it must come from the env var.
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Set it in your shell "
                "(export ANTHROPIC_API_KEY=sk-ant-...) before analysing."
            )
        # Anthropic() reads the ANTHROPIC_API_KEY environment variable for us.
        _client = anthropic.Anthropic()
    return _client


# Instructions that frame WHO the model is and WHAT we want. Crucially, it makes
# clear this is DEFENSIVE analysis of data a honeypot already captured.
SYSTEM_PROMPT = (
    "You are a cybersecurity analyst reviewing data captured by a low-interaction "
    "IoT honeypot (a decoy service that only records what connects to it). You will "
    "be given reference material retrieved from a threat-intelligence knowledge base "
    "plus the details of one captured connection attempt. Use the reference material "
    "to classify the likely attack, judge its severity, map it to a MITRE ATT&CK "
    "technique, write a short plain-English report a student could understand, and "
    "suggest practical mitigations. This is defensive analysis of already-captured "
    "attacker data."
)


def analyze_attack(event: Event) -> tuple[AttackAnalysis, list[str]]:
    """Run the RAG analysis on one captured attack.

    Returns BOTH the structured analysis AND the list of knowledge-base
    references that were retrieved and shown to the model — so we can store and
    display which sources grounded the answer.
    """
    client = _get_client()

    # --- RETRIEVAL (the "R" in RAG) ---
    # Build a short query describing the attack, then fetch the most relevant
    # notes from the threat-intel knowledge base.
    # Key the retrieval on the actual payload/port rather than assuming "Telnet",
    # so non-Telnet exploits (e.g. UPnP/HTTP router exploits) retrieve the right
    # notes instead of always pulling back generic brute-force notes.
    query = (
        f"Honeypot capture on port {event.port}. "
        f"Bytes/payload the client sent: {event.data!r}"
    )
    docs = retrieve_context(query, k=3)
    context_block = "\n".join(
        f'[{d["id"]}] {d["title"]} ({d["source"]}): {d["text"]}' for d in docs
    )

    # --- GENERATION (the "G" in RAG) ---
    # We include the raw bytes the attacker sent (e.g. the usernames/passwords
    # they tried). Using repr (!r) keeps escape chars like \r\n visible.
    user_message = (
        "Use the reference material below to ground your analysis. Where it "
        "applies, cite the relevant MITRE technique IDs or CVE numbers in your "
        "report and mitre_technique fields.\n\n"
        "=== Reference material (retrieved from the knowledge base) ===\n"
        f"{context_block}\n\n"
        "=== Captured attack ===\n"
        f"- Source IP: {event.src_ip}\n"
        f"- Target port: {event.port} (the honeypot emulates Telnet on port 23)\n"
        f"- Device uptime when captured (ms): {event.timestamp_ms}\n"
        f"- Raw bytes the client sent: {event.data!r}\n"
    )

    # messages.parse() validates the reply against AttackAnalysis for us.
    response = client.messages.parse(
        model=ANALYSIS_MODEL,
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
        output_format=AttackAnalysis,
    )

    # parsed_output is a validated AttackAnalysis instance, or None if the model
    # refused or produced something unparseable.
    if response.parsed_output is None:
        raise RuntimeError(
            f"Claude did not return a valid analysis "
            f"(stop_reason={response.stop_reason})."
        )

    # The references we showed the model, e.g. "T1110 Brute Force".
    sources = [f'{d["id"]} {d["title"]}' for d in docs]
    return response.parsed_output, sources
