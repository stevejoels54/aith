"""
app.py - the Streamlit dashboard for the IoT honeypot project.

What this is:
  A simple web UI that shows the attacks the honeypot captured and the AI's
  threat analysis of each one. It is a CLIENT of the FastAPI backend: it talks
  to the backend over HTTP (the same /events and /events/{id}/analyze endpoints
  you can hit with curl), so the dashboard never touches the database directly.

How to run it (the backend must be running too):
  cd backend && source .venv/bin/activate && uvicorn app.main:app --port 8000
  # then, in another terminal (the same venv is fine):
  streamlit run dashboard/app.py

Why a separate component:
  This keeps the three parts of the project cleanly separated: the ESP32
  captures, the FastAPI backend stores and analyses, and this dashboard displays.
"""

import requests
import streamlit as st

# Where the FastAPI backend lives. Editable in the sidebar at runtime.
DEFAULT_BACKEND = "http://localhost:8000"

# Streamlit markdown supports coloured text via :color[...]. We use it to make
# the severity level stand out. (This is text colour, not an emoji/icon.)
SEVERITY_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "green"}


st.set_page_config(page_title="IoT Honeypot Dashboard", layout="wide")


# ----------------------------- Sidebar --------------------------------------
st.sidebar.title("Honeypot Dashboard")
backend = st.sidebar.text_input("Backend URL", DEFAULT_BACKEND).rstrip("/")
if st.sidebar.button("Refresh"):
    st.rerun()
st.sidebar.markdown(
    "---\n"
    "**Pipeline**\n\n"
    "1. ESP32 honeypot captures a connection\n"
    "2. FastAPI backend stores it\n"
    "3. The AI agent retrieves MITRE/CVE notes (RAG) and classifies the attack\n"
    "4. This dashboard shows it"
)


# ----------------------------- Helpers --------------------------------------
def get_json(path: str):
    """GET a path on the backend and return parsed JSON (raises on HTTP error)."""
    resp = requests.get(f"{backend}{path}", timeout=5)
    resp.raise_for_status()
    return resp.json()


# ----------------------------- Load data ------------------------------------
st.title("Captured attacks and AI threat analysis")

try:
    events = get_json("/events")
except requests.exceptions.RequestException as exc:
    st.error(
        f"Could not reach the backend at **{backend}**. "
        f"Is it running (uvicorn)?\n\n`{exc}`"
    )
    st.stop()

# For each event, fetch its most recent analysis (if any). This is a few small
# requests; fine for a project-scale number of attacks.
rows = []
for event in events:
    try:
        analyses = get_json(f"/events/{event['id']}/analysis")
    except requests.exceptions.RequestException:
        analyses = []
    rows.append((event, analyses[0] if analyses else None))


# ----------------------------- Summary --------------------------------------
total = len(rows)
analyzed = sum(1 for _, a in rows if a)
high_or_critical = sum(
    1 for _, a in rows if a and a["severity"] in ("high", "critical")
)

c1, c2, c3 = st.columns(3)
c1.metric("Captured attacks", total)
c2.metric("Analyzed", f"{analyzed} / {total}")
c3.metric("High / Critical", high_or_critical)

if total == 0:
    st.info(
        "No attacks captured yet. Send a test event to the backend, e.g.:\n\n"
        "```bash\ncurl -X POST "
        f"{backend}/events -H 'Content-Type: application/json' "
        '-d \'{"timestamp_ms":1,"src_ip":"45.155.205.99","port":23,'
        '"data":"root\\r\\nadmin\\r\\n"}\'\n```'
    )
    st.stop()

st.markdown("---")


# ----------------------------- Attack list ----------------------------------
for event, analysis in rows:
    # Build the expander header: id, source, port, and a status hint.
    if analysis:
        status = f"[{analysis['severity'].upper()}] {analysis['classification']}"
    else:
        status = "not analyzed yet"
    header = f"#{event['id']} - {event['src_ip']} - port {event['port']} - {status}"

    with st.expander(header):
        left, right = st.columns([1, 2])

        # --- Left: the raw captured attack ---
        with left:
            st.subheader("Raw capture")
            st.write(f"**Source IP:** {event['src_ip']}")
            st.write(f"**Port:** {event['port']}")
            st.write(f"**Received:** {event['received_at']}")
            st.write("**Bytes the attacker sent:**")
            st.code(event["data"] or "(nothing sent)", language="text")

        # --- Right: the AI analysis, or a button to run it ---
        with right:
            st.subheader("AI threat analysis")
            if analysis is None:
                st.write("This attack has not been analysed yet.")
                if st.button("Analyze with AI", key=f"analyze-{event['id']}"):
                    with st.spinner("Retrieving context and calling Claude..."):
                        resp = requests.post(
                            f"{backend}/events/{event['id']}/analyze", timeout=60
                        )
                    if resp.status_code == 200:
                        st.success("Analysed.")
                        st.rerun()
                    else:
                        detail = resp.json().get("detail", resp.text)
                        st.error(f"Analysis failed ({resp.status_code}): {detail}")
            else:
                sev = analysis["severity"]
                color = SEVERITY_COLOR.get(sev, "gray")
                st.markdown(f"**Severity:** :{color}[{sev.upper()}]")
                st.markdown(f"**Classification:** {analysis['classification']}")
                st.markdown(f"**MITRE technique:** {analysis['mitre_technique']}")

                st.markdown("**Report**")
                st.write(analysis["report"])

                st.markdown("**Recommended mitigations**")
                for tip in analysis["recommended_mitigations"].split("\n"):
                    if tip.strip():
                        st.markdown(f"- {tip}")

                # The RAG references that grounded this analysis.
                if analysis.get("sources"):
                    st.markdown("**Knowledge-base references used (RAG)**")
                    for src in analysis["sources"].split("\n"):
                        if src.strip():
                            st.markdown(f"- `{src}`")

                st.caption(
                    f"Model: {analysis['model']} - analysed {analysis['analyzed_at']}"
                )
