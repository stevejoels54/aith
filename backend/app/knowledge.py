"""
knowledge.py — the threat-intelligence knowledge base for the RAG step.

What RAG (retrieval-augmented generation) means here:
  Before we ask Claude to analyse an attack, we first RETRIEVE the most relevant
  background notes (MITRE ATT&CK techniques and CVE summaries) from a small
  vector database, and hand them to the model as reference material. The model's
  answer is then *grounded* in those references instead of relying only on its
  own memory. That retrieve-then-generate flow is RAG.

How the vector database works (good viva points):
  - Each note is turned into a list of numbers (an "embedding") that captures its
    meaning. Similar meanings -> nearby numbers.
  - We store the notes + embeddings in Chroma, a local vector store.
  - To find relevant notes for an attack, we embed the attack text the same way
    and ask Chroma for the closest notes (a "nearest-neighbour" search).

Embeddings used:
  Chroma's built-in, local embedding model (all-MiniLM-L6-v2). It runs on this
  machine, is free, and needs no extra API key. It is a PRE-TRAINED model used
  as-is — we never train or fine-tune anything, per the project rules. The model
  downloads once on first use (~80 MB) and is cached afterwards.
"""

import os

import chromadb
from chromadb.config import Settings

# Where the vector database is stored on disk (backend/chroma_db/). Persisting it
# means we build the knowledge base once and reuse it across restarts.
_HERE = os.path.dirname(os.path.abspath(__file__))
_CHROMA_PATH = os.path.join(_HERE, "..", "chroma_db")
_COLLECTION_NAME = "threat_intel"


# --- The seed knowledge base ---------------------------------------------------
# A small, curated set of notes most relevant to a Telnet / IoT honeypot. Keeping
# it small and hand-written keeps the project explainable; you can add more notes
# later. "source" + "title" are shown back as the references the AI used.
SEED_DOCS = [
    {
        "id": "T1110",
        "source": "MITRE ATT&CK",
        "title": "Brute Force",
        "text": "Adversaries repeatedly try many username and password "
        "combinations to gain access. On IoT devices this commonly targets "
        "Telnet (port 23) and SSH. A burst of failed logins from a single "
        "source is a hallmark of this technique.",
    },
    {
        "id": "T1110.001",
        "source": "MITRE ATT&CK",
        "title": "Password Guessing",
        "text": "A brute-force sub-technique: the attacker guesses passwords for "
        "common usernames such as root or admin using a fixed wordlist, "
        "without any prior knowledge of the real password.",
    },
    {
        "id": "T1078",
        "source": "MITRE ATT&CK",
        "title": "Valid Accounts / Default Credentials",
        "text": "Attackers log in with legitimate credentials, very often the "
        "factory-default username and password that IoT devices ship with "
        "(for example admin/admin, root/root, root/12345). Because the "
        "credentials are valid, the access can look legitimate.",
    },
    {
        "id": "T1190",
        "source": "MITRE ATT&CK",
        "title": "Exploit Public-Facing Application",
        "text": "Attackers exploit a vulnerability in an internet-facing service "
        "or device to gain initial access, for example command injection in a "
        "router's web or UPnP interface.",
    },
    {
        "id": "T1059",
        "source": "MITRE ATT&CK",
        "title": "Command and Scripting Interpreter",
        "text": "After gaining access, attackers run shell commands (such as "
        "busybox, /bin/sh, or wget) to explore the device or to download and "
        "execute a malicious payload.",
    },
    {
        "id": "T1021",
        "source": "MITRE ATT&CK",
        "title": "Remote Services",
        "text": "Attackers use legitimate remote-access services such as Telnet, "
        "SSH, or RDP to access and control a system. Telnet is unencrypted and "
        "very common on older IoT devices.",
    },
    {
        "id": "T1046",
        "source": "MITRE ATT&CK",
        "title": "Network Service Scanning",
        "text": "Attackers scan ranges of IP addresses and ports to discover "
        "reachable services (for example open Telnet on port 23 or 2323) "
        "before attempting to log in.",
    },
    {
        "id": "T1105",
        "source": "MITRE ATT&CK",
        "title": "Ingress Tool Transfer",
        "text": "Attackers download extra tools or malware onto a compromised "
        "device, often via wget, tftp, or curl from a remote server, to install "
        "bot or crypto-miner payloads.",
    },
    {
        "id": "MIRAI",
        "source": "Threat report",
        "title": "Mirai IoT botnet",
        "text": "Mirai is IoT malware that spreads by scanning the internet for "
        "open Telnet (ports 23 and 2323) and brute-forcing logins with a "
        "built-in list of about 60 common default credentials. Once in, it "
        "downloads an architecture-specific payload and enrols the device into "
        "a DDoS botnet. Telnet brute-force with default credentials is the "
        "classic Mirai infection vector.",
    },
    {
        "id": "CVE-2017-17215",
        "source": "CVE",
        "title": "Huawei HG532 remote code execution",
        "text": "A remote code execution flaw in Huawei HG532 home routers via "
        "the TR-064 / UPnP service on port 37215. Mirai variants such as Satori "
        "exploited it to run commands and recruit routers into botnets.",
    },
    {
        "id": "CVE-2016-10401",
        "source": "CVE",
        "title": "ZyXEL hard-coded su password",
        "text": "ZyXEL PK5001Z modems contain a hard-coded password 'zyad5001' "
        "for the su command, letting an attacker with any low-privilege shell "
        "escalate to root. Hard-coded or default credentials are a common IoT "
        "weakness.",
    },
    {
        "id": "CWE-798",
        "source": "CWE",
        "title": "Use of hard-coded credentials",
        "text": "Many IoT devices ship with hard-coded or default credentials "
        "that owners never change. Attackers keep lists of these defaults and "
        "try them first, which is why a honeypot mostly sees common pairs like "
        "root/root and admin/admin.",
    },
]


# Create the Chroma client once and reuse it. anonymized_telemetry=False stops
# Chroma sending usage pings and keeps the logs clean.
_client = chromadb.PersistentClient(
    path=_CHROMA_PATH,
    settings=Settings(anonymized_telemetry=False),
)


def get_collection():
    """Return our Chroma collection, creating it if it doesn't exist.

    With no embedding_function specified, Chroma uses its default local model
    (all-MiniLM-L6-v2) to turn text into embeddings automatically.
    """
    return _client.get_or_create_collection(name=_COLLECTION_NAME)


def build_knowledge_base() -> int:
    """Load the seed notes into the vector store. Safe to call on every startup.

    We use upsert (insert-or-update keyed by id), so re-running it keeps the
    store in sync with SEED_DOCS rather than creating duplicates. Returns how
    many notes the collection holds.
    """
    collection = get_collection()
    collection.upsert(
        ids=[d["id"] for d in SEED_DOCS],
        documents=[f'{d["title"]}. {d["text"]}' for d in SEED_DOCS],
        metadatas=[{"title": d["title"], "source": d["source"]} for d in SEED_DOCS],
    )
    return collection.count()


def retrieve_context(query: str, k: int = 3) -> list[dict]:
    """Return the k most relevant notes for a query (the 'retrieval' in RAG)."""
    collection = get_collection()
    results = collection.query(query_texts=[query], n_results=k)

    # Chroma returns parallel lists nested one level deep (one entry per query).
    # We sent a single query, so we read index [0] of each list.
    docs: list[dict] = []
    ids = results["ids"][0]
    documents = results["documents"][0]
    metadatas = results["metadatas"][0]
    for i in range(len(ids)):
        docs.append(
            {
                "id": ids[i],
                "title": metadatas[i].get("title", ids[i]),
                "source": metadatas[i].get("source", ""),
                "text": documents[i],
            }
        )
    return docs
